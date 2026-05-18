import logging
import os
import hmac
import hashlib
import base64
import json
import boto3
from idp_modules import util
from aws_lambda_powertools import Tracer

tracer = Tracer()

logger = logging.getLogger(__name__)
logger.setLevel(util.get_log_level())


class CognitoIdpModuleError(util.IdpModuleError):
    """Used to raise module-specific exceptions"""

    pass

secret_cache = {}
client = boto3.client('cognito-idp')


@tracer.capture_method
def compute_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(
        client_secret.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    secret_hash = base64.b64encode(dig).decode()
    logger.debug(f"Secret hash for user {username}: {secret_hash}")
    return secret_hash

@tracer.capture_method
def handle_auth(
    event,
    parsed_username,
    user_record,
    identity_provider_record,
    response_data,
    authn_method,
):
    
    if authn_method == util.AuthenticationMethod.PUBLIC_KEY:
        raise CognitoIdpModuleError("This provider does not support public key auth.")    
    
    logger.debug(f"User record: {user_record}")


    identity_provider_config = identity_provider_record["config"]
    cognito_client_id = identity_provider_config["cognito_client_id"]
    cognito_user_pool_region = identity_provider_config.get("cognito_user_pool_region", os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')))
    cognito_client_secret_arn = identity_provider_config.get("cognito_client_secret_arn", None)
    cognito_include_source_ip = identity_provider_config.get("cognito_include_source_ip", False)
    cognito_mfa = identity_provider_record["config"].get("mfa", False)
    cognito_mfa_token_length = int(
        identity_provider_record["config"].get("mfa_token_length", 6)
    )
    password = event["password"]

    # Retrieve client secret from Secrets Manager if configured
    cognito_client_secret = None
    if cognito_client_secret_arn:
        logger.info(f"Client secret ARN configured. Retrieving client secret from Secrets Manager.")
        secret_value = util.fetch_secret_cache(secret_cache, cognito_client_secret_arn)
        if secret_value is None:
            raise CognitoIdpModuleError("Failed to retrieve Cognito client secret from Secrets Manager.")
        # Support both plain string secrets and JSON secrets with a "client_secret" key
        try:
            secret_json = json.loads(secret_value)
            cognito_client_secret = secret_json.get("client_secret", secret_value)
        except (json.JSONDecodeError, TypeError):
            cognito_client_secret = secret_value

    if cognito_mfa:
        logger.info(
            f"MFA enabled, extracting token code from last {cognito_mfa_token_length} characters of provided password."
        )
        mfa_token = password[-cognito_mfa_token_length:]
        password = password[:-cognito_mfa_token_length]
    else:
        mfa_token = None

    client = boto3.client('cognito-idp', region_name=cognito_user_pool_region)

    logger.info(f"Authenticating {parsed_username} with client id {cognito_client_id} in region {cognito_user_pool_region}")

    auth_parameters = {
        'USERNAME': parsed_username,
        'PASSWORD': password
    }

    if cognito_client_secret:
        auth_parameters['SECRET_HASH'] = compute_secret_hash(parsed_username, cognito_client_id, cognito_client_secret)

    initiate_auth_kwargs = {
        'AuthFlow': 'USER_PASSWORD_AUTH',
        'AuthParameters': auth_parameters,
        'ClientId': cognito_client_id,
    }

    if cognito_include_source_ip:
        logger.info(f"Propagating source IP {event['sourceIp']} to Cognito UserContextData.")
        initiate_auth_kwargs['UserContextData'] = {
            'IpAddress': event["sourceIp"]
        }

    response = client.initiate_auth(**initiate_auth_kwargs)

    

    logger.debug(f"Cognito response: {response}")

    if response.get("AuthenticationResult", None) is None:
        if "ChallengeName" in response:
            if cognito_mfa is None:
                logger.error(
                    f"Cognito indicated that MFA is required for this user {parsed_username} but no MFA token was provided. Verify that MFA has been enabled in the IdP config."
                )                
                raise CognitoIdpModuleError("MFA required but not configured for this user.")
            elif response["ChallengeName"] == "SOFTWARE_TOKEN_MFA":
                logger.info(f"Responding to MFA challenge with token.")
                challenge_responses = {
                    'USERNAME': parsed_username,
                    'SOFTWARE_TOKEN_MFA_CODE': mfa_token
                }
                if cognito_client_secret:
                    challenge_responses['SECRET_HASH'] = compute_secret_hash(parsed_username, cognito_client_id, cognito_client_secret)
                mfa_response = client.respond_to_auth_challenge(
                    ClientId=cognito_client_id,
                    ChallengeName='SOFTWARE_TOKEN_MFA',
                    Session=response["Session"],
                    ChallengeResponses=challenge_responses
                )
                logger.debug(f"Cognito response: {mfa_response}")
                if mfa_response.get("AuthenticationResult", None) is None:
                    raise CognitoIdpModuleError("Authentication failed. AuthenticationResult was not returned by Cognito RespondToAuthChallenge.")
                else: 
                    logger.info(f"MFA authentication for user {parsed_username} successful.")
            else: 
                logger.error(
                    f"Unsupported challenge type {response['ChallengeName']}."
                )                
                raise CognitoIdpModuleError("Unsupported challenge type {response['ChallengeName']}. SOFTWARE_TOKEN_MFA is the only supported challenge type.")                
        else:
            raise CognitoIdpModuleError("Authentication failed. AuthenticationResult was not returned by Cognito InitiateAuth.")
    else:
        logger.info(f"Authentication for user {parsed_username} successful.")
    
    return response_data
