import logging
import os
import json
import urllib
import re
import msal
from idp_modules import util
from aws_lambda_powertools import Tracer

tracer = Tracer()

logger = logging.getLogger(__name__)
logger.setLevel(util.get_log_level())

class EntraIdpModuleError(util.IdpModuleError):
    """Used to raise module-specific exceptions"""
    pass

secret_cache = {}

@tracer.capture_method
def entra_authenticate(client_id, client_secret, authority_url, username, password, scopes):
    app = msal.PublicClientApplication(
        client_id=client_id, 
        client_credential=client_secret,
        authority=authority_url
    )

    result = app.acquire_token_by_username_password(
        username=username,
        password=password,
        scopes=scopes
    )
    logger.debug(f"Authentication result: {result}")

    if "access_token" not in result:
        error_description = result.get("error_description", "Unknown error")
        logger.error(f"Authentication failure: User: {username}; Error: {error_description}")
        raise EntraIdpModuleError(f"Authentication failure: User: {username}; Error: {error_description}")

    return result

@tracer.capture_method
def entra_get_user(access_token):
    graph_url = "https://graph.microsoft.com/v1.0/me"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    response = urllib.request.urlopen(urllib.request.Request(graph_url, headers=headers))
    
    if response.status != 200:
        logger.error(f"Error retrieving user info: HTTP status code {response.status}")
        raise EntraIdpModuleError(f"Error retrieving user info: HTTP status code {response.status}")

    return json.loads(response.read().decode())

@tracer.capture_method
def handle_auth(event, parsed_username, user_record, identity_provider_record, response_data, authn_method):
    logger.debug(f"User record: {user_record}")

    if authn_method == util.AuthenticationMethod.PUBLIC_KEY:
        raise EntraIdpModuleError("This provider does not support public key auth.")

    entra_config = identity_provider_record["config"]
    entra_app_client_id = entra_config["client_id"]
    entra_app_secret_arn = entra_config.get(
        "app_secret_arn", None
    )
    entra_authority_url = entra_config.get("authority_url", "https://login.microsoftonline.com/organizations")

    scopes = entra_config.get("scopes", ["https://graph.microsoft.com/.default"])
    entra_attributes = entra_config.get("attributes", {})
    entra_ignore_missing_attributes = entra_config.get("ignore_missing_attributes", False)
    

    password = event["password"]

    entra_app_secret = util.fetch_secret_cache(secret_cache, entra_app_secret_arn)

    logger.info(f"Attempting authentication with Microsoft Entra")
    auth_result = entra_authenticate(
        client_id=entra_app_client_id, 
        client_secret=entra_app_secret, 
        authority_url=entra_authority_url, 
        username=parsed_username, 
        password=password, 
        scopes=scopes
    )
    logger.info(f"Authentication of {parsed_username} was successful")
    access_token = auth_result["access_token"]

    if entra_attributes:
        logger.info("Fetching user profile")
        entra_user_profile = entra_get_user(access_token)
        logger.debug(f"user profile: {entra_user_profile}")

        logger.info(f"Resolving mapped attributes")
        entra_resolved_attributes = {}
        for attribute in entra_attributes:
            value = entra_user_profile.get(entra_attributes[attribute], None)
            if value is not None and (isinstance(value, int) or len(value) > 0):
                entra_resolved_attributes[attribute] = value
            else:
                entra_resolved_attributes[attribute] = None
        logger.debug(f"Resolved Entra user profile attributes: {entra_resolved_attributes}")

        if "Role" in entra_attributes:
            if entra_resolved_attributes["Role"] is not None:
                logger.info(f"Applying Role {entra_resolved_attributes['Role']} from Entra user profile attributes")
                response_data["Role"] = entra_resolved_attributes["Role"]
            elif entra_ignore_missing_attributes:
                logger.warning(f"Entra user profile attribute '{entra_attributes['Role']}' for 'Role' was empty or missing. Skipping.")
            else:
                raise EntraIdpModuleError(f"Entra user profile attribute '{entra_attributes['Role']}' for property 'Role' was empty or missing. Enable debug logging and check Graph API response. To ignore, use the ignore_missing_attributes setting in the identity provider config.")

        if "Policy" in entra_attributes:
            if entra_resolved_attributes["Policy"] is not None:
                logger.info("Applying Policy from Entra user profile attributes")
                response_data["Policy"] = entra_resolved_attributes["Policy"]
            elif entra_ignore_missing_attributes:
                logger.warning(f"Entra user profile attribute '{entra_attributes['Policy']}' for 'Policy' was empty or missing. Skipping.")
            else:
                raise EntraIdpModuleError(f"Entra user profile attribute '{entra_attributes['Policy']}' for property 'Policy' was empty or missing. Enable debug logging and check Graph API response. To ignore, use the ignore_missing_attributes setting in the identity provider config.")

        if "Uid" in entra_attributes and "Gid" in entra_attributes:
            if entra_resolved_attributes["Uid"] is not None and entra_resolved_attributes["Gid"] is not None:
                logger.info(f"Applying PosixProfile {entra_resolved_attributes['Uid']},{entra_resolved_attributes['Gid']} from Entra user profile attributes")
                response_data.setdefault("PosixProfile", {})
                response_data["PosixProfile"]["Uid"] = entra_resolved_attributes["Uid"]
                response_data["PosixProfile"]["Gid"] = entra_resolved_attributes["Gid"]
            elif entra_ignore_missing_attributes:
                logger.warning(f"Entra user profile attributes '{entra_attributes['Uid']}' for 'Uid' and/or '{entra_attributes['Gid']}' for 'Gid' were empty or missing. Skipping.")
            else:
                raise EntraIdpModuleError(f"Entra user profile attribute '{entra_attributes['Uid']}' for 'Uid' and/or '{entra_attributes['Gid']}' for 'Gid' were empty or missing. Enable debug logging and check Graph API response. To ignore, use the ignore_missing_attributes setting in the identity provider config.")

    return response_data