# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.

import importlib
import ipaddress
import json
import logging
import os
import re
from aws_lambda_powertools import Tracer

tracer = Tracer()

import boto3
import botocore
from boto3.dynamodb.conditions import Key
from idp_modules import util


logger = logging.getLogger(__name__)
logger.setLevel(util.get_log_level())


os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = "regional"

AWS_REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", ""))

USERS_TABLE_ID = os.environ["USERS_TABLE"]
IDENTITY_PROVIDERS_TABLE_ID = os.environ["IDENTITY_PROVIDERS_TABLE"]
USER_NAME_DELIMITER = os.environ["USER_NAME_DELIMITER"]

ACCOUNT_ID = boto3.client('sts', config=util.boto3_config).get_caller_identity().get('Account')
USERS_TABLE = boto3.resource("dynamodb", config=util.boto3_config).Table(USERS_TABLE_ID)
IDENTITY_PROVIDERS_TABLE = boto3.resource("dynamodb",config=util.boto3_config).Table(IDENTITY_PROVIDERS_TABLE_ID)


class IdpHandlerException(Exception):
    """Used to raise handler exceptions"""

    pass


@tracer.capture_method
def ip_in_cidr_list(ip_address, cidr_list):
    for cidr in cidr_list:
        logger.debug("Checking Allowed IP CIDR: {}".format(cidr))
        network = ipaddress.ip_network(cidr)
        if ipaddress.ip_address(ip_address) in network:
            logger.info("Matched {} to IP CIDR {}".format(ip_address, cidr))
            return True
        else:
            logger.debug(
                "Source IP {} doesn't match IP CIDR {}".format(ip_address, cidr)
            )

    return False


@tracer.capture_method
def server_id_in_allow_list(server_id, allow_list):
    """
    Validates if a server ID is in the allow list.
    
    Args:
        server_id: The server ID to validate (string)
        allow_list: List or set of allowed server IDs (can be None or empty)
    
    Returns:
        True if allow_list is None, empty, or contains the server_id
        False if server_id is not in a non-empty allow_list
    """
    # If allow_list is None or empty, allow all servers
    if not allow_list or len(allow_list) == 0:
        logger.debug(f"Server ID allow list is empty or None, allowing server {server_id}")
        return True
    
    # Check if server_id is in the allow_list
    for allowed_server_id in allow_list:
        logger.debug(f"Checking allowed server ID: {allowed_server_id}")
        if server_id == allowed_server_id:
            logger.info(f"Matched server ID {server_id} to allowed server ID {allowed_server_id}")
            return True
        else:
            logger.debug(f"Server ID {server_id} doesn't match allowed server ID {allowed_server_id}")
    
    logger.debug(f"Server ID {server_id} not found in allow list")
    return False


@tracer.capture_method
def resolve_username_for_idp(username, user_record):
    """
    Resolves the username to use for identity provider authentication.
    
    Args:
        username: The Transfer Family username (from parsed input)
        user_record: The DynamoDB user record
    
    Returns:
        The username to use for IDP authentication (either idp_username or original username)
    """
    # Check if user_record contains idp_username field
    idp_username = user_record.get("idp_username", "")
    
    # If idp_username is present and non-empty, use it
    if idp_username and idp_username.strip():
        logger.info(f"Username mapping: Transfer username='{username}', IDP username='{idp_username}'")
        return idp_username
    
    # Log when idp_username is empty
    if "idp_username" in user_record and not idp_username.strip():
        logger.debug(f"idp_username field is empty, using Transfer username")
    
    # Otherwise, use the original Transfer username
    logger.info(f"No username mapping configured, using Transfer username for IDP authentication")
    return username


@tracer.capture_lambda_handler
def lambda_handler(event, context):
    response_data = {}

    logger.info({i: event[i] for i in event if i not in ["password"]})

    if "username" not in event or "serverId" not in event:
        raise IdpHandlerException("Incoming username or serverId missing  - Unexpected")

    input_username = event["username"].lower()
    logger.info(f"Username: {input_username}, ServerId: {event['serverId']}")
    tracer.put_annotation(key="transfer_user", value=input_username)
    tracer.put_annotation(key="server_id", value=event['serverId'])


    # Parse the username to get user and identity provider (if specified)
    parsed_username = input_username.split(USER_NAME_DELIMITER)

    if 1 < len(parsed_username):
        if (
            USER_NAME_DELIMITER == "@" or USER_NAME_DELIMITER == "@@"
        ):  # support format <user>@<idp>   OR <user>@@<idp>
            username = USER_NAME_DELIMITER.join(parsed_username[:-1])
            identity_provider = parsed_username[-1]
        else:  # anything else is in this order <idp>\<user> , <idp>/<user>
            username = USER_NAME_DELIMITER.join(parsed_username[1:])
            identity_provider = parsed_username[0]
    else:
        username = parsed_username[0]
        identity_provider = None

    logger.info(
        f"Parsed username and IdP: Username: {username} IDP: {identity_provider}"
    )
    if username == "$" or username == "$default$":
        raise IdpHandlerException(f"Username $default$ is reserved and cannot be used.")
    
    # Lookup user
    if identity_provider:
        user_record = USERS_TABLE.get_item(
            Key={"user": username, "identity_provider_key": identity_provider}
        ).get("Item", None)
    else:
        user_record = USERS_TABLE.query(
            KeyConditionExpression=Key("user").eq(username)
        ).get("Items", None)
        logger.debug(f"user_record query result: {user_record}")
        if 0 < len(user_record):
            user_record = user_record[0]
        else:
            user_record = None

    if not user_record:
        logger.info(
            f"Record for user {username} identity provider {identity_provider} not found, retrieving default user record"
        )
        user_record = USERS_TABLE.query(
            KeyConditionExpression=Key("user").eq("$default$")
        ).get("Items", None)
        logger.debug(f"user_record query result: {user_record}")
        if 0 < len(user_record):
            user_record = user_record[0]
        else:
            raise IdpHandlerException(f"no matching user records found")

    logger.info(f"user_record: {user_record}")

    # Resolve username for identity provider authentication
    idp_username = resolve_username_for_idp(username, user_record)
    logger.debug(f"Resolved IDP username: {idp_username}")

    # Check server ID allow list for user
    user_server_id_allow_list = user_record.get("server_id_allow_list", None)
    logger.debug(f"User Server ID Allow List: {user_server_id_allow_list}")
    if not user_server_id_allow_list or len(user_server_id_allow_list) == 0:
        logger.info("No user server ID allow list is present, skipping check.")
    else:
        if not server_id_in_allow_list(event['serverId'], user_server_id_allow_list):
            raise IdpHandlerException(
                f"User {username} is not allowed to authenticate to server {event['serverId']}."
            )
        logger.info(f"Server ID {event['serverId']} is authorized for user {username}.")

    source_ip = event["sourceIp"]

    # Check IP allow list for user
    user_ipv4_allow_list = user_record.get("ipv4_allow_list", "")
    logger.debug(f"IPv4 Allow List: {user_ipv4_allow_list}")
    if not user_ipv4_allow_list or user_ipv4_allow_list == "":
        logger.info("No user IPv4 allow list is present, skipping check.")
    else:
        if not ip_in_cidr_list(source_ip, user_ipv4_allow_list):
            raise IdpHandlerException(
                f"Source IP {source_ip} is not allowed to connect."
            )

    # Lookup identity provider config
    identity_provider = user_record.get("identity_provider_key", "$default$")
    logger.info(f"Fetching identity provider record for {identity_provider}")
    identity_provider_record = IDENTITY_PROVIDERS_TABLE.get_item(
        Key={"provider": identity_provider}
    ).get("Item", None)
    logger.debug(f"identity_provider_record: {identity_provider_record}")
    tracer.put_annotation(key="identity_provider", value=identity_provider_record["provider"])
    if identity_provider_record is None:
        raise IdpHandlerException(
            f"Identity provider {identity_provider} is not defined in the table {IDENTITY_PROVIDERS_TABLE}."
        )
    
    if identity_provider_record.get('disabled', False):
        raise IdpHandlerException(
                f"Identity provider {identity_provider} is disabled."
            )

    # Check server ID allow list for identity provider
    identity_provider_server_id_allow_list = identity_provider_record.get("server_id_allow_list", None)
    logger.debug(f"Identity Provider Server ID Allow List: {identity_provider_server_id_allow_list}")
    if not identity_provider_server_id_allow_list or len(identity_provider_server_id_allow_list) == 0:
        logger.info("No identity provider server ID allow list is present, skipping check.")
    else:
        if not server_id_in_allow_list(event['serverId'], identity_provider_server_id_allow_list):
            raise IdpHandlerException(
                f"Server {event['serverId']} is not allowed to use identity provider {identity_provider}."
            )
        logger.info(f"Server ID {event['serverId']} is authorized for identity provider {identity_provider}.")

    # Check IP allow list for IdP
    identity_provider_ipv4_allow_list = identity_provider_record.get(
        "ipv4_allow_list", ""
    )
    logger.debug(f"IPv4 Allow List: {identity_provider_ipv4_allow_list}")
    if not identity_provider_ipv4_allow_list or identity_provider_ipv4_allow_list == "":
        logger.info("No identity provider IPv4 allow list is present, skipping check.")
    else:
        if not ip_in_cidr_list(source_ip, identity_provider_ipv4_allow_list):
            raise IdpHandlerException(
                f"Source IP {source_ip} is not allowed to connect."
            )

    # Merge AWS transfer session values from identity provider and user records to begin building response. Values in user record always supersede the identity provider record, though identity provider modules have final say in further manipulating these values, this eliminates a lot of duplicate logic that would otherwise be written in provider modules.
    user_record.setdefault("config", {})
    identity_provider_record.setdefault("config", {})

    if "Role" in user_record["config"]:
        response_data["Role"] = user_record["config"]["Role"]
        logger.info(
            f"Using Role value {user_record['config']['Role']} from user record for user {input_username}"
        )
    elif "Role" in identity_provider_record["config"]:
        logger.info(
            f"Using role value {identity_provider_record['config']['Role']} from identity provider record {identity_provider} for user {input_username}"
        )
        response_data["Role"] = identity_provider_record["config"]["Role"]
    else:
        logger.warning(
            f"Role arn not found in user record for {input_username} or identity provider record {identity_provider}. It may still be provided by identity provider response."
        )

    # These are optional
    if "Policy" in user_record["config"]:
        logger.info(f"Using Policy value from user record for user {input_username}")
        response_data["Policy"] = user_record["config"]["Policy"]
    elif "Policy" in identity_provider_record["config"]:
        logger.info(
            f"Using Policy value from identity provider record {identity_provider} for user {input_username}"
        )
        response_data["Policy"] = identity_provider_record["config"]["Policy"]
    else:
        logger.info(
            f"No Policy value found in  user record for {input_username} or identity provider record {identity_provider}, skipping"
        )

    if "HomeDirectoryDetails" in user_record["config"]:
        logger.info(f"HomeDirectoryDetails found in record for user {input_username}")
        response_data["HomeDirectoryDetails"] = user_record["config"][
            "HomeDirectoryDetails"
        ]
        response_data["HomeDirectoryType"] = "LOGICAL"
    elif "HomeDirectory" in user_record["config"]:
        logger.info(
            f"HomeDirectory found for user {input_username} - Cannot be used with HomeDirectoryDetails"
        )
        response_data["HomeDirectory"] = user_record["config"]["HomeDirectory"]
        response_data["HomeDirectoryType"] = "PATH"
    elif "HomeDirectoryDetails" in identity_provider_record["config"]:
        logger.info(
            f"HomeDirectoryDetails found in identity provider record {identity_provider} for user {input_username} - Applying setting for virtual folders"
        )
        response_data["HomeDirectoryDetails"] = identity_provider_record["config"][
            "HomeDirectoryDetails"
        ]
        response_data["HomeDirectoryType"] = "LOGICAL"
    elif "HomeDirectory" in identity_provider_record["config"]:
        logger.info(
            f"HomeDirectory found in identity provider record {identity_provider} for user {input_username} - Cannot be used with HomeDirectoryDetails"
        )
        response_data["HomeDirectory"] = identity_provider_record["config"][
            "HomeDirectory"
        ]
        response_data["HomeDirectoryType"] = "PATH"
    else:
        logger.warning(
            f"HomeDirectory and HomeDirectoryDetails in user record for {input_username} or identity provider record {identity_provider}"
        )

    if "PosixProfile" in user_record["config"]:
        logger.info(
            f"Using PosixProfile value from user record for user {input_username}"
        )
        response_data["PosixProfile"] = user_record["config"]["PosixProfile"]
    elif "PosixProfile" in identity_provider_record:
        logger.info(
            f"Using PosixProfile value from identity provider record {identity_provider} for user {input_username}"
        )
        response_data["PosixProfile"] = identity_provider_record["config"][
            "PosixProfile"
        ]
    else:
        logger.info(
            f"PosixProfile not found in user record for {input_username} or identity provider record {identity_provider}, won't be set."
        )

    # Intentionally, we DO NOT merge PublicKeys entries from identity provider record because it implies shared credentials. PublicKeys entries should only come from user records or in values returned by the identity provider if implemented.

    logger.debug(
        f"Response Data before processing with IdP module: {response_data}"
    )

    if event.get("password", "").strip() == "":
        logger.info(f"No password provided, performing public key auth.")   
        authn_method = util.AuthenticationMethod.PUBLIC_KEY
    else:
        logger.info(f"Password provided, performing password auth.")
        authn_method = util.AuthenticationMethod.PASSWORD

    # Some identity providers have built-in public key support, as specified in their config. If they don't, fall back to the public_key module.
    if (
        authn_method == util.AuthenticationMethod.PUBLIC_KEY
        and not identity_provider_record.get("public_key_support", False)
    ):
        from idp_modules import public_key

        response_data = public_key.handle_auth(
            event=event,
            parsed_username=idp_username,
            user_record=user_record,
            identity_provider_record=identity_provider_record,
            response_data=response_data,
            authn_method=authn_method,
        )
    else:
        # Load the identity provider module and perform authentication with the provider
        identity_provider_module = importlib.import_module(
            f'idp_modules.{identity_provider_record["module"]}'
        )
        response_data = identity_provider_module.handle_auth(
            event=event,
            parsed_username=idp_username,
            user_record=user_record,
            identity_provider_record=identity_provider_record,
            response_data=response_data,
            authn_method=authn_method,
        )

    # HomeDirectoryDetails must be a stringified list, check if any paths have a server filter and apply the filter.
    if "HomeDirectoryDetails" in response_data:
        if type(response_data["HomeDirectoryDetails"]) == list:
            # Apply server filtering first
            total_entries = len(response_data["HomeDirectoryDetails"])
            filtered_by_server = []
            for entry in response_data["HomeDirectoryDetails"]:
                if "servers" in entry:
                    if not event['serverId'] in entry["servers"]:
                        logger.debug(f"Virtual directory entry {entry['Entry']} has a server filter that does not include {event['serverId']}. Removing from list.")
                    else:
                        logger.debug(f"Virtual directory entry {entry['Entry']} has a server filter that includes {event['serverId']}.")
                        entry.pop("servers")
                        filtered_by_server.append(entry)
                else:
                    logger.debug(f"Virtual directory entry {entry['Entry']} has no server filter.")
                    filtered_by_server.append(entry)
            
            # Log server filtering results
            server_filtered_count = len(filtered_by_server)
            logger.info(f"Server filtering: {server_filtered_count} of {total_entries} directory entries included for server {event['serverId']}")
            
            if server_filtered_count == 0:
                logger.warning(f"All directory entries filtered out by server filter for server {event['serverId']}. No directories available for user {username}.")
            
            # Apply region filtering to server-filtered entries
            filtered_home_directory_details = []
            for entry in filtered_by_server:
                if "regions" in entry:
                    if not AWS_REGION.lower() in entry["regions"]:
                        logger.debug(f"Virtual directory entry {entry['Entry']} has a region filter that does not include {AWS_REGION}. Removing from list.")
                    else:
                        logger.debug(f"Virtual directory entry {entry['Entry']} has a region filter that includes {AWS_REGION}.")
                        entry.pop("regions")
                        filtered_home_directory_details.append(entry)
                else:
                    logger.debug(f"Virtual directory entry {entry['Entry']} has no region filter.")
                    filtered_home_directory_details.append(entry)
            
            # Log region filtering results
            region_filtered_count = len(filtered_home_directory_details)
            logger.info(f"Region filtering: {region_filtered_count} of {server_filtered_count} directory entries included for region {AWS_REGION}")
            
            if region_filtered_count == 0 and server_filtered_count > 0:
                logger.warning(f"All directory entries filtered out by region filter for region {AWS_REGION}. No directories available for user {username}.")
            
            response_data["HomeDirectoryDetails"] = json.dumps(
                filtered_home_directory_details
            )

    # Strip "\n" from Public Key strings. Sometimes they are added unintentionally when copying from terminal
    if len(response_data.get("PublicKeys", [])) > 0:
        for i, key in enumerate(response_data["PublicKeys"]):
            response_data["PublicKeys"][i] = key.replace("\\n", "")

    # An extra check to make sure we've really authenticated, prevent accidental authentication. There should always be either at least 1 public key in response, or 'password' authentication should have been used.
    if (
        len(response_data.get("PublicKeys", [])) < 1
        and event.get("password", "").strip() == ""
    ):
        raise IdpHandlerException(
            "PublicKeys is empty and password was not set. Check user config and authentication module logic."
        )

    logger.debug(f"Response Data after processing with IdP module: {response_data}")

    response_data_str = json.dumps(response_data)
    
    response_variables = {
        "USERNAME": username,
        "AWS_REGION": AWS_REGION,
        "AWS_ACCOUNT": ACCOUNT_ID,
        "SERVER_ID": event['serverId']
    }

    response_data_str = re.sub(r'\{\{(\w+)\}\}', lambda match: response_variables[match.group(1)], response_data_str)

    response_data = json.loads(response_data_str)

    logger.info(f"Completed Response Data: {json.dumps(response_data, default=list)}")

    return response_data
