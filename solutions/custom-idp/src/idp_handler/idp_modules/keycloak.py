import logging
import os
import ssl
import json
import urllib.request
import urllib.parse
from idp_modules import util
from aws_lambda_powertools import Tracer

tracer = Tracer()

logger = logging.getLogger(__name__)
logger.setLevel(util.get_log_level())


class KeycloakIdpModuleError(util.IdpModuleError):
    """Used to raise module-specific exceptions"""

    pass


secret_cache = {}
admin_token_cache = {}


@tracer.capture_method
def build_ssl_context(ssl_verify, ssl_ca_secret_arn=None):
    """Build an SSL context based on the identity provider configuration."""
    if not ssl_verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    if ssl_ca_secret_arn:
        ca_data = util.fetch_secret_cache(secret_cache, ssl_ca_secret_arn)
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=ca_data)
        return ctx

    return ssl.create_default_context()


@tracer.capture_method
def keycloak_authenticate(base_url, realm, client_id, client_secret, username, password, ssl_ctx):
    """Authenticate a user against Keycloak using the Resource Owner Password Credentials grant."""
    url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
    })
    if client_secret:
        data += "&" + urllib.parse.urlencode({"client_secret": client_secret})

    encoded_data = data.encode("utf-8")
    req = urllib.request.Request(url, data=encoded_data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    safe_params = {k: v for k, v in urllib.parse.parse_qs(data).items() if k not in ("password", "client_secret")}
    logger.debug(f"Keycloak auth request: POST {url} params={safe_params}")

    try:
        with urllib.request.urlopen(req, context=ssl_ctx) as resp:
            resp_body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logger.error(
            f"Authentication failure for user {username}: HTTP {e.code}; Response: {error_body}"
        )
        raise KeycloakIdpModuleError(
            f"Authentication failure for user {username}: HTTP {e.code}; Response: {error_body}"
        )

    if "access_token" not in resp_body:
        raise KeycloakIdpModuleError(
            f"Authentication failure for user {username}: No access_token in Keycloak response."
        )

    return resp_body


@tracer.capture_method
def get_admin_token(base_url, token_realm, client_id, client_secret, ssl_ctx):
    """Obtain a service account token using client_credentials grant. Cached for 60 seconds."""
    cached = util.fetch_cache(admin_token_cache, "admin_token", 60)
    if cached is not None:
        return cached

    url = f"{base_url}/realms/{token_realm}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, context=ssl_ctx) as resp:
            token = json.loads(resp.read())["access_token"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logger.error(f"Failed to obtain admin token: HTTP {e.code}; Response: {error_body}")
        raise KeycloakIdpModuleError(
            f"Failed to obtain Keycloak admin/service account token: HTTP {e.code}; Response: {error_body}"
        )

    util.set_cache(admin_token_cache, "admin_token", token)
    return token


@tracer.capture_method
def get_keycloak_user(base_url, realm, username, admin_token, ssl_ctx):
    """Look up a user by exact username via the Keycloak Admin REST API."""
    params = urllib.parse.urlencode({"username": username, "exact": "true"})
    url = f"{base_url}/admin/realms/{realm}/users?{params}"

    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {admin_token}")

    try:
        with urllib.request.urlopen(req, context=ssl_ctx) as resp:
            users = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logger.error(f"Failed to look up user {username}: HTTP {e.code}; Response: {error_body}")
        raise KeycloakIdpModuleError(
            f"Failed to look up user {username} in Keycloak: HTTP {e.code}; Response: {error_body}"
        )

    if not users:
        raise KeycloakIdpModuleError(f"User not found in Keycloak: {username}")

    if len(users) > 1:
        raise KeycloakIdpModuleError(
            f"Multiple users found for username {username} in Keycloak, expected exactly one."
        )

    return users[0]


@tracer.capture_method
def resolve_keycloak_attributes(user, attribute_map, ignore_missing):
    """Resolve user attributes from the Keycloak user object.

    Keycloak stores custom attributes under user["attributes"] as lists.
    Standard fields like 'enabled' are top-level on the user object.
    The attribute_map maps Transfer Family property names to Keycloak attribute names.
    """
    kc_attributes = user.get("attributes", {})
    resolved = {}

    for transfer_key, kc_key in attribute_map.items():
        # Check top-level user fields first, then custom attributes
        if kc_key in user:
            value = user[kc_key]
        else:
            value = kc_attributes.get(kc_key, None)

        # Keycloak custom attributes are always lists; unwrap single values
        if isinstance(value, list) and len(value) == 1 and transfer_key != "PublicKeys":
            value = value[0]
        elif isinstance(value, list) and len(value) == 0:
            value = None

        if value is not None and (isinstance(value, int) or len(value) > 0):
            resolved[transfer_key] = value
        else:
            resolved[transfer_key] = None

    return resolved


@tracer.capture_method
def apply_resolved_attributes(resolved_attributes, attribute_map, response_data, ignore_missing):
    """Apply resolved Keycloak attributes to the Transfer Family response data.

    Follows the same pattern as LDAP, Okta, and Entra modules.
    """
    if "Role" in attribute_map:
        if resolved_attributes["Role"] is not None:
            logger.info(f"Applying Role {resolved_attributes['Role']} from Keycloak user attributes")
            response_data["Role"] = resolved_attributes["Role"]
        elif ignore_missing:
            logger.warning(
                f"Keycloak attribute '{attribute_map['Role']}' for 'Role' was empty or missing. Skipping."
            )
        else:
            raise KeycloakIdpModuleError(
                f"Keycloak attribute '{attribute_map['Role']}' for property 'Role' was empty or missing. "
                f"To ignore, use the ignore_missing_attributes setting in the identity provider config."
            )

    if "Policy" in attribute_map:
        if resolved_attributes["Policy"] is not None:
            logger.info("Applying Policy from Keycloak user attributes")
            response_data["Policy"] = resolved_attributes["Policy"]
        elif ignore_missing:
            logger.warning(
                f"Keycloak attribute '{attribute_map['Policy']}' for 'Policy' was empty or missing. Skipping."
            )
        else:
            raise KeycloakIdpModuleError(
                f"Keycloak attribute '{attribute_map['Policy']}' for property 'Policy' was empty or missing. "
                f"To ignore, use the ignore_missing_attributes setting in the identity provider config."
            )

    if "Uid" in attribute_map and "Gid" in attribute_map:
        if resolved_attributes["Uid"] is not None and resolved_attributes["Gid"] is not None:
            logger.info(
                f"Applying PosixProfile {resolved_attributes['Uid']},{resolved_attributes['Gid']} from Keycloak user attributes"
            )
            response_data.setdefault("PosixProfile", {})
            response_data["PosixProfile"]["Uid"] = resolved_attributes["Uid"]
            response_data["PosixProfile"]["Gid"] = resolved_attributes["Gid"]
        elif ignore_missing:
            logger.warning(
                f"Keycloak attributes '{attribute_map['Uid']}' for 'Uid' and/or '{attribute_map['Gid']}' for 'Gid' "
                f"were empty or missing. Skipping."
            )
        else:
            raise KeycloakIdpModuleError(
                f"Keycloak attribute '{attribute_map['Uid']}' for 'Uid' and/or '{attribute_map['Gid']}' for 'Gid' "
                f"were empty or missing. To ignore, use the ignore_missing_attributes setting in the identity provider config."
            )

    return response_data


@tracer.capture_method
def handle_auth(
    event,
    parsed_username,
    user_record,
    identity_provider_record,
    response_data,
    authn_method,
):
    logger.debug(f"User record: {user_record}")

    identity_provider_config = identity_provider_record["config"]

    # Required config
    keycloak_base_url = identity_provider_config["base_url"]
    keycloak_realm = identity_provider_config["realm"]
    keycloak_client_id = identity_provider_config["client_id"]

    # Optional config
    keycloak_client_secret_arn = identity_provider_config.get("client_secret_arn", None)
    keycloak_service_account_secret_arn = identity_provider_config.get("service_account_secret_arn", None)
    keycloak_token_realm = identity_provider_config.get("token_realm", keycloak_realm)
    keycloak_ssl_verify = identity_provider_config.get("ssl_verify", True)
    keycloak_ssl_ca_secret_arn = identity_provider_config.get("ssl_ca_secret_arn", None)
    keycloak_attributes = identity_provider_config.get("attributes", {})
    keycloak_ignore_missing_attributes = identity_provider_config.get("ignore_missing_attributes", False)

    # Resolve client secret if stored in Secrets Manager
    keycloak_client_secret = None
    if keycloak_client_secret_arn:
        keycloak_client_secret = util.fetch_secret_cache(secret_cache, keycloak_client_secret_arn)

    ssl_ctx = build_ssl_context(keycloak_ssl_verify, keycloak_ssl_ca_secret_arn)

    if authn_method == util.AuthenticationMethod.PASSWORD:
        # --- Password authentication: authenticate user directly via ROPC grant ---
        logger.info(f"Attempting password authentication for user {parsed_username} against Keycloak realm {keycloak_realm}")
        keycloak_authenticate(
            base_url=keycloak_base_url,
            realm=keycloak_realm,
            client_id=keycloak_client_id,
            client_secret=keycloak_client_secret,
            username=parsed_username,
            password=event["password"],
            ssl_ctx=ssl_ctx,
        )
        logger.info(f"Password authentication successful for user {parsed_username}")

        # If attributes are configured, use admin API to retrieve them
        if keycloak_attributes:
            if keycloak_service_account_secret_arn is None:
                logger.info(
                    "Attributes configured but no service_account_secret_arn provided. "
                    "Using client_credentials grant with the configured client to retrieve user attributes."
                )
                if keycloak_client_secret is None:
                    raise KeycloakIdpModuleError(
                        "Attributes are configured but neither service_account_secret_arn nor client_secret_arn is set. "
                        "A service account or confidential client is required to query the Keycloak Admin API for user attributes."
                    )
                admin_token = get_admin_token(
                    base_url=keycloak_base_url,
                    token_realm=keycloak_token_realm,
                    client_id=keycloak_client_id,
                    client_secret=keycloak_client_secret,
                    ssl_ctx=ssl_ctx,
                )
            else:
                logger.info("Using service account credentials to retrieve user attributes from Keycloak Admin API.")
                service_account = json.loads(
                    util.fetch_secret_cache(secret_cache, keycloak_service_account_secret_arn)
                )
                admin_token = get_admin_token(
                    base_url=keycloak_base_url,
                    token_realm=keycloak_token_realm,
                    client_id=service_account.get("client_id", keycloak_client_id),
                    client_secret=service_account["client_secret"],
                    ssl_ctx=ssl_ctx,
                )

            kc_user = get_keycloak_user(
                base_url=keycloak_base_url,
                realm=keycloak_realm,
                username=parsed_username,
                admin_token=admin_token,
                ssl_ctx=ssl_ctx,
            )
            logger.debug(f"Keycloak user object: {kc_user}")

            # Check if user is enabled
            if not kc_user.get("enabled", True):
                raise KeycloakIdpModuleError(
                    f"Account for user {parsed_username} is disabled in Keycloak. Failing authentication."
                )

            resolved = resolve_keycloak_attributes(
                kc_user, keycloak_attributes, keycloak_ignore_missing_attributes
            )
            logger.debug(f"Resolved Keycloak attributes: {resolved}")
            apply_resolved_attributes(resolved, keycloak_attributes, response_data, keycloak_ignore_missing_attributes)

    elif authn_method == util.AuthenticationMethod.PUBLIC_KEY:
        from . import public_key

        # --- Public key authentication: use admin API to retrieve user and public keys ---
        if keycloak_service_account_secret_arn is not None:
            logger.info(
                "Public key auth with service account configured. "
                "Using service account to retrieve user details and public keys from Keycloak."
            )
            service_account = json.loads(
                util.fetch_secret_cache(secret_cache, keycloak_service_account_secret_arn)
            )
            admin_token = get_admin_token(
                base_url=keycloak_base_url,
                token_realm=keycloak_token_realm,
                client_id=service_account.get("client_id", keycloak_client_id),
                client_secret=service_account["client_secret"],
                ssl_ctx=ssl_ctx,
            )
        elif keycloak_client_secret is not None:
            logger.info(
                "Public key auth with client credentials. "
                "Using client_credentials grant to retrieve user details and public keys from Keycloak."
            )
            admin_token = get_admin_token(
                base_url=keycloak_base_url,
                token_realm=keycloak_token_realm,
                client_id=keycloak_client_id,
                client_secret=keycloak_client_secret,
                ssl_ctx=ssl_ctx,
            )
        else:
            logger.info(
                "No service account or client secret configured. "
                "Passing to public key auth module to use keys from user record."
            )
            response_data = public_key.handle_auth(
                event=event,
                parsed_username=parsed_username,
                user_record=user_record,
                identity_provider_record=identity_provider_record,
                response_data=response_data,
                authn_method=authn_method,
            )
            return response_data

        kc_user = get_keycloak_user(
            base_url=keycloak_base_url,
            realm=keycloak_realm,
            username=parsed_username,
            admin_token=admin_token,
            ssl_ctx=ssl_ctx,
        )
        logger.debug(f"Keycloak user object: {kc_user}")

        # Check if user is enabled
        if not kc_user.get("enabled", True):
            raise KeycloakIdpModuleError(
                f"Account for user {parsed_username} is disabled in Keycloak. Failing authentication."
            )

        # Resolve attributes (including PublicKeys if mapped)
        if keycloak_attributes:
            resolved = resolve_keycloak_attributes(
                kc_user, keycloak_attributes, keycloak_ignore_missing_attributes
            )
            logger.debug(f"Resolved Keycloak attributes: {resolved}")
            apply_resolved_attributes(resolved, keycloak_attributes, response_data, keycloak_ignore_missing_attributes)

        # Retrieve public keys from Keycloak user attributes
        kc_user_attributes = kc_user.get("attributes", {})
        public_keys_attr = identity_provider_config.get("public_key_attribute", "sshPublicKey")
        kc_public_keys = kc_user_attributes.get(public_keys_attr, [])

        if kc_public_keys:
            logger.info(
                f"Found {len(kc_public_keys)} public key(s) in Keycloak attribute '{public_keys_attr}' for user {parsed_username}"
            )
            if isinstance(kc_public_keys, str):
                kc_public_keys = [kc_public_keys]
            response_data.setdefault("PublicKeys", [])
            response_data["PublicKeys"].extend(kc_public_keys)
        else:
            logger.info(
                f"No public keys found in Keycloak attribute '{public_keys_attr}' for user {parsed_username}. "
                f"Falling back to public key module for keys from user record."
            )

        # Always pass through the public_key module so it can merge keys from the user record config
        response_data = public_key.handle_auth(
            event=event,
            parsed_username=parsed_username,
            user_record=user_record,
            identity_provider_record=identity_provider_record,
            response_data=response_data,
            authn_method=authn_method,
        )
    else:
        raise KeycloakIdpModuleError(
            f"Keycloak module does not support authentication method: {authn_method}."
        )

    return response_data
