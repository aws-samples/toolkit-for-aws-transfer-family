"""
Keycloak Identity Provider Module
==================================
Provides password and public key authentication for AWS Transfer Family
against a Keycloak identity provider.

Overview
--------
This module supports two authentication flows:

1. Password authentication (ROPC grant)
   - The user's password is verified directly against Keycloak using the
     Resource Owner Password Credentials (ROPC) grant (grant_type=password).
   - Optionally, the Keycloak Admin REST API is then called to verify the
     account is enabled and retrieve per-user attributes (Role, Policy,
     PosixProfile, etc.) defined in the identity provider's `attributes` map.
   - If no admin/client secret is configured, account status check and
     attribute lookup are skipped and Transfer Family session settings are
     taken entirely from the DynamoDB user record.
   - Password authentication can be disabled by setting
     `password_auth_support: false` in the identity provider config.

2. Public key authentication
   - Keycloak does not perform cryptographic key verification — that is done
     by AWS Transfer Family itself after this module returns the public key(s).
   - This module uses the Keycloak Admin REST API to verify the user exists
     and their account is enabled, then optionally retrieves SSH public keys
     and other attributes via the `attributes` map.
   - Public keys are sourced from Keycloak (via the `attributes` map) if
     configured. If Keycloak returns no keys, the module falls back to keys
     stored in the DynamoDB user record. The two sources are mutually
     exclusive — Keycloak takes precedence.
   - Public key support must be enabled by setting `public_key_support: true`
     on the identity provider record. Without this, app.py bypasses this
     module entirely and uses the generic public_key module (DynamoDB only).

Client configuration
--------------------
Two Keycloak clients are supported:

- Authentication client (client_id / client_secret_arn):
    Used for password auth via ROPC. Requires Direct Access Grants enabled.
    Not required when password_auth_support is false.

- Admin client (admin_client_id / admin_client_secret_arn):
    Used for Admin API calls (user lookup, account status, attribute retrieval).
    Requires Service Account Roles enabled with view-users and query-users
    from the realm-management client of the realm where users live (client_realm).
    Defaults to the authentication client if not separately configured.

Attribute mapping
-----------------
The `attributes` config key is an optional map of Transfer Family session
property names to Keycloak custom user attribute names. For example:

    {
        "Role":       "transferRole",
        "PublicKeys": "sshPublicKey",
        "Policy":     "transferPolicy",
        "Uid":        "uidNumber",
        "Gid":        "gidNumber"
    }

Keycloak stores custom attributes as lists. Single-value attributes are
unwrapped to a scalar. PublicKeys is kept as a list to support multiple keys.

Keycloak attributes always override corresponding values in DynamoDB.

DynamoDB config keys
--------------------
All keys live under identity_provider_record["config"]:

Required:
    base_url        - Keycloak server base URL (e.g. https://keycloak.example.com)
    client_realm    - Realm containing the users to authenticate

Required for password auth (unless password_auth_support is false):
    client_id       - Client ID for password authentication (ROPC grant)

Optional:
    client_secret_arn           - Secrets Manager ARN for the client secret (plain string)
    admin_client_id             - Client ID for Admin API calls (defaults to client_id)
    admin_client_secret_arn     - Secrets Manager ARN for the admin client secret (plain string)
    admin_realm                 - Realm to obtain admin token from (defaults to client_realm)
    ssl_verify                  - Whether to verify TLS certificates (default: true)
    ssl_ca_secret_arn           - Secrets Manager ARN for a custom CA certificate (PEM)
    attributes                  - Map of Transfer Family property -> Keycloak attribute name
    ignore_missing_attributes   - If true, silently skip missing attributes (default: false)
    password_auth_support       - If false, reject password auth attempts (default: true)
"""

import logging
import os
import ssl
import json
import base64
import time
import urllib.request
import urllib.parse
from idp_modules import util
from aws_lambda_powertools import Tracer

tracer = Tracer()

logger = logging.getLogger(__name__)
logger.setLevel(util.get_log_level())


class KeycloakIdpModuleError(util.IdpModuleError):
    """Raised for Keycloak-specific authentication and configuration errors."""
    pass


# Module-level cache for Secrets Manager values. Secrets are fetched once per
# Lambda execution context and reused for subsequent invocations within the same
# warm instance. This avoids repeated Secrets Manager API calls for the same secret.
secret_cache = {}

# Module-level cache for admin bearer tokens. Lambda execution contexts are reused
# across invocations ("warm instances"), so caching here avoids a token endpoint
# round-trip on every authentication request. The token is cached until 30 seconds
# before its actual expiry (read from the JWT exp claim), so we never use a token
# that is about to expire. This works correctly regardless of the Keycloak realm's
# token lifetime configuration.
admin_token_cache = {}


@tracer.capture_method
def build_ssl_context(ssl_verify, ssl_ca_secret_arn=None):
    """Build an SSL context for connections to Keycloak.

    Args:
        ssl_verify: When False, disables TLS certificate verification entirely.
                    Not recommended for production.
        ssl_ca_secret_arn: Optional Secrets Manager ARN containing a PEM-encoded
                           CA certificate. Use when Keycloak uses a private or
                           self-signed certificate.

    Returns:
        ssl.SSLContext configured according to the supplied parameters.
    """
    if not ssl_verify:
        # Disable all certificate verification — use only in development/testing
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    if ssl_ca_secret_arn:
        # Load a custom CA certificate from Secrets Manager for private PKI
        ca_data = util.fetch_secret_cache(secret_cache, ssl_ca_secret_arn)
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=ca_data)
        return ctx

    # Default: use the system trust store for certificate verification
    return ssl.create_default_context()


@tracer.capture_method
def keycloak_authenticate(base_url, client_realm, client_id, client_secret, username, password, ssl_ctx):
    """Authenticate a user against Keycloak using the Resource Owner Password Credentials (ROPC) grant.

    Posts grant_type=password to the Keycloak token endpoint. On success,
    Keycloak returns an access token. The token itself is not used further —
    a successful response is sufficient to confirm the credentials are valid.

    The Keycloak client must have Direct Access Grants enabled. For confidential
    clients, client_secret must be provided.

    Args:
        base_url:       Keycloak server base URL
        client_realm:   Realm to authenticate against
        client_id:      Client ID with Direct Access Grants enabled
        client_secret:  Client secret for confidential clients, or None for public clients
        username:       Username to authenticate
        password:       Password to verify
        ssl_ctx:        SSL context for the HTTPS connection

    Raises:
        KeycloakIdpModuleError: If authentication fails (HTTP error or no access_token returned)
    """
    url = f"{base_url}/realms/{client_realm}/protocol/openid-connect/token"
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

    # Log request parameters but exclude sensitive values
    safe_params = {k: v for k, v in urllib.parse.parse_qs(data).items() if k not in ("password", "client_secret")}
    logger.info(f"Keycloak auth request: POST {url} params={safe_params}")

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
def get_admin_token(base_url, admin_realm, client_id, client_secret, ssl_ctx):
    """Obtain a bearer token for the Keycloak Admin REST API using the client_credentials grant.

    The client must have Service Account Roles enabled in Keycloak and the
    service account must be assigned view-users and query-users from the
    realm-management client of the realm where users live.

    Note: admin_realm may differ from client_realm when the admin client is
    defined in a different realm to the users (e.g. a service account in the
    master realm managing users in a separate realm).

    Tokens are cached in admin_token_cache keyed by (base_url, admin_realm, client_id).
    The cache entry expires 30 seconds before the token's actual expiry, read from
    the JWT exp claim. This means the cache TTL automatically reflects whatever
    token lifetime is configured in the Keycloak realm/client, with no hardcoded
    assumptions about expiry duration.

    Args:
        base_url:       Keycloak server base URL
        admin_realm:    Realm to obtain the admin token from
        client_id:      Admin client ID with service account roles enabled
        client_secret:  Admin client secret
        ssl_ctx:        SSL context for the HTTPS connection

    Returns:
        Bearer token string for use in Authorization headers

    Raises:
        KeycloakIdpModuleError: If the token request fails
    """
    # Use a composite cache key so different admin clients/realms don't share tokens
    cache_key = f"{base_url}::{admin_realm}::{client_id}"

    cached = admin_token_cache.get(cache_key)
    if cached:
        # Check if the token is still valid (with a 30-second buffer before expiry)
        if cached["expires_at"] > time.time() + 30:
            logger.debug(f"Using cached admin token for {cache_key}")
            return cached["token"]
        else:
            logger.debug(f"Cached admin token for {cache_key} is expired or about to expire, refreshing.")

    url = f"{base_url}/realms/{admin_realm}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, context=ssl_ctx) as resp:
            resp_body = json.loads(resp.read())
            token = resp_body["access_token"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logger.error(f"Failed to obtain admin token: HTTP {e.code}; Response: {error_body}")
        raise KeycloakIdpModuleError(
            f"Failed to obtain Keycloak admin/service account token: HTTP {e.code}; Response: {error_body}"
        )

    # Read the expiry from the JWT payload (exp claim) rather than using a hardcoded TTL.
    # The JWT is base64url-encoded in three parts: header.payload.signature
    try:
        payload_b64 = token.split(".")[1]
        # Add padding if needed for base64 decoding
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(payload_b64))
        expires_at = payload["exp"]
        logger.debug(f"Admin token for {cache_key} expires at {expires_at} (unix timestamp)")
    except Exception as e:
        # If we can't parse the JWT, fall back to a conservative 60-second TTL
        logger.warning(f"Could not parse admin token JWT to read expiry, defaulting to 60s TTL: {e}")
        expires_at = time.time() + 60

    admin_token_cache[cache_key] = {"token": token, "expires_at": expires_at}
    return token


@tracer.capture_method
def get_keycloak_user(base_url, client_realm, username, admin_token, ssl_ctx):
    """Look up a single user by exact username via the Keycloak Admin REST API.

    Uses the ?exact=true parameter to prevent partial matches. The admin client
    must have view-users and query-users roles assigned for client_realm.

    Args:
        base_url:       Keycloak server base URL
        client_realm:   Realm to search for the user in
        username:       Exact username to look up
        admin_token:    Bearer token from get_admin_token()
        ssl_ctx:        SSL context for the HTTPS connection

    Returns:
        Keycloak user object dict containing id, username, enabled, attributes, etc.

    Raises:
        KeycloakIdpModuleError: If the user is not found, multiple matches are
                                returned, or the API call fails
    """
    params = urllib.parse.urlencode({"username": username, "exact": "true"})
    url = f"{base_url}/admin/realms/{client_realm}/users?{params}"

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
    """Resolve Transfer Family session properties from a Keycloak user object.

    Keycloak stores custom user attributes under user["attributes"] as lists,
    even for single values (e.g. {"uidNumber": ["1000"]}). Standard top-level
    fields such as "enabled" are not lists.

    For each entry in attribute_map, this function:
    - Checks top-level user fields first (e.g. "enabled", "username")
    - Falls back to custom attributes under user["attributes"]
    - Unwraps single-item lists to a scalar, except for properties that are
      expected to remain as lists (currently only PublicKeys, which supports
      multiple SSH keys)
    - Sets the resolved value to None if the attribute is absent or empty

    Args:
        user:           Keycloak user object from get_keycloak_user()
        attribute_map:  Dict mapping Transfer Family property name -> Keycloak attribute name
                        e.g. {"Role": "transferRole", "PublicKeys": "sshPublicKey"}
        ignore_missing: Unused here; present for signature consistency with apply_resolved_attributes

    Returns:
        Dict mapping Transfer Family property name -> resolved value (or None if not found)
    """
    kc_attributes = user.get("attributes", {})
    resolved = {}

    # Properties that Transfer Family expects as lists even when only one value is present.
    # All other properties are unwrapped from single-item lists to a scalar.
    list_valued_keys = {"PublicKeys"}

    for transfer_key, kc_key in attribute_map.items():
        # Check top-level user fields first (e.g. "enabled"), then custom attributes
        if kc_key in user:
            value = user[kc_key]
        else:
            value = kc_attributes.get(kc_key, None)

        # Unwrap single-item lists unless the property is expected to be a list
        if isinstance(value, list) and len(value) == 1 and transfer_key not in list_valued_keys:
            value = value[0]
        elif isinstance(value, list) and len(value) == 0:
            value = None

        # Store None explicitly so apply_resolved_attributes can detect missing values
        if value is not None and (isinstance(value, int) or len(value) > 0):
            resolved[transfer_key] = value
        else:
            resolved[transfer_key] = None

    return resolved


@tracer.capture_method
def apply_resolved_attributes(resolved_attributes, attribute_map, response_data, ignore_missing, authn_method):
    """Apply resolved Keycloak attributes to the Transfer Family session response.

    For each supported Transfer Family property present in attribute_map:
    - If the resolved value is not None, it is written into response_data,
      overriding any value previously set from DynamoDB.
    - If the resolved value is None and ignore_missing is True, a warning is
      logged and the property is left as-is in response_data (DynamoDB value
      is preserved if one was set).
    - If the resolved value is None and ignore_missing is False, authentication
      fails with an error.

    PublicKeys is a special case: it is never returned for password authentication
    (AWS Transfer Family rejects responses that include PublicKeys for password auth).

    Uid and Gid are always applied together as PosixProfile. If one is present
    but the other is missing, the pair is treated as missing.

    Args:
        resolved_attributes:    Output of resolve_keycloak_attributes()
        attribute_map:          The attributes config map from the identity provider record
        response_data:          The Transfer Family session response dict being built
        ignore_missing:         Whether to silently skip missing attributes
        authn_method:           The authentication method (PASSWORD or PUBLIC_KEY)

    Returns:
        response_data with Keycloak attribute values applied
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

    if "PublicKeys" in attribute_map:
        if authn_method == util.AuthenticationMethod.PASSWORD:
            # AWS Transfer Family rejects responses that include PublicKeys for
            # password authentication — skip regardless of what Keycloak returned
            logger.debug("Skipping PublicKeys attribute — not returned for password authentication.")
        elif resolved_attributes["PublicKeys"] is not None:
            keys = resolved_attributes["PublicKeys"]
            if isinstance(keys, str):
                keys = [keys]
            logger.info(f"Applying {len(keys)} public key(s) from Keycloak user attributes")
            response_data.setdefault("PublicKeys", [])
            response_data["PublicKeys"].extend(keys)
        elif ignore_missing:
            logger.warning(
                f"Keycloak attribute '{attribute_map['PublicKeys']}' for 'PublicKeys' was empty or missing. Skipping."
            )
        else:
            raise KeycloakIdpModuleError(
                f"Keycloak attribute '{attribute_map['PublicKeys']}' for property 'PublicKeys' was empty or missing. "
                f"To ignore, use the ignore_missing_attributes setting in the identity provider config."
            )

    if "Uid" in attribute_map and "Gid" in attribute_map:
        # Uid and Gid must both be present to form a valid PosixProfile.
        # If only one is found, the pair is treated as missing.
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
    """Main entry point for Keycloak authentication, called by app.py.

    Handles both PASSWORD and PUBLIC_KEY authentication methods. The flow differs
    per method but both share the same config resolution and Admin API logic.

    Password authentication flow:
        1. Verify credentials via ROPC grant (keycloak_authenticate)
        2. If a client or admin secret is configured:
           a. Obtain an admin token (get_admin_token)
           b. Look up the user via Admin API (get_keycloak_user)
           c. Verify the account is enabled
           d. If attributes are configured, resolve and apply them
        3. If no secret is configured, skip steps 2a-2d with a warning.
           Session settings will come entirely from DynamoDB.

    Public key authentication flow:
        1. If a client or admin secret is configured:
           a. Obtain an admin token (get_admin_token)
           b. Look up the user via Admin API (get_keycloak_user)
           c. Verify the account is enabled
           d. If attributes are configured (including PublicKeys), resolve and apply them
        2. If no secret is configured, skip steps 1a-1d with a warning.
        3. Always call public_key.handle_auth as a fallback:
           - If Keycloak returned PublicKeys, public_key.handle_auth is a no-op
             (it skips DynamoDB when PublicKeys is already in response_data)
           - If Keycloak returned no keys, public_key.handle_auth reads keys
             from the DynamoDB user record
           - If neither source has keys, public_key.handle_auth raises an error

    Args:
        event:                      Lambda event from AWS Transfer Family
        parsed_username:            Username resolved for the identity provider
        user_record:                DynamoDB user record
        identity_provider_record:   DynamoDB identity provider record
        response_data:              Transfer Family session response dict (pre-populated
                                    by app.py with values from DynamoDB)
        authn_method:               util.AuthenticationMethod.PASSWORD or PUBLIC_KEY

    Returns:
        response_data with all session properties populated

    Raises:
        KeycloakIdpModuleError: On authentication failure, disabled account,
                                missing required attributes, or configuration errors
    """
    logger.debug(f"User record: {user_record}")

    identity_provider_config = identity_provider_record["config"]

    # --- Resolve required config ---
    keycloak_base_url = identity_provider_config["base_url"]
    keycloak_client_realm = identity_provider_config["client_realm"]

    # password_auth_support defaults to true; when false, password auth is
    # rejected and client_id is not required
    password_auth_support = identity_provider_config.get("password_auth_support", True)

    # Reject password auth if explicitly disabled for this provider
    if authn_method == util.AuthenticationMethod.PASSWORD and not password_auth_support:
        raise KeycloakIdpModuleError(
            "Password authentication is disabled for this identity provider. "
            "Set 'password_auth_support' to true in the identity provider config to enable it."
        )

    # client_id is required for password auth; optional for public key only setups
    if password_auth_support:
        keycloak_client_id = identity_provider_config["client_id"]
    else:
        keycloak_client_id = identity_provider_config.get("client_id", None)

    # --- Resolve optional config ---

    # Authentication client secret (used for ROPC and as Admin API fallback)
    keycloak_client_secret_arn = identity_provider_config.get("client_secret_arn", None)

    # Admin client — separate client for Admin API calls (recommended for production).
    # Defaults to the authentication client if not separately configured.
    keycloak_admin_client_id = identity_provider_config.get("admin_client_id", keycloak_client_id)
    keycloak_admin_client_secret_arn = identity_provider_config.get("admin_client_secret_arn", None)

    # admin_realm is the realm used to obtain the admin token. Differs from
    # client_realm only when the admin client is defined in a separate realm
    # (e.g. a service account in master realm, users in a different realm).
    keycloak_admin_realm = identity_provider_config.get("admin_realm", keycloak_client_realm)

    keycloak_ssl_verify = identity_provider_config.get("ssl_verify", True)
    keycloak_ssl_ca_secret_arn = identity_provider_config.get("ssl_ca_secret_arn", None)

    # attributes is an optional map of Transfer Family property -> Keycloak attribute name.
    # When empty, no Admin API attribute lookup is performed and all session settings
    # come from DynamoDB.
    keycloak_attributes = identity_provider_config.get("attributes", {})
    keycloak_ignore_missing_attributes = identity_provider_config.get("ignore_missing_attributes", False)

    # --- Resolve secrets from Secrets Manager ---
    keycloak_client_secret = None
    if keycloak_client_secret_arn:
        keycloak_client_secret = util.fetch_secret_cache(secret_cache, keycloak_client_secret_arn)

    keycloak_admin_client_secret = None
    if keycloak_admin_client_secret_arn:
        keycloak_admin_client_secret = util.fetch_secret_cache(secret_cache, keycloak_admin_client_secret_arn)

    ssl_ctx = build_ssl_context(keycloak_ssl_verify, keycloak_ssl_ca_secret_arn)

    # -------------------------------------------------------------------------
    # Password authentication
    # -------------------------------------------------------------------------
    if authn_method == util.AuthenticationMethod.PASSWORD:
        logger.info(f"Attempting password authentication for user {parsed_username} against Keycloak realm {keycloak_client_realm}")
        keycloak_authenticate(
            base_url=keycloak_base_url,
            client_realm=keycloak_client_realm,
            client_id=keycloak_client_id,
            client_secret=keycloak_client_secret,
            username=parsed_username,
            password=event["password"],
            ssl_ctx=ssl_ctx,
        )
        logger.info(f"Password authentication successful for user {parsed_username}")

        # Call the Admin API to check account status and resolve attributes.
        # Requires at least one secret to be configured. If neither is set,
        # skip with a warning — session settings come from DynamoDB only.
        if keycloak_admin_client_secret_arn is not None or keycloak_client_secret is not None:
            if keycloak_admin_client_secret_arn is not None:
                # Preferred: use the dedicated admin client
                logger.info("Using admin client credentials to call Keycloak Admin API.")
                admin_token = get_admin_token(
                    base_url=keycloak_base_url,
                    admin_realm=keycloak_admin_realm,
                    client_id=keycloak_admin_client_id,
                    client_secret=keycloak_admin_client_secret,
                    ssl_ctx=ssl_ctx,
                )
            else:
                # Fallback: use the authentication client for Admin API calls.
                # The client must have service account roles enabled.
                logger.info("Using client credentials to call Keycloak Admin API.")
                admin_token = get_admin_token(
                    base_url=keycloak_base_url,
                    admin_realm=keycloak_admin_realm,
                    client_id=keycloak_client_id,
                    client_secret=keycloak_client_secret,
                    ssl_ctx=ssl_ctx,
                )

            kc_user = get_keycloak_user(
                base_url=keycloak_base_url,
                client_realm=keycloak_client_realm,
                username=parsed_username,
                admin_token=admin_token,
                ssl_ctx=ssl_ctx,
            )
            logger.debug(f"Keycloak user object: {kc_user}")

            # Reject authentication if the Keycloak account is disabled,
            # regardless of whether attributes are configured
            if not kc_user.get("enabled", True):
                raise KeycloakIdpModuleError(
                    f"Account for user {parsed_username} is disabled in Keycloak. Failing authentication."
                )

            # Resolve and apply per-user attributes from Keycloak if configured.
            # Keycloak attribute values override anything already in response_data from DynamoDB.
            if keycloak_attributes:
                resolved = resolve_keycloak_attributes(
                    kc_user, keycloak_attributes, keycloak_ignore_missing_attributes
                )
                logger.debug(f"Resolved Keycloak attributes: {resolved}")
                apply_resolved_attributes(resolved, keycloak_attributes, response_data, keycloak_ignore_missing_attributes, authn_method)
        else:
            if keycloak_attributes:
                raise KeycloakIdpModuleError(
                    "Attributes are configured but neither admin_client_secret_arn nor client_secret_arn is set. "
                    "A confidential client is required to query the Keycloak Admin API for user attributes."
                )
            logger.warning(
                "No admin or client secret configured — skipping account status check and attribute lookup."
            )

    # -------------------------------------------------------------------------
    # Public key authentication
    # -------------------------------------------------------------------------
    elif authn_method == util.AuthenticationMethod.PUBLIC_KEY:
        from . import public_key

        # Call the Admin API to verify the user exists, check account status,
        # and optionally retrieve attributes including SSH public keys.
        if keycloak_admin_client_secret_arn is not None or keycloak_client_secret is not None:
            if keycloak_admin_client_secret_arn is not None:
                # Preferred: use the dedicated admin client
                logger.info("Using admin client credentials to call Keycloak Admin API.")
                admin_token = get_admin_token(
                    base_url=keycloak_base_url,
                    admin_realm=keycloak_admin_realm,
                    client_id=keycloak_admin_client_id,
                    client_secret=keycloak_admin_client_secret,
                    ssl_ctx=ssl_ctx,
                )
            else:
                # Fallback: use the authentication client
                logger.info("Using client credentials to call Keycloak Admin API.")
                admin_token = get_admin_token(
                    base_url=keycloak_base_url,
                    admin_realm=keycloak_admin_realm,
                    client_id=keycloak_client_id,
                    client_secret=keycloak_client_secret,
                    ssl_ctx=ssl_ctx,
                )

            kc_user = get_keycloak_user(
                base_url=keycloak_base_url,
                client_realm=keycloak_client_realm,
                username=parsed_username,
                admin_token=admin_token,
                ssl_ctx=ssl_ctx,
            )
            logger.debug(f"Keycloak user object: {kc_user}")

            # Reject authentication if the account is disabled
            if not kc_user.get("enabled", True):
                raise KeycloakIdpModuleError(
                    f"Account for user {parsed_username} is disabled in Keycloak. Failing authentication."
                )

            # Resolve and apply attributes if configured.
            # If PublicKeys is in the attribute map, SSH keys are added to response_data here.
            if keycloak_attributes:
                resolved = resolve_keycloak_attributes(
                    kc_user, keycloak_attributes, keycloak_ignore_missing_attributes
                )
                logger.debug(f"Resolved Keycloak attributes: {resolved}")
                apply_resolved_attributes(resolved, keycloak_attributes, response_data, keycloak_ignore_missing_attributes, authn_method)
        else:
            if keycloak_attributes:
                raise KeycloakIdpModuleError(
                    "Attributes are configured but neither admin_client_secret_arn nor client_secret_arn is set. "
                    "A confidential client is required to query the Keycloak Admin API for user attributes."
                )
            logger.warning(
                "No admin or client secret configured — skipping account status check and attribute lookup. "
                "Falling back to public key module for keys from user record."
            )

        # Always call the public_key module as a fallback for key resolution:
        #   - If Keycloak already populated PublicKeys in response_data, this is a no-op
        #     (public_key.handle_auth skips DynamoDB when PublicKeys is already present)
        #   - If Keycloak returned no keys (attributes not configured, or no keys on the user),
        #     this reads public keys from the DynamoDB user record
        #   - If neither source provides keys, public_key.handle_auth raises an error
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
