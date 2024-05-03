import logging
import os
import ssl

import ldap3
from aws_xray_sdk.core import patch_all, xray_recorder
from idp_modules import util

patch_all()

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG if os.environ.get("LOGLEVEL", "DEBUG") else logging.INFO)


class LdapIdpModuleError(util.IdpModuleError):
    """Used to raise module-specific exceptions"""

    pass


@xray_recorder.capture()
def handle_auth(
    event,
    parsed_username,
    user_record,
    identity_provider_record,
    response_data,
    authn_method,
):
    logger.debug(f"User record: {user_record}")

    if authn_method != util.AuthenticationMethod.PASSWORD:
        raise LdapIdpModuleError(
            "Password not specified, this provider does not support public key auth."
        )

    identity_provider_config = identity_provider_record["config"]
    ldap_host = identity_provider_config["server"]
    ldap_port = int(identity_provider_config.get("port", 636))
    ldap_ssl = identity_provider_config.get("ssl", True)
    ldap_ssl_verify = identity_provider_config.get("ssl_verify", True)
    ldap_attributes = identity_provider_config.get("attributes", {})
    ldap_search_base = identity_provider_config["search_base"]
    ldap_ignore_missing_attributes = identity_provider_config.get(
        "ignore_missing_attributes", False
    )
    if "domain" in identity_provider_config:
        ldap_domain = identity_provider_config["domain"]
        domain_username = f"{ldap_domain}\{parsed_username}"
    else:
        domain_username = parsed_username

    logger.info(f"LDAP domain username: {domain_username}")

    ldap_attribute_query_list = []

    for attribute in ldap_attributes:
        ldap_attribute_query_list.append(ldap_attributes[attribute])

    ldap_tls = ldap3.Tls(
        validate=ssl.CERT_NONE if not ldap_ssl_verify else ssl.CERT_REQUIRED
    )
    ldap_server = ldap3.Server(
        host=ldap_host, port=ldap_port, use_ssl=ldap_ssl, tls=ldap_tls
    )
    ldap_connection = ldap3.Connection(
        server=ldap_server,
        user=domain_username,
        password=event["password"],
        auto_bind=True,
    )

    logger.debug(f"ldap_connection: {ldap_connection}")

    logger.info("Attempting LDAP bind")

    bound = ldap_connection.bind()

    logger.info(f"LDAP bound: {bound}")
    if not bound:
        raise LdapIdpModuleError(
            f"Unable to perform LDAP bind with credentials provided. Failing auth. Last error: {ldap_connection.last_error}"
        )

    logger.info(f"whoami: {ldap_connection.extend.standard.who_am_i()}")

    if len(ldap_attribute_query_list) > 0:
        logger.info(
            f"Attempting to retrieve LDAP attributes {ldap_attribute_query_list} for user {parsed_username} on base {ldap_search_base}"
        )
        ldap_connection.search(
            search_base=ldap_search_base,
            search_filter=f"(|(&(objectClass=user)(uid={parsed_username}))(&(objectCategory=person)(sAMAccountName={parsed_username})))",
            search_scope=ldap3.SUBTREE,
            dereference_aliases=ldap3.DEREF_NEVER,
            attributes=ldap_attribute_query_list,
        )
        logger.debug(f"LDAP response: {ldap_connection.response}")
        search_response = [
            entry
            for entry in ldap_connection.response
            if entry["type"] == "searchResEntry"
        ]
        if len(search_response) < 1:
            raise LdapIdpModuleError(
                f"The LDAP search for user {parsed_username} returned no results. Enable debug logging and check LDAP response for more information."
            )
        if len(search_response) > 1:
            raise LdapIdpModuleError(
                f"The LDAP search for user {parsed_username} returned no results. Enable debug logging and check LDAP response for more information."
            )

    # Normalize empty values to simplify checking if a value is missing or empty
    ldap_resolved_attributes = {}
    for attribute in ldap_attributes:
        value = ldap_connection.response[0]["attributes"].get(
            ldap_attributes[attribute], None
        )
        if not value is None and (type(value) == int or len(value) > 0):
            ldap_resolved_attributes[attribute] = value
        else:
            ldap_resolved_attributes[attribute] = None
    logger.debug(f"Resolved LDAP attributes: {ldap_resolved_attributes}")

    if "Role" in ldap_attributes:
        if not ldap_resolved_attributes["Role"] is None:
            logger.info(
                f"Applying Role {ldap_resolved_attributes['Role']} from LDAP Attributes"
            )
            response_data["Role"] = ldap_resolved_attributes["Role"]
        elif ldap_ignore_missing_attributes:
            logger.warning(
                f"LDAP attribute {ldap_attributes['Role']} for 'Role' was empty of missing. Skipping."
            )
        else:
            raise LdapIdpModuleError(
                f"LDAP attribute {ldap_attributes['Role']} for property 'Role' was empty or missing. Enable debug logging adn check LDAP response. To ignore, use the ignore_missing_attributes setting in the identity provider config."
            )

    if "Policy" in ldap_attributes:
        if not ldap_resolved_attributes["Policy"] is None:
            logger.info("Applying Policy from LDAP Attributes")
            response_data["Policy"] = ldap_resolved_attributes["Policy"]
        elif ldap_ignore_missing_attributes:
            logger.warning(
                f"LDAP attribute {ldap_attributes['Policy']} for 'Policy' was empty of missing. Skipping."
            )
        else:
            raise LdapIdpModuleError(
                f"LDAP attribute {ldap_attributes['Policy']} for property 'Policy' was empty or missing. Enable debug logging adn check LDAP response. To ignore, use the ignore_missing_attributes setting in the identity provider config."
            )

    if "Uid" in ldap_attributes and "Gid" in ldap_attributes:
        if (
            not ldap_resolved_attributes["Uid"] is None
            and not ldap_resolved_attributes["Gid"] is None
        ):
            logger.info(
                f"Applying PosixProfile {ldap_resolved_attributes['Uid']},{ldap_resolved_attributes['Gid']} from LDAP Attributes"
            )
            response_data.setdefault("PosixProfile", {})
            response_data["PosixProfile"]["Uid"] = ldap_resolved_attributes["Uid"]
            response_data["PosixProfile"]["Gid"] = ldap_resolved_attributes["Gid"]
        elif ldap_ignore_missing_attributes:
            logger.warning(
                f"LDAP attributes {ldap_attributes['Uid']} for 'Uid' and/or {ldap_attributes['Gid']} for 'Gid' were empty of missing. Skipping."
            )
        else:
            raise LdapIdpModuleError(
                f"LDAP attribute {ldap_attributes['Uid']} for 'Uid' and/or {ldap_attributes['Gid']}  for 'Gid' were empty or missing. Enable debug logging adn check LDAP response. To ignore, use the ignore_missing_attributes setting in the identity provider config."
            )

    return response_data
