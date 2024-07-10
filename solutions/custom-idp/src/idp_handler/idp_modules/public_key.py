import logging
import os

from aws_xray_sdk.core import patch_all, xray_recorder
from idp_modules import util

patch_all()

logger = logging.getLogger(__name__)
logger.setLevel(util.get_log_level())


class PublicKeyIdpModuleError(util.IdpModuleError):
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

    if not event["protocol"] == "SFTP":
        raise PublicKeyIdpModuleError(
            f"Protocol {event['protocol']} does not support public key auth."
        )

    user_record_config = user_record["config"]

    if not "PublicKeys" in response_data:
        if not "PublicKeys" in user_record_config:
            raise PublicKeyIdpModuleError(
                f"No public keys defined for user in config of user {user_record['user']}."
            )
        else:
            logger.info(f'PublicKeys found in config for user {user_record["user"]}')
            response_data.setdefault(
                "PublicKeys", []
            )  # Sometimes a list isn't returned by boto3 dynamodb get_item when there is only one item in a string set, so we iterate.
            for key in user_record_config["PublicKeys"]:
                response_data["PublicKeys"].append(key)

    return response_data
