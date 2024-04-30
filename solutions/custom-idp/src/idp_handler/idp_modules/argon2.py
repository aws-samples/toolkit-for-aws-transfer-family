import logging
import os

from aws_xray_sdk.core import patch_all, xray_recorder
from idp_modules import util
import argon2

patch_all()

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG if os.environ.get("LOGLEVEL", "DEBUG") else logging.INFO)


class Argon2IdpModuleError(util.IdpModuleError):
    "Used to raise module-specific exceptions"
    pass


@xray_recorder.capture()
def handle_auth(
    event, parsed_username, user_record, identity_provider_record, response_data
):
    logger.debug(f"User record: {user_record}")  

    if event.get("password", "").strip() == "" :
        raise Argon2IdpModuleError(
            "Password not specified, this provider does not support public key auth."
    )
    user_record_config = user_record["config"]
    hashed_password = user_record_config.get("argon2_password", "")
    logger.debug(f"Hashed password: {hashed_password}")
    

    if hashed_password.strip() == "":
        raise Argon2IdpModuleError(
            f"No argon2_password defined in record for user {parsed_username}."
        )

    hasher = argon2.PasswordHasher()
    # Throws an exception if password/hash is incorrect 
    hasher.verify(hashed_password, event["password"])

    logger.info(f"User {parsed_username} authenticated successfully.")

    return response_data


