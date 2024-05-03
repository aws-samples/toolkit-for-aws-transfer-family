import base64
import logging
import os

import boto3
from aws_xray_sdk.core import patch_all, xray_recorder
from botocore.config import Config
from botocore.exceptions import ClientError
from enum import Enum

patch_all()

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG if os.environ.get("LOGLEVEL", "DEBUG") else logging.INFO)

boto3_config = Config(retries={"max_attempts": 10, "mode": "standard"})


class IdpModuleError(Exception):
    """Used to raise IdP module exceptions"""

    pass


class AuthenticationMethod(Enum):
    PASSWORD = 1
    PUBLIC_KEY = 2


@xray_recorder.capture()
def get_secret(secret_id):
    client = boto3.session.Session().client(
        service_name="secretsmanager", config=boto3_config
    )

    try:
        resp = client.get_secret_value(SecretId=secret_id)
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if "SecretString" in resp:
            logger.info("Found Secret String")
            return resp["SecretString"]
        else:
            logger.info("Found Binary Secret")
            return base64.b64decode(resp["SecretBinary"])
    except ClientError as err:
        logger.error(
            f'Error Talking to SecretsManager: {err.response["Error"]["Code"]}, Message: {str(err)}'
        )
        return None


@xray_recorder.capture()
def get_transfer_server_details(server_id):
    client = boto3.session.Session().client(
        service_name="transfer", config=boto3_config
    )

    try:
        resp = client.describe_server(ServerId=server_id)
        return resp
    except ClientError as err:
        logger.error(
            f'Error Talking to AWS Transfer API: {err.response["Error"]["Code"]}, Message: {str(err)}'
        )
        return None
