import os
import ssl
import ldap3
import boto3
import logging
import urllib3
import json


class LdapIdpModuleError(Exception):
    """Used to raise module-specific exceptions"""
    pass


client_secrets = boto3.client('secretsmanager', region_name=os.environ["Region"])
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def lambda_handler(event, context):
    try:
        logger.debug(json.dumps(event))

        if event['RequestType'] == 'Create':

            ldap_host = os.environ["ADServerDNS"]
            ldap_port = os.environ["ADServerPort"]
            ldap_ssl = os.environ["ADSSL"]=='true'
            ldap_search_base = os.environ["ADSearchBase"]
            domain_username = get_secret(os.environ["ADDomainUser"])
            domain_user_password =  get_secret(os.environ["ADDomainUserPassword"])
            new_username = get_secret(os.environ["ADNewUser"])
            ldap_ssl_verify = True
            new_user_cn = f"cn={new_username},{ldap_search_base}"


            ldap_tls = ldap3.Tls(
                validate=ssl.CERT_NONE if not ldap_ssl_verify else ssl.CERT_REQUIRED
            )

            ldap_server = ldap3.Server(
                host=ldap_host, port=int(ldap_port), use_ssl=ldap_ssl, tls=ldap_tls
            )

            ldap_connection = ldap3.Connection(
                server=ldap_server,
                user=domain_username,
                password=domain_user_password, 
                auto_bind=True,
            )

            bound = ldap_connection.bind()
            if not bound:
                raise LdapIdpModuleError(
                    f"Unable to perform LDAP bind with credentials provided. Failing auth. Last error: {ldap_connection.last_error}"
                )

            attributes = get_attributes(new_username, "transfer", "testuser")

            OBJECT_CLASS = ['top', 'person', 'organizationalPerson', 'user']
            ldap_connection.add(new_user_cn, object_class=OBJECT_CLASS, attributes=attributes)
            if ldap_connection.result["result"] != 0:
                raise LdapIdpModuleError(
                    f"Unable to create user. Last error: {ldap_connection.result['description']}"
                )

            ldap_connection.modify(new_user_cn, {'userAccountControl': [('MODIFY_REPLACE', 544)]})
            if ldap_connection.result["result"] != 0:
                raise LdapIdpModuleError(
                    f"Unable to create user. Last error: {ldap_connection.result['description']}"
                )

            ldap_connection.unbind()
            logger.debug(ldap_connection.result)

            send_response(event, context, "SUCCESS", {"message":f"User {new_user_cn} created successfully."})
            return 
        
        send_response(event, context, "SUCCESS", {"message":f"Request processed"})
        return 

    except Exception as e:
        logger.error(f"add user failure: {str(e)}")
        send_response(event, context, "FAILED", {"message": f"User creation failed. {str(e)}" })


def get_secret(secret_name):
    try:
        logger.debug(f"getting secret {secret_name}")
        get_secret_value_response = client_secrets.get_secret_value(SecretId=secret_name)
        logging.info("Secret retrieved successfully.")
        SecretString=get_secret_value_response["SecretString"]
        logger.debug(f"value {SecretString}")
        return SecretString
    except client_secrets.exceptions.ResourceNotFoundException:
        msg = f"The requested secret {secret_name} was not found."
        logger.info(msg)
        return msg
    except Exception as e:
        logger.error(f"An unknown error occurred: {str(e)}.")
        raise

def get_attributes(username, forename, surname):
    return {
        "displayName": username,
        "sAMAccountName": username,
        "userPrincipalName": "{0}@test.core.bogus.org.uk".format(username),
        "name": username,
        "givenName": forename,
        "sn": surname
    }


def send_response(event, context, response_status, response_data, physical_resource_id=None, no_echo=False):

    http = urllib3.PoolManager()
    response_url = event['ResponseURL']

    response_body = {}
    response_body['Status'] = response_status
    response_body['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    response_body['PhysicalResourceId'] = physical_resource_id or context.log_stream_name
    response_body['StackId'] = event['StackId']
    response_body['RequestId'] = event['RequestId']
    response_body['LogicalResourceId'] = event['LogicalResourceId']
    response_body['NoEcho'] = no_echo
    response_body['Data'] = response_data

    json_response_body = json.dumps(response_body)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_response_body))
    }

    logger.info("AMI Lookup  Event Lambda handler sending response request " + json.dumps(json_response_body))
    try:
        response = http.request("PUT", response_url,
                                body=json_response_body,
                                headers=headers)
        logger.info(f"AMI Lookup handler status: {response.status}")
    except Exception as e:
        logger.error("send_response(..) failed executing http.request(..): " + str(e))
