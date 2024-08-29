# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.# Copyright Amazon.com, Inc. or its affiliates.
# All Rights Reserved.

import est_common as cmn
import boto3
import os

GENERATE_CERT = os.environ['GENERATE_CERT'] == "true"
CA_CERT_SECRET_NAME = os.environ['CA_CERT_SECRET_NAME']
CA_KEY_SECRET_NAME = os.environ['CA_KEY_SECRET_NAME']
CA_VALIDITY_YEARS = int(os.environ['CA_VALIDITY_YEARS'])
KMS_KEY_ARN = os.environ['KMS_KEY_ARN']
REGISTER_CA = os.environ['REGISTER_CA'] == "true"
PROV_TEMPLATE_NAME = os.environ['PROV_TEMPLATE_NAME']
PROVISIONING_BUCKET_NAME = os.environ['PROVISIONING_BUCKET_NAME']
EXTERNAL_CA_CERT_S3_KEY = os.environ['EXTERNAL_CA_CERT_S3_KEY']
EXTERNAL_CA_PKEY_S3_KEY = os.environ['EXTERNAL_CA_PKEY_S3_KEY']
FORCE = os.environ.get('FORCE', False) == "true"


# Set certificate attributes
attributes = {
    "CN": "IoT Core private CA",
    "C": "US",
    "ST": "Washington",
    "L": "Seattle",
    "O": "Amazon Web Services",
    "OU": "Solutions Architecture",
}

secret_client = boto3.client('secretsmanager')
iot_client = boto3.client('iot')
s3_client = boto3.client('s3')


def register_ca_once(cert: str, template_name: str) -> None:
    if REGISTER_CA is True:  # One more safeguard
        for ca_cert in iot_client.list_ca_certificates(templateName=template_name)['certificates']:
            if iot_client.describe_ca_certificate(
                    certificateId=ca_cert['certificateId'])["certificateDescription"]["certificatePem"] == cert:
                cmn.logger.info("CA Certificate already registered. No action")
                return

        response = iot_client.register_ca_certificate(
            caCertificate=cert,
            setAsActive=True,
            allowAutoRegistration=True,
            certificateMode="SNI_ONLY",
            registrationConfig={'templateName': template_name}
        )
        cmn.logger.info("IoT CA certificate registered: {}".format(response))
    else:
        cmn.logger.info("REGISTER_CA is set to False. No action")


def update_secret(secret_name: str, secret_value: str):
    secret_client.put_secret_value(
        SecretId=secret_name,
        SecretString=secret_value
    )
    cmn.logger.info("Updated secret: {}".format(secret_name))


def lambda_handler(event, context):
    """
    This function creates a self-signed certificate for the AWS IoT Core private CA, if it does already exist in
    Secrets Manager
    :param event:
    :param context:
    :return:
    """
    init_cert_value = "NULL"
    init_key_value = "NULL"

    # Create secrets with default value if they don't exist
    try:
        cert_value = secret_client.get_secret_value(SecretId=CA_CERT_SECRET_NAME)['SecretString']
    except secret_client.exceptions.ResourceNotFoundException:
        response = secret_client.create_secret(
            Name=CA_CERT_SECRET_NAME,
            Description="IoT Core private CA certificate",
            KmsKeyId=KMS_KEY_ARN,
            SecretString=init_cert_value
        )
        cert_value = init_cert_value
        cmn.logger.info(
            "Certificate doesn't exist. Empty Secret created: {}".format(response))

    try:
        key_value = secret_client.get_secret_value(SecretId=CA_KEY_SECRET_NAME)['SecretString']
    except secret_client.exceptions.ResourceNotFoundException:
        response = secret_client.create_secret(
            Name=CA_KEY_SECRET_NAME,
            Description="IoT Core private CA key",
            KmsKeyId=KMS_KEY_ARN,
            SecretString=init_key_value
        )
        key_value = init_key_value
        cmn.logger.info(
            "Key doesn't exist. Empty Secret created: {}".format(response))

    # Register external CA certificate if allowed and provided
    # This might register an additional certificate in IoT Core if the pem file has changed
    if EXTERNAL_CA_CERT_S3_KEY != "":

        cert_value = None
        key_value = None
        do_update = True
        try:
            cmn.logger.debug("Reading external CA certificate from S3")
            cert_value = s3_client.get_object(
                Bucket=PROVISIONING_BUCKET_NAME,
                Key=EXTERNAL_CA_CERT_S3_KEY
            )['Body'].read()
            if isinstance(cert_value, bytes):
                cert_value = cert_value.decode('utf-8')
        except Exception as e:
            cmn.logger.critical("Error reading external CA certificate with S3 key:  {}".format(
                EXTERNAL_CA_CERT_S3_KEY))
            cmn.logger.critical("Registering external CA Cert & Key process aborted!!!")
            do_update = False

        try:
            if EXTERNAL_CA_PKEY_S3_KEY != "" and do_update is True:
                cmn.logger.debug("Reading external CA private key from S3")
                # Register private key if available
                key_value = s3_client.get_object(
                    Bucket=PROVISIONING_BUCKET_NAME,
                    Key=EXTERNAL_CA_PKEY_S3_KEY
                )['Body'].read()
                if isinstance(key_value, bytes):
                    key_value = key_value.decode('utf-8')
        except Exception as e:
            cmn.logger.error("Error reading external CA private key with S3 key {}".format(
                EXTERNAL_CA_PKEY_S3_KEY))
            cmn.logger.critical("Registering external CA Cert & Key process aborted!!!")
            do_update = False

        if do_update is True:
            # Store the values
            update_secret(CA_CERT_SECRET_NAME, cert_value)
            if key_value is None:
                key_value = "NONE"
            update_secret(CA_KEY_SECRET_NAME, key_value)
            if REGISTER_CA is True:
                register_ca_once(cert_value, PROV_TEMPLATE_NAME)

            # Stay secure - do not expose secrets: clear objects from S3
        if EXTERNAL_CA_PKEY_S3_KEY != "":
            try:
                response = s3_client.delete_object(
                    Bucket=PROVISIONING_BUCKET_NAME,
                    Key=EXTERNAL_CA_PKEY_S3_KEY
                )
                cmn.logger.info("External CA private key deleted from S3 for security "
                                "reasons.\nResponse is: {}".format(response))
            except Exception as e:  # nosec Bandit suppression: we ignore the exception if the object doesn't exist
                pass
        try:
            response = s3_client.delete_object(
                Bucket=PROVISIONING_BUCKET_NAME,
                Key=EXTERNAL_CA_CERT_S3_KEY
            )
            cmn.logger.info("External CA certificate deleted from S3 for security "
                            "reasons.\nResponse is: {}".format(response))
        except Exception as e:  # nosec Bandit suppression: we ignore the exception if the object doesn't exist
            pass
        return

    if (GENERATE_CERT is not True or len(key_value) > 10 or len(cert_value) > 10) and FORCE is not True:
        if GENERATE_CERT is True:
            cmn.logger.warn("Certificate and/or key already exist. No action!")
        else:
            cmn.logger.warn("Certificate generation not enabled. No action!")
        return


    if not cert_value.startswith("-----BEGIN CERTIFICATE-----"):
        # We can update the certificates and key
        cmn.logger.info("Creating self-signed certificate as IoT Core CA.")
        cert, key = cmn.create_self_signed_root_ca(attributes=attributes, validity_years=CA_VALIDITY_YEARS)
        # Store the certificate and key in Secrets Manager
        cert_pem = cmn.cert_to_pem(cert)
        update_secret(CA_CERT_SECRET_NAME, cert_pem)
        update_secret(CA_KEY_SECRET_NAME, cmn.private_key_to_pem(key))
    else:
        cmn.logger.warning("Certificate already exists in Secret {}. This value will be used to register the "
                           "certificate to IoT Core. No new CA created!".format(
            CA_CERT_SECRET_NAME))
        cert_pem = cert_value

    if REGISTER_CA is True:
        register_ca_once(cert_pem, PROV_TEMPLATE_NAME)
