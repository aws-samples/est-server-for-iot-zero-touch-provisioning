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


def register_ca_once(cert, template_name):
    if REGISTER_CA is True: # One more safeguard
        for ca_cert in iot_client.list_ca_certificates(templateName=template_name)['certificates']:
            if iot_client.describe_ca_certificate(certificateId=ca_cert['certificateId'])["certificateDescription"] \
                    ["certificatePem"] == cert:
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


def lambda_handler(event, context):
    """
    This function creates a self-signed certificate for the AWS IoT Core private CA, if it does already exist in
    Secrets Manager
    :param event:
    :param context:
    :return:
    """
    INIT_CERT_VALUE = "NULL"
    INIT_KEY_VALUE = "NULL"
    try:
        cert_value = secret_client.get_secret_value(SecretId=CA_CERT_SECRET_NAME)['SecretString']
    except secret_client.exceptions.ResourceNotFoundException:
        response = secret_client.create_secret(
            Name=CA_CERT_SECRET_NAME,
            Description="IoT Core private CA certificate",
            KmsKeyId=KMS_KEY_ARN,
            SecretString=INIT_CERT_VALUE
        )
        cert_value = INIT_CERT_VALUE
        cmn.logger.info(
            "GENERATE_CERT is set to False and Cert doesn't exist. Empty Secret created: {}".format(response))

    try:
        key_value = secret_client.get_secret_value(SecretId=CA_KEY_SECRET_NAME)['SecretString']
    except secret_client.exceptions.ResourceNotFoundException:
        response = secret_client.create_secret(
            Name=CA_KEY_SECRET_NAME,
            Description="IoT Core private CA key",
            KmsKeyId=KMS_KEY_ARN,
            SecretString=INIT_KEY_VALUE
        )
        key_value = INIT_KEY_VALUE
        cmn.logger.info(
            "GENERATE_CERT is set to False and Key doesn't exist. Empty Secret created: {}".format(response))

    if REGISTER_CA is True and cert_value.startswith("-----BEGIN CERTIFICATE-----"):
        register_ca_once(cert_value, PROV_TEMPLATE_NAME)

    if (GENERATE_CERT is not True or len(key_value) > 10 or len(cert_value) > 10) and FORCE is not True:
        if GENERATE_CERT is True:
            cmn.logger.warn("Certificate and/or key already exist. No action!")
        else:
            cmn.logger.warn("Certificate generation not enabled. No action!")
        return

    # We can update the certificates and key
    cert, key = cmn.create_self_signed_root_ca(attributes=attributes, validity_years=CA_VALIDITY_YEARS)
    # Store the certificate and key in Secrets Manager
    cert_pem = cmn.cert_to_pem(cert)
    cert_response = secret_client.put_secret_value(
        SecretId=CA_CERT_SECRET_NAME,
        SecretString=cert_pem,
    )
    cmn.logger.info("New Certificate stored in Secret: {}".format(cert_response))

    key_response = secret_client.put_secret_value(
        SecretId=CA_KEY_SECRET_NAME,
        SecretString=cmn.private_key_to_pem(key),
    )
    cmn.logger.info("New Key stored in Secret: {}".format(key_response))

    if REGISTER_CA is True or FORCE is True:
        register_ca_once(cert_pem, PROV_TEMPLATE_NAME)
