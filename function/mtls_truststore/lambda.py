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


import json
import boto3
import os
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from cryptography import x509
import est_common as cmn

# Import the environment variables

TRUSTSTORE = os.environ['TRUSTSTORE_S3_KEY']
SECRETS_PATH = os.environ['SECRETS_PATH']
BUCKET = os.environ['BUCKET']
DOMAIN = os.environ['DOMAIN']
CA_SECRETS_NAME = os.environ['CA_SECRETS_NAME']
CA_CERT_VALIDITY = int(os.environ['CA_CERT_VALIDITY'])
CLIENT_SECRETS_NAME = os.environ['CLIENT_SECRETS_NAME']
CLIENT_PFX_SECRET_NAME = os.environ['CLIENT_PFX_SECRET_NAME']
CLIENT_CERT_VALIDITY = int(os.environ['CLIENT_CERT_VALIDITY'])
KMS_KEY_ARN = os.environ['KMS_KEY_ARN']
GENERATE_TRUSTSTORE = os.environ['GENERATE_TRUSTSTORE'] == "true"
FORCE = os.environ.get('FORCE', False) == "true"

# Set certificate attributes
attributes_root = {
    "CN": "API Gateway mTLS private CA",
    "C": "US",
    "ST": "Washington",
    "L": "Seattle",
    "O": "Amazon Web Services",
    "OU": "Solutions Architecture",
}

attributes_client = {
    "CN": "EST client mTLS-cert",
    "C": "US",
    "ST": "Washington",
    "L": "Seattle",
    "O": "Amazon Web Services",
    "OU": "Solutions Architecture",
}

s3_client = boto3.client('s3')
secret_client = boto3.client('secretsmanager')


def secret_exists(secret_name: str) -> bool:
    """
    Check if a secret exists in AWS Secrets Manager
    :param secret_name:
    :return:
    """
    try:
        secret = secret_client.get_secret_value(SecretId=secret_name)
        if "SecretString" in secret:
            if len(secret["SecretString"]) > 10:
                cmn.logger.info("Secret {} already exists.".format(secret_name))
                return True
        if "SecretBinary" in secret:
            if len(secret["SecretBinary"]) > 10:
                cmn.logger.info("Secret {} already exists.".format(secret_name))
                return True
    except secret_client.exceptions.ResourceNotFoundException:
        return False
    return False


def create_or_update(secret_name: str, secret_value: str or bytes, descr: str) -> None:
    """
    Create, update a secret in AWS Secrets Manager
    :param secret_name:
    :param secret_value:
    :param descr:
    :return:
    """

    try:
        args = {
            "Name": secret_name,
            "Description": descr,
            "KmsKeyId": KMS_KEY_ARN
        }
        if isinstance(secret_value, str):
            args["SecretString"] = secret_value
        elif isinstance(secret_value, bytes):
            args["SecretBinary"] = secret_value
        else:
            raise ValueError("Secret value must be a string or bytes")
        response = secret_client.create_secret(**args)
        cmn.logger.info("Secret created successfully: {} / {}".format(response['Name'], response['ARN']))
    except secret_client.exceptions.ResourceExistsException:
        args = {
            "SecretId": secret_name,
        }
        if isinstance(secret_value, str):
            args["SecretString"] = secret_value
        elif isinstance(secret_value, bytes):
            args["SecretBinary"] = secret_value
        else:
            raise ValueError("Secret value must be a string or bytes")
        response = secret_client.put_secret_value(**args)
        cmn.logger.info("Secret updated successfully: {}".format(response['Name'], response['ARN']))


def lambda_handler(event, context):
    """
    This function creates the secrets, self-signed certificate and client certificate in the Truststore
    for a quick mTLS configuration of API Gateway. If the target truststore pem file already exists, the
    function will not make any change.
    :param event:
    :param context:
    :return:
    """
    if FORCE is not True:
        if secret_exists(CA_SECRETS_NAME) or secret_exists(CLIENT_SECRETS_NAME) or secret_exists(
                CLIENT_PFX_SECRET_NAME):
            cmn.logger.warn("Secrets already exist. You must clear all of them if you want to update the Truststore "
                            "(write a string of less than 10 characters. No modification done.")
            return

        if not GENERATE_TRUSTSTORE:
            cmn.logger.warn("Truststore generation is disabled. No action (Secrets will not be created/updated).")
            return

        response = s3_client.list_objects(Bucket=BUCKET, Prefix=TRUSTSTORE)
        if 'Contents' in response:
            for content in response['Contents']:
                if content.get('Key') == TRUSTSTORE:
                    cmn.logger.info("The Truststore chain {} already exists. Delete it from S3 and clear the Secrets"
                                    "if you want to re-generate it. No modification done.".format(TRUSTSTORE))
                    return

    if GENERATE_TRUSTSTORE is True:
        # Create the Root CA
        root_cert, root_key = cmn.create_self_signed_root_ca(attributes=attributes_root,
                                                             validity_years=CA_CERT_VALIDITY)

        # The CSR
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, attributes_client["CN"]),
                x509.NameAttribute(NameOID.COUNTRY_NAME, attributes_client["C"]),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, attributes_client["ST"]),
                x509.NameAttribute(NameOID.LOCALITY_NAME, attributes_client["L"]),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, attributes_client["O"]),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, attributes_client["OU"]),
            ])).add_extension(
            # Describe what FQDN we want this certificate for.
            x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]),
            critical=False,
        ).sign(client_key, hashes.SHA256())

        # Then Sign the CSR with the CA
        client_cert = cmn.sign_csr_with_own_ca(csr, root_cert, root_key, validity_years=CLIENT_CERT_VALIDITY)

        # Generate a pkcs12 bundle
        client_p12 = (pkcs12.serialize_key_and_certificates(
            b"est-client.pfx", client_key, client_cert, None, serialization.NoEncryption()
        ))

        # Store everything in Secrets Manager
        ca_secrets = {
            "certificate": cmn.cert_to_pem(root_cert),
            "key": cmn.private_key_to_pem(root_key)
        }

        cmn.logger.info("API Gateway mTLS Root CA secrets create/update")
        create_or_update(
            secret_name=CA_SECRETS_NAME,
            secret_value=json.dumps(ca_secrets),
            descr="API Gateway mTLS Root CA certificate"
        )

        # FIXME: where to store for customer convenience
        client_secrets = {
            "certificate": cmn.cert_to_pem(client_cert),
            "key": cmn.private_key_to_pem(client_key)
        }

        cmn.logger.info("API Gateway client mTLS secrets create/update")
        create_or_update(
            secret_name=CLIENT_SECRETS_NAME,
            secret_value=json.dumps(client_secrets),
            descr="API Gateway client mTLS secrets"
        )

        cmn.logger.info("API Gateway client mTLS secrets on PFX format create/update")
        create_or_update(
            secret_name=CLIENT_PFX_SECRET_NAME,
            secret_value=client_p12,
            descr="API Gateway client mTLS secrets in PFX format"
        )

        # Store the truststore for API Gateway mTLS on S3
        truststore = s3_client.put_object(
            Body=root_cert.public_bytes(serialization.Encoding.PEM),
            Bucket=BUCKET,
            Key=TRUSTSTORE
        )
        cmn.logger.info("Truststore uploaded to S3: {}".format(TRUSTSTORE))

        # Place the client files on S3
        s3key = SECRETS_PATH + "/est-client-cert.pem"
        s3_client.put_object(
            Body=cmn.cert_to_pem(client_cert),
            Bucket=BUCKET,
            Key=s3key
        )
        cmn.logger.info("Stored client certificate on S3 in {}".format(s3key))

        s3key = SECRETS_PATH + "/est-client-private-key.pem"
        s3_client.put_object(
            Body=cmn.private_key_to_pem(client_key),
            Bucket=BUCKET,
            Key=s3key
        )
        cmn.logger.info("Stored client private key on S3 in {}".format(s3key))

        s3key = SECRETS_PATH + "/est-client.pfx"
        s3_client.put_object(
            Body=client_p12,
            Bucket=BUCKET,
            Key=s3key
        )
        cmn.logger.info("Stored client p12 bundle on S3 in {}".format(s3key))
    else:
        cmn.logger.warn("FORCE is True but GENERATE_TRUSTSTORE is False. No action taken by precaution.")
