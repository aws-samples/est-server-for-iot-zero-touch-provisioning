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
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
import json
import os
import boto3
import est_common as cmn
from cryptography.x509 import load_pem_x509_csr
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

CA_SECRETS_NAME = os.environ['CA_SECRETS_NAME']
CLIENT_CERT_VALIDITY = int(os.environ['CLIENT_CERT_VALIDITY'])
TRUSTSTORE_BUCKET = os.environ['TRUSTSTORE_BUCKET']

s3_client = boto3.client('s3')

SCR_CA_KEY = "certificate"
SCR_KEY_KEY = "key"


def get_csr(bucket, key):
    response = s3_client.get_object(Bucket=bucket, Key=key)

    return load_pem_x509_csr(response['Body'].read())


def lambda_handler(event, context):
    """
    This function signs a CSR with the mTLS Root CA secrets if available. It is provided as a convenience for signing
    client certificates during testing or small scale deployments. Best practice is to have mTLS client certificates
    generated at factory without storing the certificate on S3 as it is done here.
    The function expects the following elements in the 'event':
    * csr_s3_key: the S3 key of the CSR
    * input_bucket (optional): the input bucket. If not provided, the Truststore bucket is used.
    * output_bucket (optional): bucket name for storing the signed certificate. If absent input_bucket is used.
    * validity (optional): override the default validity period of signed certificate

    The output certificate file name is based on the input_s3_key where the extension (if any) is replaced by .crt
    Keep in mind that this function must have read access to the input_bucket and write access to the output_bucket.
    Since the default bucket is the Truststore, this function has already read/write access to it.
    """
    input_bucket = event.get('input_bucket', TRUSTSTORE_BUCKET)
    csr_s3_key = event['csr_s3_key']
    output_bucket = event.get('output_bucket', input_bucket)
    validity = event.get('validity', CLIENT_CERT_VALIDITY)

    csr = get_csr(bucket=input_bucket, key=csr_s3_key)

    ca_secrets = json.loads(cmn.get_secret_value(secret_id=CA_SECRETS_NAME))
    if SCR_CA_KEY not in ca_secrets or SCR_KEY_KEY not in ca_secrets:
        raise Exception("{} or {} not found in the CA secrets".format(SCR_CA_KEY, SCR_KEY_KEY))
    ca_key_str = ca_secrets[SCR_KEY_KEY]
    if not ca_key_str.startswith("-----BEGIN RSA PRIVATE KEY-----"):
        msg = "The private key for the mTLS CA is not known. Cannot sign the client CSR."
        cmn.logger.warning(msg)
        return cmn.no_content204(msg)

    ca_cert = load_pem_x509_certificate(ca_secrets[SCR_CA_KEY].encode('utf-8'))
    ca_key = load_pem_private_key(ca_key_str.encode('utf-8'), None)

    cert_obj = cmn.sign_csr_with_own_ca(csr=csr, root_cert=ca_cert, root_key=ca_key, validity_years=validity)
    cert_pem = cert_obj.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")
    cert_s3_key = os.path.splitext(csr_s3_key)[0] + ".crt"
    s3_client.put_object(Body=cert_pem, Bucket=output_bucket, Key=cert_s3_key)

    return {
        'statusCode': 200,
        'body': "CSR '{}' signed and uploaded successfully".format(csr_s3_key)
    }
