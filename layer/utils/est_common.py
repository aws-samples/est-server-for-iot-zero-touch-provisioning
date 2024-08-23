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

import logging
import sys
import json
import os
import base64
import boto3
from cryptography import x509
from cryptography.x509 import load_der_x509_csr
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import time
from customisations import sign_device_csr_with_external_pki

logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('myLambda')
LOG_LEVEL = str(os.environ.get("LOG_LEVEL", "INFO")).upper()
logger.setLevel(LOG_LEVEL)

# Amazon root CA for AWS IoT Core endpoint
RSA_CA_CERT_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
ECC_CA_CERT_URL = "https://www.amazontrust.com/repository/AmazonRootCA3.pem"

iot_client = boto3.client('iot')
secret_client = boto3.client('secretsmanager')


def error400(msg: str) -> dict:
    logger.error("400" + msg)
    return {
        "statusCode": 400,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(msg)
    }


def error500(msg: str) -> dict:
    logger.error("500" + msg)
    return {
        "statusCode": 500,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(msg)
    }


def error501() -> dict:
    logger.error("501" + "Not Implemented")
    return {
        "statusCode": 501,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps("Not Implemented. Contact the developers if you require this endpoint.")
    }


def success200_json(body) -> dict:
    logger.info("200" + json.dumps(body))
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(body)
    }


def success200_cert(cert: bytes or str) -> dict:
    # Do not log anything for privacy & security reasons
    if isinstance(cert, str):
        cert = cert.encode("utf-8")
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/pkcs7-mime; smime-type=certs-only",
            "Content-Transfer-Encoding": "base64"
        },
        "body": base64.b64encode(cert)
    }


def no_content204(msg: str = "", headers: dict = None) -> dict:
    payload = {
        "statusCode": 204,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": msg
    }
    if headers:
        payload["headers"] = headers
    return payload


def does_thing_exist(thing_name: str) -> bool:
    """
    Check if the thing exists
    :param thing_name: The name of the thing
    :return: True or False
    """
    try:
        iot_client.describe_thing(
            thingName=thing_name
        )
        return True
    except iot_client.exceptions.ResourceNotFoundException:
        return False
    except Exception as e:
        logger.error(f"Error checking if thing exists: {e}")
        raise


def lower_case_keys(dictionary: dict) -> dict:
    """
    This function returns a new dictionary with all keys lowercased
    :param dictionary:
    :return: dict
    """
    return {k.lower(): v for k, v in dictionary.items()}


def validate_enroll_request(event) -> bool:
    """
    This function validates the request
    :param event:
    :return: True or False
    """
    valid = True
    # Headers are supposed to be case-insensitive
    headers_lc = {k.lower(): v for k, v in event['headers'].items()}
    accept = headers_lc.get('accept', [])
    if "*/*" not in accept and "application/pkcs7-mime" not in accept:
        valid = False
    if "application/pkcs10" not in headers_lc.get('content-type', []):
        valid = False
    if not headers_lc.get('content-transfer-encoding', "") == "base64":
        valid = False
    if "attachment" not in headers_lc.get('content-disposition', ""):
        valid = False
    if valid is not True:
        logger.error("Invalid header(s) detected: {}".format(event))
    return valid


def extract_csr(event) -> bytes or None:
    """
    This function extracts the csr from the event - the CSR is in DER format
    :param event:
    :return: csr
    """
    csr = None
    try:
        csr = base64.b64decode(event['body'])
    except Exception as e:
        logger.error(f"Error decoding CSR: {e}")
    finally:
        return csr


def validate_csr(csr: bytes) -> tuple[dict or None, x509.base.CertificateSigningRequest or None]:
    """
    This function validates the CSR contains the right elements. it expects the Serial Number (SN) field to contain the
    device serial number and the Common Name (CN) filed to contain a combination of the AWS IoT Thing Serial Number and
    a Name like <serial_number>_<name>. The CN is expected to be used as the Thing Name for AWS IoT Core provisioning.
    :param csr: The Certificate Signing Request as a string
    :return tuple: ({"thingName": string,"serialNumber": string}, certificate object)
    """
    try:
        req = load_der_x509_csr(csr)
        cn = req.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not len(cn) > 0:
            raise Exception("No common name found in CSR")
        cn = cn[0].value
        sn = req.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if not len(sn) > 0:
            raise Exception("No serial number found in CSR")
        sn = sn[0].value
        d = {
            "thingName": cn,
            "serialNumber": sn
        }
        logger.info("CSR validation data: {}".format(d))
        return d, req
    except Exception as e:
        logger.error(f"Error validating CSR: {e}")
        return None, None


def create_self_signed_root_ca(attributes: dict, validity_years: int) -> tuple[x509.base.Certificate, rsa.RSAPrivateKey]:
    """
    Generates a self-signed Root CA.
    :param attributes:
    :param validity_years:
    :return: root_ca_cert, root_key objects
    """

    root_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096
    )

    # The self-signed Root CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, attributes["CN"]),
        x509.NameAttribute(NameOID.COUNTRY_NAME, attributes["C"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, attributes["ST"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, attributes["L"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, attributes["O"]),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, attributes["OU"]),
    ])

    root_ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our certificate will be valid for ~10 years
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * validity_years)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
        critical=False,
    ).sign(root_key, hashes.SHA256())

    return root_ca_cert, root_key


def sign_csr_with_own_ca(csr: x509.base.CertificateSigningRequest, root_cert: x509.base.Certificate,
                         root_key: rsa.RSAPrivateKey, validity_years: float = 10) -> x509.base.Certificate or None:
    """
    Sign the CSR with the self-signed Root CA
    :param validity_years:
    :param csr: CSR object
    :param root_cert: Root CA certificate object
    :param root_key: Root CA private key object
    :return: Certificate object
    """
    try:
        ski_ext = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        client_cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            root_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            # Our certificate will be valid for 10 years
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * validity_years)
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value),
            critical=False,
        ).sign(root_key, hashes.SHA256())
        return client_cert
    except Exception as e:
        logger.error(f"Error signing CSR: {e}")
        return None


def get_secret_value(secret_id: str) -> str or bytes or None:
    """
    Return a secret as a string or bytes depending on the type of secret.
    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager/client/get_secret_value.html
    In some case the secrets can be base64 encoded. This is not addressed by this function because it is unlikely to
    happen within the scope of this CDK project.
    :param secret_id:
    :return: string or bytes
    """
    try:
        response = secret_client.get_secret_value(
            SecretId=secret_id
        )
        if 'SecretBinary' in response:
            return response['SecretBinary']
        else:
            return response['SecretString']
    except Exception as e:
        logger.error(f"Error getting secret value: {e}")
        return None


def is_key(key: str) -> bool:
    """
    Check if key has the signature of a key. Covers for Key in PKCS#1 and PKCS#8.
    :param key: a string
    :return: True if the string looks like a key
    """
    return key.startswith("-----BEGIN RSA PRIVATE KEY-----") or key.startswith("-----BEGIN PRIVATE KEY-----")


def sign_thing_csr(csr: x509.base.CertificateSigningRequest, csr_data: dict, ca_cert_secret_arn: str,
                   ca_key_secret_arn: str, validity_years: float) -> x509.base.Certificate or None:
    """
    Sign a new CSR with own or external CA.
    Important: for external CA you must implement the function `sign_externally`
    :param validity_years:
    :param csr:
    :param csr_data:
    :param ca_cert_secret_arn:
    :param ca_key_secret_arn:
    :return string: The PEM formatted signed certificate
    """
    cert_str = get_secret_value(ca_cert_secret_arn)
    key_str = get_secret_value(ca_key_secret_arn)
    if isinstance(key_str, bytes):
        key_str = key_str.decode('utf-8')
    if key_str is None or cert_str is None:
        # Something bad happened
        logger.critical("Exception when reading secrets")
        return None
    elif not is_key(key_str):
        # We don't have the key to sign the CSR, so we delegate to an external signing service
        logger.info("Delegating signature of the CSR")
        return sign_device_csr_with_external_pki(csr, csr_data, validity_years)  # Must be implemented by end user
    elif cert_str == "":
        # We don't have a certificate which is unexpected since we have to register it in IoT Core
        logger.error("Missing Root Certificate for IoT Core in Secrets Manager")
        return None
    else:
        cert_obj = load_pem_x509_certificate(cert_str.encode('utf-8'))
        key_obj = load_pem_private_key(key_str.encode('utf-8'), None)
        signed_cert = sign_csr_with_own_ca(
            csr=csr,
            root_cert=cert_obj,
            root_key=key_obj,
            validity_years=validity_years
        )
        logger.info("Signed a new certificate for: {}".format(csr_data))
        return signed_cert


def register_certificate_with_iot_core(cert: str, thing_name: str, iot_policy_name: str) -> bool:
    """
    Register a certificate with AWS IoT Core
    :param iot_policy_name: the name of the IoT Policy to attach to the certificate
    :param str cert: PEM formatted Thing certificate
    :param str thing_name: The name of the IoT Thing
    :return: True if success or False
    """
    if does_thing_exist(thing_name):
        registration = iot_client.register_certificate(
            certificatePem=cert,
            setAsActive=True
        )
        cert_id = registration['certificateId']
        logger.debug("Certificate {} registered".format(cert_id))
        # Wait for the certificate to be provisioned
        i = 0
        while i < 25:
            i += 1
            certs = [c['certificateId'] for c in iot_client.list_certificates()['certificates']]
            if cert_id in certs:
                break
            time.sleep(0.2)
        logger.debug("Attaching to Policy: {}".format(iot_policy_name))
        iot_client.attach_policy(
            policyName=iot_policy_name,
            target=registration['certificateArn']
        )
        attachment = iot_client.attach_thing_principal(
            thingName=thing_name,
            principal=registration['certificateArn']
        )
        logger.info("New certificate {} attached to Thing: {}".format(registration, thing_name))
        return True
    logger.warning("The certificate could not be attached to Thing {}".format(thing_name))
    return False


def cert_to_pem(cert: x509.base.Certificate or load_der_x509_csr) -> str:
    """
    Convert a certificate or CSR object to PEM format
    :param cert: cert object
    :return: string
    """
    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")


def private_key_to_pem(key: rsa.RSAPrivateKey) -> str:
    """
    Convert a private key object to PEM format
    :param key: key object
    :return: string
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def cert_to_pkcs7_der(certs: list[x509.base.Certificate]) -> bytes:
    """
    Convert a certificate object to DER format
    :param certs: cert object
    :return: bytes
    """
    return pkcs7.serialize_certificates(certs, serialization.Encoding.DER)


def pem_cert_to_pkcs7_der(pem_cert: str) -> bytes:
    """
    Converts a PEM certificate to DER format
    :param pem_cert:
    :return:
    """
    cert = load_pem_x509_certificate(pem_cert.encode('utf-8'))
    return cert_to_pkcs7_der([cert])
