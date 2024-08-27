"""
This is the place where you can implement your customisation of the EST server.

Implement the interface to your own PKI to sign the IoT device CSR in 'sign_device_csr_with_external_pki'. Do not change
the name of the functions  which is called automatically if the credentials for signing the device CSR are not present
(CA cert and private key) in the deployment. Make sure to return the PEM formatted x509 certificate as a string
(not Bytes) or return 'None' if the signing fails. If your PKI expects a PEM format for the CSR, uncomment the
corresponding line below and the 'serialization' import.

pre_enroll, post_enroll, pre_reenroll, post_reenroll are functions that are called before and after the enrollment and
reenrollment happens. You can implement your custom logic in these functions. Return 'True' if the operation is
successful or false otherwise. Do not change the name of these functions either.

"""
import os
import json
from cryptography import x509
import boto3

# from cryptography.hazmat.primitives import serialization


def sign_device_csr_with_external_pki(csr: x509.base.CertificateSigningRequest,
                                      csr_data: dict, validity_years: float) -> x509.base.Certificate or None:
    """
    This is an example of how you could sign the certificate externally using a PKI
    :param validity_years:
    :param object csr: The Certificate Signing Request object
    :param dict csr_data: The parsed CSR data see below
    :return: PEM Formatted Certificate as a String

    csr_data = {
            "thingName": equals common name (CN) from CSR,
            "serialNumber": equals Serial number (SN) from CSR
        }
    """
    # convert the csr object to bytes:
    # csr_bytes = csr.public_bytes(encoding=serialization.Encoding.PEM)
    # convert the csr object to string:
    # csr_str = csr.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    # get the custom secret (dict with your key:value):
    secret_client = boto3.client('secretsmanager')  # Usually not in function but acceptable in this use case
    custom_secret_arn = os.environ.get('CUSTOM_SECRET_ARN', None)
    if custom_secret_arn:
        custom_secret = json.loads(secret_client.get_secret_value(SecretId=custom_secret_arn)['SecretString'])

    raise NotImplementedError("Signing a CSR externally is not implemented")


def pre_enroll(event) -> bool:
    """
    This is the first function that is called when enrollment happens before the certificate is generated (CSR is signed)
    :param event:
    :return:
    """
    return True


def post_enroll(event) -> bool:
    """
    This is the last function that is called when enrollment happens after the certificate is generated
    :param event:
    :return:
    """
    return True


def pre_reenroll(event) -> bool:
    """
    This is the first function that is called when enrollment happens before the certificate is generated (CSR signed)
    :param event:
    :return: True or False
    """
    return True


def post_reenroll(event) -> bool:
    """
    This is the last function that is called when enrollment happens after the certificate is generated
    :param event:
    :return: True or False
    """
    return True
