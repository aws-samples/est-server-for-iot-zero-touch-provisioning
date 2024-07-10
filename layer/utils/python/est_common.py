import logging
import sys
import json
import os
import base64
from boto3 import client as botoclient

logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('myLambda')
LOG_LEVEL = str(os.environ.get("LOG_LEVEL", "WARN")).upper()
logger.setLevel(LOG_LEVEL)

# Amazon root CA for AWS IoT Core endpoint
RSA_CA_CERT_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
ECC_CA_CERT_URL = "https://www.amazontrust.com/repository/AmazonRootCA3.pem"


def error400(msg):
    logger.error("400" + msg)
    return {
        "statusCode": 400,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(msg)
    }

def error500(msg):
    logger.error("500" + msg)
    return {
        "statusCode": 500,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(msg)
    }

def error501():
    logger.error("501" + "Not Implemented")
    return {
        "statusCode": 501,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps("Not Implemented. Contact the developers if you require this endpoint.")
    }

def success200_json(body):
    logger.info("200" + json.dumps(body))
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(body)
    }


def success200_cert(cert:str):
    # Do not log anything for privacy & security reasons
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/pkcs7-mime",
            "Content-Transfer-Encoding": "base64"
        },
        "body": base64.b64encode(cert.encode("utf-8"))
    }

def sign_csr(iot_client: botoclient, csr: str):
    """
    This function is responsible for signing the certificate with the private key
    :param csr: the csr as a string
    :param iot_client: boto3 client for iot
    :return: certificate
    """
    try:
        return iot_client.create_certificate_from_csr(
            certificateSigningRequest=csr,
            setAsActive=True
        )
    except Exception as e:
        logger.error(f"Error signing certificate: {e}")
        return None


def validate_enroll_request(event):
    """
    This function validates the request
    :param event:
    :return: True or False
    """
    valid = True
    accept = event['headers'].get('Accept', [])
    if "*/*" not in accept and "application/pkcs7-mime" not in accept:
        valid = False
    if not "application/pkcs10" in event['headers'].get('Content-Type', []):
        valid = False
    if not event['headers'].get('Content-Transfer-Encoding', "") == "base64":
        valid = False
    if not "attachment" in event['headers'].get('Content-Disposition', ""):
        valid = False
    return valid


def extract_csr(event):
    """
    This function extracts the csr from the event
    :param event:
    :return: csr
    """
    csr = None
    try:
        csr = base64.b64decode(event['body']).decode('utf-8')
    except Exception as e:
        logger.error(f"Error decoding CSR: {e}")
    finally:
        return csr



