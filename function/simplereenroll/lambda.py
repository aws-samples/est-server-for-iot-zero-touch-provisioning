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


import os
import est_common as cmn
from cryptography.x509.base import CertificateSigningRequest
from customisations import pre_reenroll, post_reenroll

CA_CERT_SECRET_ARN = os.environ['CA_CERT_SECRET_ARN']
CA_KEY_SECRET_ARN = os.environ['CA_KEY_SECRET_ARN']
IOT_POLICY_NAME = os.environ['IOT_POLICY_NAME']
STRICT_HEADERS_CHECK = os.environ.get('STRICT_HEADERS_CHECK', 'false').lower() == 'true'
DEVICE_CERT_VALIDITY_YEARS = float(os.environ.get('DEVICE_CERT_VALIDITY_YEARS', '1'))


def reenroll(csr: CertificateSigningRequest, csr_data: dict,
             validity_years: float) -> str or None:
    """
    This function signs a certificate for a IoT device. If the Thing exists in this account, it will be reattached
    to the new certificate. The previous certificate stays attached.
    If the Thing does not exist, no exception is raised because the IoT service could be living in another account.
    But the new certificate won't be usable until it is attached to a thing.
    custom code to sign the certificate with your private PKI.
    :param validity_years:
    :param csr: The Certificate Signing Request
    :param csr_data: The parsed CSR data as a dict
    :return dict: {
        'certificateArn': 'string',
        'certificateId': 'string',
        'certificatePem': 'string'
        }:
    """
    cert = cmn.sign_thing_csr(csr=csr, csr_data=csr_data, ca_cert_secret_arn=CA_CERT_SECRET_ARN,
                              ca_key_secret_arn=CA_KEY_SECRET_ARN, validity_years=validity_years)
    if cert:
        pem_cert = cmn.cert_to_pem(cert)
        der_cert = cmn.cert_to_pkcs7_der([cert])
        _ = cmn.register_certificate_with_iot_core(pem_cert, csr_data['thingName'], IOT_POLICY_NAME)
        return der_cert
    else:
        return None


def lambda_handler(event, context):
    """
    Return a new signed CSR after executing pre-reenroll and post-reenroll custom actions
    The expected Certificate format is DER
    """
    cmn.logger.debug("Event: {}".format(event))
    try:
        if STRICT_HEADERS_CHECK is not False and cmn.validate_enroll_request(event) is not True:
            return cmn.error400("request validation failed")
        csr_str = cmn.extract_csr(event)
        if not csr_str:
            return cmn.error400("CSR extraction failed")
        csr_data, csr = cmn.validate_csr(csr_str)
        if not csr_data:
            return cmn.error400("CSR validation failed")
        if pre_reenroll(event) is not True:
            return cmn.error400("Pre-enrollment failed")
        cert = reenroll(csr, csr_data, DEVICE_CERT_VALIDITY_YEARS)
        if not cert:
            return cmn.error400("Certificate signing failed")
        cmn.logger.warning("New reenrollment certificate signed for {}".format(csr_data))
        if post_reenroll(event) is not True:
            return cmn.error400("Post-enrollment failed")
        return cmn.success200_cert(cert)
    except Exception as e:
        cmn.logger.error(f"Error: {e}")
        return cmn.error500("Internal server error")
