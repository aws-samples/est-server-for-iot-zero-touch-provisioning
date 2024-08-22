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
from customisations import pre_enroll, post_enroll

CA_CERT_SECRET_ARN = os.environ['CA_CERT_SECRET_ARN']
CA_KEY_SECRET_ARN = os.environ['CA_KEY_SECRET_ARN']
STRICT_HEADERS_CHECK = os.environ.get('STRICT_HEADERS_CHECK', 'false').lower() == 'true'


def enroll(csr: CertificateSigningRequest, csr_data: dict) -> bytes or None:
    """
    This is the function that generates the certificate for an IoT device.
    :param csr: The Certificate Signing Request object
    :param csr_data: The parsed CSR data
    :return bytes: The DER encoded signed certificate
    """
    cert = cmn.sign_thing_csr(csr=csr, csr_data=csr_data, ca_cert_secret_arn=CA_CERT_SECRET_ARN,
                                  ca_key_secret_arn=CA_KEY_SECRET_ARN)
    if cert:
        return cmn.cert_to_der(cert)
    else:
        return None


def lambda_handler(event, context):
    """
    Return a new signed CSR after executing pre-enroll and post-enroll custom actions
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
        if pre_enroll(event) is not True:
            return cmn.error400("Pre-enrollment failed")
        cert = enroll(csr, csr_data)
        if not cert:
            return cmn.error400("Certificate signing failed")
        cmn.logger.warning("New enrollment certificate signed for {}".format(csr_data))
        if post_enroll(event) is not True:
            return cmn.error400("Post-enrollment failed")
        return cmn.success200_cert(cert)
    except Exception as e:
        cmn.logger.error(f"Error: {e}")
        return cmn.error500("Internal server error")
