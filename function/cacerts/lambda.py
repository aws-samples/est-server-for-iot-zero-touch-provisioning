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


CA_CERT_SECRET_ARN = os.environ['CA_CERT_SECRET_ARN']
STRICT_HEADERS_CHECK = os.environ.get('STRICT_HEADERS_CHECK', 'false').lower() == 'true'


def lambda_handler(event, context):
    """
    Returns the current CA certificate used for mTLS in DER format
    :param event: 
    :param context: 
    :return: 
    """
    cmn.logger.debug("Event: {}".format(event))
    headers_lc = {k.lower(): v for k, v in event['headers'].items()}
    accept = headers_lc.get('accept', [])
    if STRICT_HEADERS_CHECK is not False and "*/*" not in accept and "application/pkcs7-mime" not in accept:
        cmn.logger.warn("Unsupported accept header: {}".format(accept))
        return cmn.error400("Unsupported accept header")
    cert = cmn.get_secret_value(CA_CERT_SECRET_ARN)
    if not cert:
        cmn.logger.error("Failed to retrieve certificate ARN: {}".format(CA_CERT_SECRET_ARN))
        return cmn.error500("Failed to retrieve the certificate")

    cmn.logger.debug("Returning certificate from secret ARN {} to caller".format(CA_CERT_SECRET_ARN))
    return cmn.success200_cert(cmn.pem_cert_to_pkcs7_der(cert))

