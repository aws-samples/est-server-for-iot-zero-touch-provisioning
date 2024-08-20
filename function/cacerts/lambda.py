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
from urllib import request

AMAZON_IOT_CA_URL = os.environ['AMAZON_IOT_CA_URL']


def lambda_handler(event, context):
    """
    Returns the current CA certificate used by AWS IoT Core
    :param event: 
    :param context: 
    :return: 
    """
    cmn.logger.debug("Event: {}".format(event))
    headers_lc = {k.lower(): v for k, v in event['headers'].items()}
    accept = headers_lc.get('accept', [])
    if "*/*" not in accept and "application/pkcs7-mime" not in accept:
        cmn.logger.warn("Unsupported accept header: {}".format(accept))
        return cmn.error400("Unsupported accept header")
    req = request.urlopen(AMAZON_IOT_CA_URL)  # nosec Bandit suppression: This URL downloads the Amazon IoT CA
    cert = req.read().decode('utf-8')
    if cert:
        return cmn.success200_cert(cert)
    else:
        cmn.logger.error("Failed to retrieve certificate ARN: {}".format(AMAZON_IOT_CA_URL))
        return cmn.error500("Failed to retrieve the certificate")
