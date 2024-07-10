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

import urllib.request
import est_common as cmn


def lambda_handler(event, context):
    """
    Returns the current CA certificate from AWS IoT
    :param event: 
    :param context: 
    :return: 
    """
    cmn.logger.debug("Event: ".format(event))
    accept = event['headers'].get('Accept', [])
    if "*/*" not in accept and "application/pkcs7-mime" not in accept:
        return cmn.error400("Unsupported Accept header")
    q_params = event['queryStringParameters']
    ctype = q_params['certificate-type'] if (q_params is not None and 'certificate-type'
                                             in event['queryStringParameters']) else "RSA"
    if ctype == 'RSA':
        cert_url = cmn.RSA_CA_CERT_URL
    elif ctype == 'ECC':
        cert_url = cmn.ECC_CA_CERT_URL
    else:
        return cmn.error400(f"Unsupported certificate type: {ctype}")
    try:
        with urllib.request.urlopen(cert_url) as response:
            cert = response.read().decode('utf-8')
        return cmn.success200_cert(cert)
    except Exception as e:
        msg = f"Failed to retrieve certificate: {e}"
        return cmn.error500(msg)
