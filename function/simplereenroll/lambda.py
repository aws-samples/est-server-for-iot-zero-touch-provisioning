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

import base64
import boto3

import est_common as cmn

iot_client = boto3.client('iot')


def pre_reenroll(event):
    """
    This is the first function that is called when enrollment happens before the certificate is generated
    :param event:
    :return: True or False
    """
    return True


def enroll(csr ,csr_data):
    """
    This is the function that generates the signed certificate
    :param csr:
    :param csr_data:
    :return:
    """
    return cmn.sign_csr_aws(iot_client, csr)


def post_reenroll(event):
    """
    This is the last function that is called when enrollment happens after the certificate is generated
    :param event:
    :return: True or False
    """
    return True


def lambda_handler(event, context):
    """
    Return a new signed CSR after executing pre-reenroll and post-reenroll custom actions
    """
    cmn.logger.debug("Event: ".format(event))
    try:
        if cmn.validate_enroll_request(event) is not True:
            return cmn.error400("request validation failed")
        csr = cmn.extract_csr(event)
        if not csr:
            return cmn.error400("CSR extraction failed")
        csr_data = cmn.validate_csr(csr)
        if not csr_data:
            return cmn.error400("CSR validation failed")
        if pre_reenroll(event) is not True:
            return cmn.error400("Pre-enrollment failed")
        sign_response = enroll(csr, csr_data)
        if not sign_response:
            return cmn.error400("Certificate signing failed")
        cert = sign_response['certificatePem']
        cmn.logger.warning("New reenrollment certificate signed for {}\n\twith ID: {}\n\tand ARN: {}".format(
            csr_data, sign_response['certificateId'], sign_response['certificateArn']))
        if post_reenroll(event) is not True:
            return cmn.error_400("Post-enrollment failed")
        return cmn.success200_cert(cert)
    except Exception as e:
        cmn.logger.error(f"Error: {e}")
        return cmn.error500("Internal server error")
