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
import requests
import awsiot
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import base64 as b64
import os


class EstClient(object):
    """
    This class is a Client to an EST Server supporting the following endpoints:
    /cacerts
    /csrattrs
    /serverkeygen
    /simpleenroll
    /simplereenroll
    """

    def __init__(self, thing_name, est_api_domain, est_api_cert, mtls_cert_pem, mtls_key_pem):
        """
        Sets variables and creates a CSR for IoT device.
        :param est_api_domain:
        :param mtls_cert_pem:
        :param mtls_key_pem:
        """
        self.thing_name = thing_name
        self.est_uri = est_api_domain
        self.est_api_cert = est_api_cert
        self.est_url = "https://{}/.well-known/est".format(est_api_domain)
        self.mtls_cert = load_pem_x509_certificate(mtls_cert_pem.encode('utf-8'))
        self.mtls_key = load_pem_private_key(mtls_key_pem.encode('utf-8'), password=None)
        self.iot_ca_cert = None
        self.csrattrs = None
        self.iot_device_key = None
        self.iot_device_csr = None
        self.iot_device_cert_init = None
        self.iot_device_cert_renewed = None
        self.make_csr()
        self.default_headers = {
            "Accept": "*/*",
            "Content-Type": "application/pkcs10",
            "Content-Transfer-Encoding": "base64",
            "Content-Disposition": "attachment",
        }
        # Store secrets in files because of Requests accepting only file strings
        self.files_base_path = "./temp"
        os.makedirs(self.files_base_path, exist_ok=True)
        self.est_api_cert_path = self.files_base_path + "/api_ca_cert.pem"
        self.mtls_cert_path = self.files_base_path + "/mtls_cert.crt"
        self.mtls_key_path = self.files_base_path + "/mtls_key.key"
        with open(self.est_api_cert_path, 'w') as f:
            f.write(est_api_cert)
        with open(self.mtls_cert_path, 'w') as f:
            f.write(mtls_cert_pem)
        with open(self.mtls_key_path, 'w') as f:
            f.write(mtls_key_pem)
        self.iot_ca_cert_path = self.files_base_path + "/iot_ca_cert.crt"

    def get_iot_ca_cert(self, headers=None):
        """
        Calls /cacerts endpoing and stores the certificate
        :returns: dict with response elements status_code, headers, content
        """
        if not headers:
            headers = {"Accept": "application/pkcs7-mime"}
        r = requests.get(self.est_url + "/cacerts", headers=headers,
                         cert=(self.mtls_cert_path, self.mtls_key_path),
                         verify=self.est_api_cert_path
                         )
        r.raise_for_status()  # Raises an exception for 4xx and 5xx
        cert = b64.b64decode(r.content)
        with open(self.iot_ca_cert_path, "w") as f:
            f.write(cert.decode('utf-8'))
        self.iot_ca_cert = load_pem_x509_certificate(b64.b64decode(r.content))
        return {
            "crt_pem": self.iot_ca_cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8"),
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def get_csr_attrs(self, headers=None):
        """
        Calls /csrattrs endpoint
        :returns: dict with response elements status_code, headers, content
        """
        headers = headers or {"Accept": "*/*"}
        r = requests.get(self.est_url + "/csrattrs", headers=headers,
                         cert=(self.mtls_cert_path, self.mtls_key_path),
                         verify=self.est_api_cert_path
                         )
        r.raise_for_status()  # Raises an exception if not 200
        self.csrattrs = r.content
        return {
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def server_keygen(self, headers=None, content=""):
        """
        Calls /serverkeygen endpoing
        :returns: dict with response elements status_code, headers, content
        """

        content = base64.b64encode(content if isinstance(content, bytes) else content.encode("utf-8"))
        r = requests.post(self.est_url + "/serverkeygen",
                          headers=headers or self.default_headers,
                          data=content,
                          cert=(self.mtls_cert_path, self.mtls_key_path),
                          verify=self.est_api_cert_path
                          )
        return {
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def make_csr(self, attributes=None):
        """
        Creates and stores a CSR for this IoT Device. If called several times, new CSR and key is generated and stored,
        overwriting the previous one.
        :returns: nothing
        """
        self.iot_device_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        if not attributes:
            attributes = {
                "CN": self.thing_name,
                "C": "US",
                "ST": "Washington",
                "L": "Seattle",
                "O": "Amazon Web Services",
                "OU": "Solutions Architecture",
                "SN": "123456789AB"
            }

        self.iot_device_csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, attributes.get("CN", "")),
                x509.NameAttribute(NameOID.COUNTRY_NAME, attributes.get("C", "")),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, attributes.get("ST", "")),
                x509.NameAttribute(NameOID.LOCALITY_NAME, attributes.get("L", "")),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, attributes.get("O", "")),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, attributes.get("OU", "")),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, attributes.get("SN", "")),
            ])).add_extension(
            # Describe what FQDN we want this certificate for.
            x509.SubjectAlternativeName([x509.DNSName(self.est_uri)]),
            critical=False,
        ).sign(self.iot_device_key, hashes.SHA256())

    def _enrollment_call(self, headers, content):
        if not content:
            content = base64.b64encode(self.iot_device_csr.public_bytes(encoding=serialization.Encoding.PEM))
        r = requests.post(self.est_url + "/simpleenroll",
                          headers=headers or self.default_headers,
                          data=content,
                          cert=(self.mtls_cert_path, self.mtls_key_path),
                          verify=self.est_api_cert_path
                          )
        return r

    def simpleenroll(self, headers=None, content=""):
        """
        Calls /simpleenroll endpoing
        :returns: dict with response elements crt, status_code, headers, content
        """
        r = self._enrollment_call(headers, content)
        if r.status_code == 200:
            crt_pem = b64.b64decode(r.content).decode('utf-8')
            self.iot_device_cert_init = load_pem_x509_certificate(b64.b64decode(r.content))
        else:
            crt_pem = r.text
        return {
            "crt_pem": crt_pem,
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def simplereenroll(self, headers=None, content=""):
        """
        Calls /simplereenroll endpoing
        :returns: dict with response elements crt, status_code, headers, content
        """
        r = self._enrollment_call(headers, content)
        if r.status_code == 200:
            crt_pem = b64.b64decode(r.content).decode('utf-8')
            self.iot_device_cert_renewed = load_pem_x509_certificate(b64.b64decode(r.content))
        else:
            crt_pem = r.text
        return {
            "crt_pem": crt_pem,
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

