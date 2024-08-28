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
from awsiot import mqtt_connection_builder
from awscrt.mqtt import QoS
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
import base64 as b64
import os
import datetime
import json

IOT_CORE_CA_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"


def rotate_file_name_if_exist(file_path: str, org_file_path: str = None, index: int = 0) -> int:
    if org_file_path is None:
        org_file_path = file_path

    if not os.path.exists(file_path):
        return index
    else:
        index += 1
        file_name, file_extension = os.path.splitext(file_path)
        if file_path != org_file_path:
            file_name = file_name.rsplit("-", 1)[0]
        new_file_name = "{}-{:0=3}{}".format(file_name, index, file_extension)
        _ = rotate_file_name_if_exist(new_file_name, org_file_path, index)
        os.rename(file_path, new_file_name)
    return index


def write_to_file(file_path: str, content: str):
    _ = rotate_file_name_if_exist(file_path)
    if isinstance(content, bytes):
        mode = "wb"
    else:
        mode = "w"
    with open(file_path, mode) as f:
        f.write(content)


def clear_directory(dir_path: str):
    for file in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file)
        if os.path.isfile(file_path):
            os.remove(file_path)


def verify_cert(cert: x509.base.Certificate, ca: x509.base.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(ca)
        return True
    except Exception as e:
        print("Certificate verification against CA failed")
        print(e)
        return False


class EstClient(object):
    """
    This class is a Client to an EST Server supporting the following endpoints:
    /cacerts
    /csrattrs
    /serverkeygen
    /simpleenroll
    /simplereenroll
    """

    def __init__(self, thing_name: str, est_api_domain: str, est_api_cert: str,
                 mtls_cert_pem: str, mtls_key_pem: str, save_test_data: bool = True,
                 http_timeout: [int, float] = 20, csr_key_size: int = 4096):
        """
        :param thing_name: the Thing name
        :param est_api_domain:  The EST API FQN
        :param est_api_cert: The API CA Certificate (for TLS verification)
        :param mtls_cert_pem: The mTLS client certificate in pem format
        :param mtls_key_pem: The mTLS client private key in pem format
        :param save_test_data: If True certificates, keys and CSR are saved to disk
        :param http_timeout: timeout for http response
        """
        self.thing_name = thing_name
        self.est_uri = est_api_domain
        self.est_api_cert = est_api_cert
        self.est_url = "https://{}/.well-known/est".format(est_api_domain)
        self.mtls_cert = load_pem_x509_certificate(mtls_cert_pem.encode('utf-8'))
        self.mtls_key = load_pem_private_key(mtls_key_pem.encode('utf-8'), password=None)
        self.save_test_data = save_test_data
        self.http_timeout = http_timeout
        self.csrattrs = None
        self.csr_key_size = csr_key_size

        self.cacerts = None
        self.iot_device_key = None
        self.iot_device_csr = None
        self.iot_device_cert = None

        self.files_base_path = os.path.normpath("./test_data/est_client/{}".format(
            datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")))
        os.makedirs(self.files_base_path, exist_ok=True)

        self.est_api_cert_path = os.path.join(self.files_base_path, "api_ca.pem")
        self.cacerts_path = os.path.join(self.files_base_path, "cacerts.pem")
        self.mtls_cert_path = os.path.join(self.files_base_path, "mtls_cert.crt")
        self.mtls_key_path = os.path.join(self.files_base_path, "mtls_key.key")

        self.iot_device_csr_path = os.path.join(self.files_base_path, "iot_device.csr")
        self.iot_device_key_path = os.path.join(self.files_base_path, "iot_device.key")
        self.iot_device_cert_path = os.path.join(self.files_base_path, "iot_device.crt")

        self.make_csr(key_size=self.csr_key_size)
        self.default_headers = {
            "Accept": "*/*",
            "Content-Type": "application/pkcs10",
            "Content-Transfer-Encoding": "base64",
            "Content-Disposition": "attachment",
        }
        # Store secrets in files because of Requests accepting only file path strings
        write_to_file(self.est_api_cert_path, est_api_cert)
        write_to_file(self.mtls_cert_path,mtls_cert_pem)
        write_to_file(self.mtls_key_path, mtls_key_pem)

    @property
    def iot_key_bytes(self) -> bytes:
        return self.iot_device_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption())

    @property
    def iot_csr_bytes(self) -> bytes:
        return self.iot_device_csr.public_bytes(encoding=serialization.Encoding.PEM)

    @property
    def iot_cert_bytes(self) -> bytes:
        return self.iot_device_cert.public_bytes(encoding=serialization.Encoding.PEM)

    @property
    def cacerts_bytes(self) -> bytes:
        return self.cacerts.public_bytes(encoding=serialization.Encoding.PEM)

    def get_cacerts(self, headers: dict or None = None) -> dict:
        """
        Calls /cacerts endpoing and stores the certificate
        :returns: dict with response elements status_code, headers, content
        """

        headers = headers or {"Accept": "application/pkcs7-mime"}
        r = requests.get(self.est_url + "/cacerts", headers=headers,
                         cert=(self.mtls_cert_path, self.mtls_key_path),
                         verify=self.est_api_cert_path, timeout=self.http_timeout
                         )
        r.raise_for_status()  # Raises an exception for 4xx and 5xx
        pkcs7_certs = pkcs7.load_der_pkcs7_certificates(b64.b64decode(r.content))
        self.cacerts = pkcs7_certs[0]
        cert = self.cacerts.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        if self.save_test_data:
            write_to_file(self.cacerts_path, cert)
        return {
            "crt_pem": cert,
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def get_csrattrs(self, headers: dict or None = None) -> dict:
        """
        Calls /csrattrs endpoint
        :returns: dict with response elements status_code, headers, content
        """
        r = requests.get(self.est_url + "/csrattrs",
                         headers=headers or {"Accept": "*/*"},
                         cert=(self.mtls_cert_path, self.mtls_key_path),
                         verify=self.est_api_cert_path, timeout=self.http_timeout
                         )
        r.raise_for_status()  # Raises an exception if not 200
        self.csrattrs = r.content
        return {
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def server_keygen(self, headers: dict or None = None, content: str = "") -> dict:
        """
        Calls /serverkeygen endpoing
        :returns: dict with response elements status_code, headers, content
        """

        content = base64.b64encode(content if isinstance(content, bytes) else content.encode("utf-8"))
        r = requests.post(self.est_url + "/serverkeygen",
                          headers=headers or self.default_headers,
                          data=content,
                          cert=(self.mtls_cert_path, self.mtls_key_path),
                          verify=self.est_api_cert_path,
                          timeout=self.http_timeout
                          )
        return {
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def make_csr(self, attributes: dict or None = None, key_size: int = 4096) -> None:
        """
        Creates and stores a CSR for this IoT Device. If called several times, new CSR and key is generated and stored,
        overwriting the previous one.
        :returns: nothing
        """
        self.iot_device_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
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

        # Store
        if self.save_test_data is True:
            print("Saving CSR data in {}".format(self.files_base_path))
            write_to_file(self.iot_device_csr_path, self.iot_device_csr.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'))
            write_to_file(self.iot_device_key_path, self.iot_device_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("utf-8"))

    def _enrollment_call(self, headers: dict or None, content: bytes, api_endpoint: str) -> requests.models.Response:
        if not content:
            content = base64.b64encode(self.iot_device_csr.public_bytes(encoding=serialization.Encoding.DER))
        r = requests.post(self.est_url + api_endpoint,
                          headers=headers or self.default_headers,
                          data=content,
                          cert=(self.mtls_cert_path, self.mtls_key_path),
                          verify=self.est_api_cert_path,
                          timeout=self.http_timeout
                          )
        return r

    def simpleenroll(self, headers: dict or None = None, content: bytes = b"") -> dict:
        """
        Calls /simpleenroll endpoing
        :returns: dict with response elements crt, status_code, headers, content
        """
        r = self._enrollment_call(headers, content, "/simpleenroll")
        if r.status_code == 200:
            pkcs7_certs = pkcs7.load_der_pkcs7_certificates(b64.b64decode(r.content))
            self.iot_device_cert = pkcs7_certs[0]
            crt_pem = self.iot_device_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
            if verify_cert(self.iot_device_cert, self.cacerts) is not True:
                raise Exception("Device Certificate verification against PKI CA failed")
        else:
            crt_pem = r.text
        if self.save_test_data:
            write_to_file(self.iot_device_cert_path, crt_pem)
        return {
            "crt_pem": crt_pem,
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def simplereenroll(self, headers: dict or None = None, content: bytes = b"") -> dict:
        """
        Calls /simplereenroll endpoing
        :returns: dict with response elements crt, status_code, headers, content
        """
        # Create a new CSR before calling the signing endpoint. It also creates a new key as if it was rolled on the device
        self.make_csr(key_size=self.csr_key_size)
        r = self._enrollment_call(headers, content, "/simplereenroll")
        if r.status_code == 200:
            pkcs7_certs = pkcs7.load_der_pkcs7_certificates(b64.b64decode(r.content))
            new_cert = pkcs7_certs[0]
            if verify_cert(new_cert, self.cacerts) is not True:
                raise Exception("Device Certificate verification against PKI CA failed")
            self.iot_device_cert = new_cert
            crt_pem = self.iot_device_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
            if self.save_test_data:
                write_to_file(self.iot_device_cert_path, crt_pem)
        else:
            crt_pem = r.text
        return {
            "crt_pem": crt_pem,
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def self_initialise(self) -> bool:
        """
        Performs the tasks necessary to collect all the data for an IoT Device
        :return: nothing
        """
        resp = self.get_cacerts()
        if not resp['status_code'] == 200:
            print("Failed to boostrap from /cacerts")
            print("Response is: {}".format(json.dumps(resp)))
            return False
        resp = self.simpleenroll()
        if not resp['status_code'] == 200:
            print("Failed to boostrap from /simpleenroll")
            print("Response is: {}".format(json.dumps(resp)))
            return False
        return True


class IotClient(object):
    """
    Implementation of an IoT Client
    """

    def __init__(self, thing_name: str, endpoint: str, port: int or None, est_client_kwargs: dict, save_test_data: bool,
                 http_timeout: [int, float] = 20):
        self.thing_name = thing_name
        self.endpoint = endpoint
        self.port = port
        self.root_ca = None
        self.certificate = None
        self.private_key = None
        self.certificate_prev = None
        self.private_key_prev = None
        self.connected = False
        self.est_client = None
        self.mqtt_connection = None
        self.messages = {}
        self.save_test_data = save_test_data
        self.http_timeout = http_timeout
        self.files_base_path = os.path.normpath("./test_data/iot_client/{}".format(
            datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")))
        self.iot_core_ca_path = os.path.join(self.files_base_path, "iot_core_root_ca.pem")
        self.iot_device_cert_path = os.path.join(self.files_base_path, "iot_device.crt")
        self.iot_device_key_path = os.path.join(self.files_base_path, "iot_device.key")
        self.iot_device_csr_path = os.path.join(self.files_base_path, "iot_device.csr")
        os.makedirs(self.files_base_path, exist_ok=True)
        self.est_kwargs = est_client_kwargs

    @property
    def is_connected(self) -> bool:
        return self.connected

    @property
    def mqtt_messages(self) -> dict:
        return self.messages

    def set_iot_creds(self, ca_certificate: str, device_certificate: str, device_private_key: str):
        """
        Force setting the credentials for connecting to IoT Core.
        :param ca_certificate: PEM format
        :param device_certificate: PEM format
        :param device_private_key: PEM format
        :return:
        """
        self.root_ca = ca_certificate
        self.certificate = device_certificate
        self.private_key = device_private_key

    def on_connection_interrupted(self, connection, error, **kwargs):
        print("Connection interrupted")
        self.connected = False

    def on_connection_resumed(self, connection, return_code, session_present, **kwargs):
        print("Connection resumed")
        self.connected = True

    def on_connection_success(self, connection, callback_data):
        print("Connection success")
        self.connected = True

    def on_connection_failure(self, connection, callback_data):
        print("Connection failure")
        self.connected = False

    def on_connection_closed(self, connection, callback_data):
        print("Connection closed")
        self.connected = False

    def est_bootstrap(self) -> bool:
        self.est_client = EstClient(**self.est_kwargs)
        if self.est_client.self_initialise() is True:
            self.certificate = self.est_client.iot_cert_bytes
            self.private_key = self.est_client.iot_key_bytes
            if self.save_test_data is True:
                write_to_file(self.iot_device_cert_path, self.certificate.decode('utf-8'))
                write_to_file(self.iot_device_key_path, self.private_key.decode('utf-8'))
            return True
        else:
            return False

    def get_root_ca(self) -> bool:
        """
        Collect the CA required to connect to AWS Iot Core: It is always the 'Amazon Root CA 1'
        :return:
        """
        try:
            r = requests.get(IOT_CORE_CA_URL, timeout=self.http_timeout)
            self.root_ca = r.content
            if self.save_test_data is True:
                write_to_file(self.iot_core_ca_path, self.root_ca.decode('utf-8'))
            return True
        except Exception as e:
            print("Got exception when fetching AWS IoT Root CA from URL {}: {}".format(IOT_CORE_CA_URL, e))
            return False

    def init_connection(self, skip_est=False) -> None:
        """
        Connects to AWS IoT Core
        :return: nothing
        """
        if not self.est_client or skip_est is False:
            if self.est_bootstrap() is False:
                raise Exception("Failed to bootstrap EST Client")
        if not self.root_ca:
            if self.get_root_ca() is not True:
                raise Exception("Failed to fetch AWS IoT Root CA")

        if self.connected:
            self.disconnect()

        self.mqtt_connection = mqtt_connection_builder.mtls_from_bytes(
            client_id=self.thing_name,
            endpoint=self.endpoint,
            cert_bytes=self.certificate,
            pri_key_bytes=self.private_key,
            on_connection_interrupted=self.on_connection_interrupted,
            on_connection_resumed=self.on_connection_resumed,
            on_connection_success=self.on_connection_success,
            on_connection_failure=self.on_connection_failure,
            on_connection_closed=self.on_connection_closed,
            clean_session=True,
            port=self.port,
            ca_bytes=self.root_ca
        )
        # Sets the callback for all messages
        self.mqtt_connection.on_message(self.new_message)

    def connect(self) -> None:
        """
        Connects to AWS IoT Core
        :return: nothing
        """
        if self.connected:
            print("Already connected")
            return
        if not self.mqtt_connection:
            self.init_connection()
        print("Connecting...")
        connect_future = self.mqtt_connection.connect()
        connect_future.result()  # Raises an exception if connection fails

    def disconnect(self) -> None:
        """
        Disconnects from AWS IoT Core
        :return: nothing
        """
        print("Disconnecting current connection")
        if self.mqtt_connection:  # Just a safeguard
            self.mqtt_connection.disconnect()
        self.connected = False

    def new_message(self, topic: str, payload: bytes, dup: bool, qos: QoS, retain: bool, **kwargs) -> None:
        print("Received message from topic '{}': {}".format(topic, payload))
        if topic not in self.messages:
            self.messages[topic] = {}
        self.messages[topic][datetime.datetime.now().isoformat()] = {
            "payload": payload.decode('utf-8'),
            "dup": dup,
            "qos": qos,
            "retain": retain,
            "kwargs": kwargs
        }

    def subscribe(self, topic: str, qos: QoS = QoS.AT_LEAST_ONCE) -> bool:
        if not self.connected:
            # subscribe will hang until the connection resumes
            print("Not connected, cannot subscribe")
            return False
        future, _ = self.mqtt_connection.subscribe(topic=topic, qos=qos)
        result = future.result()
        print("Subscribed: {}".format(result))
        return True

    def publish(self, topic: str, payload: str, qos=QoS.AT_LEAST_ONCE, retain=False) -> bool:
        """
        """
        if not self.connected:
            print("Not connected, cannot publish")
            return False
        future, _ = self.mqtt_connection.publish(
            topic=topic,
            payload=payload,
            qos=qos,
            retain=retain
        )
        result = future.result()
        print("Published: {}".format(result))
        return True

    def renew_certificate(self) -> dict:
        certificate_prev = self.certificate
        private_key_prev = self.private_key
        r = self.est_client.simplereenroll()
        if r['status_code'] == 200:
            self.certificate_prev = certificate_prev
            self.private_key_prev = private_key_prev
            self.certificate = self.est_client.iot_cert_bytes
            self.private_key = self.est_client.iot_key_bytes
            if self.save_test_data is True:
                write_to_file(self.iot_device_cert_path, self.certificate.decode('utf-8'))
                write_to_file(self.iot_device_key_path, self.private_key.decode('utf-8'))
            print("Device Cert and Key updated")
        else:
            print("Failed to renew certificate")
            print("Response is: {}".format(r))
        return r
