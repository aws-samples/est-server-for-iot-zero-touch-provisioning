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
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
import base64 as b64
import os
import datetime

IOT_CORE_CA_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"


def verify_cert(cert: x509.base.Certificate, pki_ca: x509.base.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(pki_ca)
        return True
    except Exception as e:
        print("Certificate verification against PKI CA failed")
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

    def __init__(self, thing_name: str, est_api_domain: str, est_api_cert: str, mtls_cert_pem: str, mtls_key_pem: str):
        """

        :param thing_name: the Thing name
        :param est_api_domain:  The EST API FQN
        :param est_api_cert: The API CA Certificate (for TLS verification)
        :param mtls_cert_pem: The mTLS client certificate in pem format
        :param mtls_key_pem: The mTLS client private key in pem format
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
        self.iot_device_cert = None
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
        self.iot_ca_cert_path = self.files_base_path + "/iot_pki_ca_cert.pem"

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
    def iot_ca_cert_bytes(self) -> bytes:
        return self.iot_ca_cert.public_bytes(encoding=serialization.Encoding.PEM)

    def get_iot_ca_cert(self, headers: dict or None = None) -> dict:
        """
        Calls /cacerts endpoing and stores the certificate
        :returns: dict with response elements status_code, headers, content
        """

        headers = headers or {"Accept": "application/pkcs7-mime"}
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

    def get_csr_attrs(self, headers: dict or None = None) -> dict:
        """
        Calls /csrattrs endpoint
        :returns: dict with response elements status_code, headers, content
        """
        r = requests.get(self.est_url + "/csrattrs",
                         headers=headers or {"Accept": "*/*"},
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
                          verify=self.est_api_cert_path
                          )
        return {
            "status_code": r.status_code,
            "headers": r.headers,
            "content": r.content
        }

    def make_csr(self, attributes: dict or None = None) -> None:
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

    def _enrollment_call(self, headers: dict or None, content: bytes, api_endpoint: str) -> requests.models.Response:
        if not content:
            content = base64.b64encode(self.iot_device_csr.public_bytes(encoding=serialization.Encoding.PEM))
        r = requests.post(self.est_url + api_endpoint,
                          headers=headers or self.default_headers,
                          data=content,
                          cert=(self.mtls_cert_path, self.mtls_key_path),
                          verify=self.est_api_cert_path
                          )
        return r

    def simpleenroll(self, headers: dict or None = None, content: bytes = b"") -> dict:
        """
        Calls /simpleenroll endpoing
        :returns: dict with response elements crt, status_code, headers, content
        """
        r = self._enrollment_call(headers, content, "/simpleenroll")
        if r.status_code == 200:
            crt_pem = b64.b64decode(r.content).decode('utf-8')
            self.iot_device_cert = load_pem_x509_certificate(b64.b64decode(r.content))
            if verify_cert(self.iot_device_cert, self.iot_ca_cert) is not True:
                raise Exception("Device Certificate verification against PKI CA failed")
        else:
            crt_pem = r.text
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
        # Create a new CSR before calling the signing endpoint. It also creates a new key as it was rolled on the device
        self.make_csr()
        r = self._enrollment_call(headers, content, "/simplereenroll")
        if r.status_code == 200:
            crt_pem = b64.b64decode(r.content).decode('utf-8')
            self.iot_device_cert = load_pem_x509_certificate(b64.b64decode(r.content))
            if verify_cert(self.iot_device_cert, self.iot_ca_cert) is not True:
                raise Exception("Device Certificate verification against PKI CA failed")
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
        resp = self.get_iot_ca_cert()
        if not resp['status_code'] == 200:
            print("Failed to boostrap from /cacerts")
            return False
        resp = self.simpleenroll()
        if not resp['status_code'] == 200:
            print("Failed to boostrap from /simpleenroll")
            return False
        return True


class IotClient(object):
    """
    Implementation of an IoT Client
    """

    def __init__(self, thing_name: str, endpoint: str, port: int or None, est_client_kwargs: dict, save_creds: bool):
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
        self.est_kwargs = est_client_kwargs
        self.mqtt_connection = None
        self.messages = {}
        self.save_creds = save_creds

    @property
    def is_connected(self) -> bool:
        return self.connected

    @property
    def mqtt_messages(self) -> dict:
        return self.messages

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

    def est_bootstrap(self, save: bool = False) -> bool:
        self.est_client = EstClient(**self.est_kwargs)
        if self.est_client.self_initialise() is True:
            self.certificate = self.est_client.iot_cert_bytes
            self.private_key = self.est_client.iot_key_bytes
            if save:
                save_to_disk("temp/iot_device.crt", self.certificate.decode('utf-8'))
                save_to_disk("./temp/iot_device.key", self.private_key.decode('utf-8'))
            return True
        else:
            return False

    def get_root_ca(self, save: bool = False) -> bool:
        try:
            r = requests.get(IOT_CORE_CA_URL)
            self.root_ca = r.content
            if save is True:
                save_to_disk("./temp/iot_core_root_ca.pem", self.root_ca.decode('utf-8'))
            return True
        except Exception as e:
            print("Got exception when fetching AWS IoT Root CA from URL {}: {}".format(IOT_CORE_CA_URL, e))
            return False

    def init_connection(self) -> None:
        """
        Connects to AWS IoT Core
        :return: nothing
        """
        if not self.est_client:
            if self.est_bootstrap() is not True:
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

    def renew_certificate(self, save: bool = False) -> dict:
        r = self.est_client.simplereenroll()
        if r['status_code'] == 200:
            self.certificate_prev = self.certificate
            self.private_key_prev = self.private_key
            self.certificate = self.est_client.iot_cert_bytes
            self.private_key = self.est_client.iot_key_bytes
            if save:
                save_to_disk("temp/iot_device_prev.crt", self.certificate_prev.decode('utf-8'))
                save_to_disk("./temp/iot_device_prev.key", self.private_key_prev.decode('utf-8'))
                save_to_disk("temp/iot_device.crt", self.certificate.decode('utf-8'))
                save_to_disk("./temp/iot_device.key", self.private_key.decode('utf-8'))
            print("Device Cert and Key updated")
        return r


def save_to_disk(filename: str, data: str):
    with open(filename, "w") as f:
        f.write(data)
