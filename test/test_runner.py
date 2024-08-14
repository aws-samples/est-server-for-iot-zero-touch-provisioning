import unittest
import boto3
from test_clients import EstClient
import yaml
from uuid import uuid4
import json
import requests

TEST_CFG_FILE = "test_config.yaml"


class Test01EstServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Setup the test environment ONCE (setUp method runs before each test)
        :return: None
        """
        cls.setup_done = False
        with open(TEST_CFG_FILE, "r") as f:
            cls.test_config = yaml.safe_load(f)
        with open(cls.test_config['cdk_config_file'], "r") as f:
            cls.cdk_config = yaml.safe_load(f)
        cls.api_domain = cls.cdk_config['Properties']['apiCustomDomainName']
        print("Fetching the API Certificate")
        acm_client = boto3.client('acm')
        cert = acm_client.get_certificate(
            CertificateArn=cls.cdk_config['Properties']['apiCertificateArn'])
        cls.api_cert = cert['Certificate']
        cls.mtls_cert_pem = cls.test_config['mtls_cert_pem']
        cls.mtls_key_pem = cls.test_config['mtls_key_pem']
        if not cls.test_config['mtls_cert_pem'] or not cls.test_config['mtls_key_pem']:
            print("mTLS credentials not provided, attempting to read from AWS Cloud ASM")
            cls.asm_client = boto3.client('secretsmanager')
            secrets = cls.asm_client.get_secret_value(
                SecretId=cls.cdk_config['Properties']['estMtlsClientSecretsName'])
            if not secrets:
                raise Exception("No mTLS secrets found in AWS Cloud ASM")
            cls.mtls_secrets = json.loads(secrets['SecretString'])
            cls.mtls_cert_pem = cls.mtls_secrets['certificate']
            cls.mtls_key_pem = cls.mtls_secrets['key']

        cls.thing_name = "estThing-{}".format(uuid4())
        cls.est_client = EstClient(
            thing_name=cls.thing_name,
            est_api_domain=cls.api_domain,
            est_api_cert=cls.api_cert,
            mtls_cert_pem=cls.mtls_cert_pem,
            mtls_key_pem=cls.mtls_key_pem
        )
        cls.setup_done = True

    def test_01(self):
        """
        Call the API without client certificate, expect Connection error
        :return: None
        """
        with self.assertRaises(requests.exceptions.ConnectionError) as cm:
            r = requests.get(url="https://{}/.well-known/est/cacerts".format(self.api_domain),
                             headers={"Accept": "application/pkcs7-mime"})
        self.assertIsInstance(cm.exception, requests.exceptions.ConnectionError)
        self.assertEqual("Connection reset by peer", cm.exception.args[0].args[1].args[1])

    def test_02(self):
        """
        Validate that IoT CA is correctly fetched
        :return:
        """
        r = self.est_client.get_iot_ca_cert()
        self.assertEqual(r["status_code"], 200, "Status code 200 expected from /cacerts")
        self.assertIn("-----BEGIN CERTIFICATE-----", r['crt_pem'], "PEM format expected")
        self.assertEqual("application/pkcs7-mime", r['headers']['content-type'],
                         "PKCS7 MIME content-type header expected")

    def test_03(self):
        """
        Validate that csrattrs returns no content
        :return:
        """
        r = self.est_client.get_csr_attrs()
        self.assertEqual(204, r["status_code"], "Status code 204 expected from /csrattrs")
        self.assertEqual("application/json", r['headers']['content-type'],
                         "application/json content-type header expected")
        self.assertEqual(b"", r['content'],  "No content expected")

    def test_04(self):
        """
        Validate that server_keygen is not implemented
        :return: 
        """
        r = self.est_client.server_keygen()
        self.assertEqual(501, r["status_code"], "Status code 501 expected from /server_keygen")

    def test_05(self):
        """
        Validate that simpleenroll returns a signed certificate
        :return:
        """
        r = self.est_client.simpleenroll()
        self.assertEqual(200, r["status_code"], "Status code 200 expected from /simpleenroll")
        self.assertEqual("application/pkcs7-mime", r['headers']['content-type'],
                         "application/pkcs7-mime content-type header expected")
        self.assertIn("-----BEGIN CERTIFICATE-----", r['crt_pem'], "PEM format expected")

    def test_06(self):
        """
        Validate that simplereenroll returns a signed certificate
        :return:
        """
        r = self.est_client.simplereenroll()
        self.assertEqual(200, r["status_code"], "Status code 200 expected from /simplereenroll")
        self.assertEqual("application/pkcs7-mime", r['headers']['content-type'],
                         "application/pkcs7-mime content-type header expected")
        self.assertIn("-----BEGIN CERTIFICATE-----", r['crt_pem'], "PEM format expected")


if __name__ == "__main__":
    unittest.main()
