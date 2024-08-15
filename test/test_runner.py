import unittest
import boto3
from test_clients import EstClient, IotClient
import yaml
from uuid import uuid4
import json
import requests
import time

TEST_CFG_FILE = "test_config.yaml"


class Init(object):
    def __init__(self, **kwargs):
        with open(TEST_CFG_FILE, "r") as f:
            self.test_config = yaml.safe_load(f)
        with open(self.test_config['cdk_config_file'], "r") as f:
            self.cdk_config = yaml.safe_load(f)
        self.api_domain = self.cdk_config['Properties']['apiCustomDomainName']
        print("Fetching the API Certificate")
        acm_client = boto3.client('acm')
        cert = acm_client.get_certificate(
            CertificateArn=self.cdk_config['Properties']['apiCertificateArn'])
        self.api_cert = cert['Certificate']
        self.mtls_cert_pem = self.test_config['mtls_cert_pem']
        self.mtls_key_pem = self.test_config['mtls_key_pem']
        if not self.test_config['mtls_cert_pem'] or not self.test_config['mtls_key_pem']:
            print("mTLS credentials not provided, attempting to read from AWS Cloud ASM")
            self.asm_client = boto3.client('secretsmanager')
            secrets = self.asm_client.get_secret_value(
                SecretId=self.cdk_config['Properties']['estMtlsClientSecretsName'])
            if not secrets:
                raise Exception("No mTLS secrets found in AWS Cloud ASM")
            self.mtls_secrets = json.loads(secrets['SecretString'])
            self.mtls_cert_pem = self.mtls_secrets['certificate']
            self.mtls_key_pem = self.mtls_secrets['key']


class Test01EstServer(object): #unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Setup the test environment ONCE (setUp method runs before each test)
        :return: None
        """
        cls.setup_done = False
        cls.init = Init()
        cls.api_domain = cls.init.api_domain
        cls.thing_name = "estThing-{}".format(uuid4())
        cls.est_client = EstClient(
            thing_name=cls.thing_name,
            est_api_domain=cls.init.api_domain,
            est_api_cert=cls.init.api_cert,
            mtls_cert_pem=cls.init.mtls_cert_pem,
            mtls_key_pem=cls.init.mtls_key_pem
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
        self.assertEqual(b"", r['content'], "No content expected")

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


class Test02IotClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Setup the test environment ONCE (setUp method runs before each test)
        :return: None
        """
        cls.setup_done = False
        cls.init = Init()
        cls.api_domain = cls.init.api_domain
        # Fix Me:
        cls.thing_name = "thing05" # "estThing-{}".format(uuid4())
        cls.est_api_domain = cls.init.api_domain,
        cls.est_api_cert = cls.init.api_cert,
        cls.mtls_cert_pem = cls.init.mtls_cert_pem,
        cls.mtls_key_pem = cls.init.mtls_key_pem
        cls.setup_done = True

        cls.b3client = boto3.client('iot')
        cls.endpoint = cls.b3client.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']
        print("IoT Endpoint: {}".format(cls.endpoint))
        cls.est_client_kwargs = dict(
            thing_name=cls.thing_name,
            est_api_domain=cls.init.api_domain,
            est_api_cert=cls.init.api_cert,
            mtls_cert_pem=cls.init.mtls_cert_pem,
            mtls_key_pem=cls.init.mtls_key_pem
        )

        cls.iot_client = IotClient(
            thing_name=cls.thing_name,
            endpoint=cls.endpoint,
            port=None,
            est_client_kwargs=cls.est_client_kwargs
        )

    @classmethod
    def tearDownClass(cls):
        cls.iot_client.disconnect()

    def test_01(self):
        try:
            r = self.iot_client.connect()
        except Exception as e:
            print("Got exception on first connection attempt: {}".format(e))
            print("Waiting a bit before checking result...")
            time.sleep(10)
        r = self.iot_client.connect()
        self.assertTrue(self.iot_client.is_connected, "Connection to AWS IoT Core should be successful")


if __name__ == "__main__":
    unittest.main()
    """
    st = unittest.TestSuite()
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    # suite.addTests(loader.loadTestsFromTestCase(Test01EstServer))
    suite.addTests(loader.loadTestsFromTestCase(Test02IotClient))
    runner = unittest.TextTestRunner()
    runner.run(suite)
    """
