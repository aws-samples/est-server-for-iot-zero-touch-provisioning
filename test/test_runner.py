import unittest
import boto3
import botocore.exceptions
from awscrt import exceptions
from test_clients import EstClient, IotClient
import yaml
from uuid import uuid4
import json
import requests
import time

TEST_CFG_FILE = "test_config.yaml"


class Init(object):
    def __init__(self, **kwargs):
        print("Initialising the Test environment")
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
        self.topic = self.test_config['mqtt_topic']
        self.save_creds = self.test_config['save_iot_creds_to_disk']
        self.endpoint = self.test_config['iot_endpoint']
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
        else:
            self.mtls_cert_pem = open(self.test_config['mtls_cert_pem'], "r").read()
            self.mtls_key_pem = open(self.test_config['mtls_key_pem'], "r").read()


class Test01EstServer(unittest.TestCase):

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
                             headers={"Accept": "application/pkcs7-mime"}, timeout=20)
        self.assertIsInstance(cm.exception, requests.exceptions.ConnectionError)
        self.assertEqual("Connection reset by peer", cm.exception.args[0].args[1].args[1])

    def test_02(self):
        """
        Validate that IoT CA is correctly fetched
        :return:
        """
        r = self.est_client.get_iot_ca_cert()
        self.assertEqual(200, r["status_code"], "Status code 200 expected from /cacerts")
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
        cls.thing_name = "estThing-{}".format(uuid4())
        cls.topic = cls.init.topic.replace("<thing_name>", cls.thing_name)
        print("IoT Thing name under test: {}".format(cls.thing_name))
        cls.est_api_domain = cls.init.api_domain,
        cls.est_api_cert = cls.init.api_cert,
        cls.mtls_cert_pem = cls.init.mtls_cert_pem,
        cls.mtls_key_pem = cls.init.mtls_key_pem
        cls.save_creds = cls.init.save_creds
        cls.b3client = boto3.client('iot')
        if cls.init.endpoint:
            cls.endpoint = cls.init.endpoint
        else:
            cls.endpoint = cls.b3client.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']
        print("Using IoT Endpoint: {}".format(cls.endpoint))
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
            est_client_kwargs=cls.est_client_kwargs,
            save_creds=cls.save_creds
        )
        cls.setup_done = True

    @classmethod
    def tearDownClass(cls):
        cls.iot_client.disconnect()
        delete_thing(cls.thing_name)

    def assert_publish(self, topic: str, message: str):
        print("Publishing to topic: {}".format(self.topic))
        r = self.iot_client.publish(topic, message)
        self.assertTrue(r, "Publishing to topic should be successful")
        time.sleep(2)
        print(self.iot_client.mqtt_messages)
        self.assertIn(topic, self.iot_client.mqtt_messages, "Message should be received on topic")
        received = self.iot_client.mqtt_messages[topic]
        keys = sorted(list(received.keys()), reverse=True)
        self.assertEqual(message, received[keys[0]]['payload'], "Message content should match")

    def assert_subscribe(self, topic: str):
        print("Subscribing to topic: {}".format(topic))
        r = self.iot_client.subscribe(topic)
        self.assertTrue(r, "Subscription to topic should be successful")

    def test_01(self):
        """
        Test connection to IoT Core and JITP
        """
        self.assertRaises(exceptions.AwsCrtError, self.iot_client.connect)
        print("Got exception on first connection attempt.")
        print("Waiting a bit before second attempt...")
        time.sleep(4)
        self.iot_client.connect()
        time.sleep(2)
        self.assertTrue(self.iot_client.is_connected, "Connection to AWS IoT Core should be successful")

    def test_02(self):
        """
        Test subscription to right topic
        """
        self.assert_subscribe(self.topic)

    def test_03(self):
        """
        Assert publication
        """
        self.assert_publish(self.topic, "Hello from test case 03")

    def test_04(self):
        """
        Connection with new certificate and key
        """
        old_cert = self.iot_client.certificate
        old_key = self.iot_client.private_key
        r = self.iot_client.renew_certificate(save=self.save_creds)
        self.assertEqual(200, r.get('status_code'), "Certificate renewal should be successful")
        self.assertTrue(self.iot_client.disconnect, "Disconnection from IoT Core should be successful")
        new_cert = self.iot_client.certificate
        new_key = self.iot_client.private_key
        self.assertNotEqual(old_cert, new_cert, "Certificate should be different")
        self.assertNotEqual(old_key, new_key, "Key should be different")
        self.iot_client.init_connection()
        self.iot_client.connect()
        time.sleep(2)
        self.assertTrue(self.iot_client.is_connected, "Connection to AWS IoT Core should be successful")

    def test_05(self):
        """
        Assert subscription after certificate renewal
        """
        self.assert_subscribe(self.topic)

    def test_06(self):
        """
        Assert publication after certificate renewal
        """
        self.assert_publish(self.topic, "Hello from test case 06")


def delete_thing(thing_name: str):
    """
    Delete an IoT Thing and its certificates
    :param thing_name: Thing name
    :return: None
    """
    print("Deleting thing: {}".format(thing_name))
    iot_client = boto3.client('iot')
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]
    region = iot_client.meta.region_name
    try:
        principals = iot_client.list_thing_principals(
            thingName=thing_name
        )
    except botocore.exceptions.ClientError:
        print("Thing {} not found".format(thing_name))
        return

    cert_finger_print = "arn:aws:iot:{}:{}:cert/".format(region, account_id)
    certs = []
    for principal in principals['principals']:
        if principal.startswith(cert_finger_print):
            certs.append(principal)
    print("Found certificates: {}".format(certs))
    delete_certificates(thing_name, certs, iot_client)
    iot_client.delete_thing(thingName=thing_name)
    print("Thing {} deleted".format(thing_name))


def delete_certificates(thing_name, certificates: list, iot_client: boto3.client):
    """
    Delete certificates and policies attached to a thing
    :param certificates: list of certificate ARNs
    :param thing_name:
    :param certificates:
    :param iot_client:
    :return:
    """
    for cert in certificates:
        cert_id = cert.split('/')[1]
        policies = [p['policyName'] for p in iot_client.list_principal_policies(principal=cert)['policies']]
        for policy in policies:
            print("Detaching policies: {}".format(policies))
            iot_client.detach_principal_policy(policyName=policy, principal=cert)
        print("Deleting Certificate: {}".format(cert_id))
        iot_client.detach_thing_principal(thingName=thing_name, principal=cert)
        iot_client.update_certificate(certificateId=cert_id, newStatus='INACTIVE')
        iot_client.delete_certificate(certificateId=cert_id, forceDelete=True)
    iot_client.delete_thing(thingName=thing_name)
    print("Thing {} deleted".format(thing_name))


if __name__ == "__main__":
    unittest.main()
