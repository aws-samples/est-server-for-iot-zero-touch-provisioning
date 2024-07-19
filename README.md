# Welcome to the EST Server for AWS IoT

This CDK project deploys an Enrollment over Secure Transport (EST) server, which is a way for an IoT device to obtain
a certificate without exposing any secret and without human intervention. It makes Zero-Trust and Zero-Touch possible.

The EST Servicer has been developed to be compliant with [[RFC7030](https://datatracker.ietf.org/doc/html/rfc7030)].
In addition, it provides features which will facilitate the management of IoT devices like enabling Just In Time 
Provisioning (JITP). *Implicit trust anchor* is not implemented. You'll have to use *the explicit trust anchor*, meaning 
that the EST server Certificate will have to be known in advance by the device.

The multiple options available will hopefully allow you to configure the EST service according to your use case, and
in just a few minutes. We will go in details in the next sections, but for now lets take care of the impatiens.

## Flash Start
If you don't know what an EST Server is and/or you are not familiar with the AWS Cloud Development Kit (CDK) nor 
AWS services (Amazon API Gateway, Amazon S3, AWS Iot Core, AWS Certificate Manager ) stop reading and skip to the next 
sections.

1. Clone this repo on your development environment
1. Log your dev environment on you AWS account
1. Get a certificate for the API Gateway (AGW) custom domain name
1. If you didn't use AWS Certificate Manager (ACM) to generate the certificate, import it in ACM and not its ARN.

You have 2 options for quick start, depending on how you will handle mTLS for the EST server, IoT device certificate
signing and JITP.

### You don't have any Root CA Certificate except for API Gateway custom domain name
No worries, they will be generated for you

1. Copy the file `config/config-sample-all-generated.yaml` to `config/config.yaml`
1. Edit `config/config.yaml` looking for the strings in CAPITAL letter
   1. AGW domain name
   2. AGW domain certificate
1. Check if the duration of the various certificates is suitable for your application (default 10 years)
1. Give a look at the IoT Provisioning Template `config/iot_template_default.json`, make a copy and modify as necessary
1. If you copied the Provisioning Template input its new path/name in the configuration file
1. Give a look at the IoT Policy `config/iot_policy_default.json`, make a copy and modify as necessary
1. If you copied the IoT Policy input its new path/name in the configuration file
1. `cdk deploy --all`

Et voilà!

* A self-signed Root CA Certificate has been generated with its private key. It will be used to sign the devices CSR.
All is stored in AWS Secrets Manager (ASM).
* A self-signed root CA has been generated and AGW configured to use it for mTLS. A client certificate, private key and 
pfx file have been generated and signed by this CA. They are all stored in ASM, and the client files are also present
in the Truststore bucket (see AWS CloudFormation stack outputs). You can install the client cert in postman for testing.
Best is to have the client certs generated and signed at the device factory, and you should only install the Root CA.

### You already have a CA Trust Chain and client Certificate for mTLS and you use an external PKI for signing the devices
In this case, you just have to pass the files in the config file. Make sure they are available locally in your dev
environment.

You'll have to implement the interface to your PKI... do you like python3? 

1. Copy the file `config/config-sample-all-external.yaml` to `config/config.yaml`
1. Edit `config/config.yaml` looking for the strings in CAPITAL letter
   1. AGW domain name
   2. AGW domain certificate
   3. Path to your mTLS CA trust chain (to be provisioned in AGW)
   4. Path to your IoT PKI CA (to be provisioned in IoT Core)
1. Check if the duration of the various certificates is suitable for your application (default 10 years)
1. Give a look at the IoT Provisioning Template `config/iot_template_default.json`, make a copy and modify as necessary
1. If you copied the Provisioning Template input its new path/name in the configuration file
1. Give a look at the IoT Policy `config/iot_policy_default.json`, make a copy and modify as necessary
1. If you copied the IoT Policy input its new path/name in the configuration file
1. Open the file `layer/utils/est_common.py`
   1. Find the function `sign_externally` - this is where you will implement the interface to your external PKI.

### Pro-tips
The lambda `function/simpleenroll/lambda.py` has `pre_enroll` and  `post_enroll` functions which are placeholders to 
perform additional tasks. There you can, for example,  check if a device is not in a forbidden list before signing it 
CSR and record the transaction in a DB... or anything else you like.

It is the same for `function/simplereenroll/lambda.py` with pre_reenroll and `post_reenroll`.

### About re-enrollment
The first time a device obtains a certificates and connects to IoT Core, it will be enrolled automatically by JITP.
Later on, when the device renews its certificate it will try to connect to IoT Core with this new certificate but would
fail if the new certificate has not been associated with the matching IoT Thing.
This project makes an attempt to find a matching IoT Thing and attach the new certificate to it. Of course, if this
EST server is not hosted in the same account and the IoT Things, it will fail (without raising an Exception). You will
then have to figure out how to do that!

## Taking it slower

 to be continued...











The `cdk.json` file tells the CDK Toolkit how to execute your app.

## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `npx cdk deploy`  deploy this stack to your default AWS account/region
* `npx cdk diff`    compare deployed stack with current state
* `npx cdk synth`   emits the synthesized CloudFormation template
