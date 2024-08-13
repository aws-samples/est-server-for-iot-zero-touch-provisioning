# Welcome to the EST Server for AWS IoT

This CDK project deploys an Enrollment over Secure Transport (EST) server, which is a way for an IoT device to obtain
a certificate without exposing any secret and without human intervention. It makes Zero-Trust and Zero-Touch possible.

The EST Server has been developed to be compliant with [[RFC7030](https://datatracker.ietf.org/doc/html/rfc7030)] and it
entirely "serverless".
Note that *Implicit trust anchor* is not implemented. You'll have to use *the explicit trust anchor*, meaning 
that the EST server Certificate will have to be known in advance by the device.

In addition, it provides features which will facilitate the management of IoT devices like enabling Just In Time 
Provisioning (JITP). You will also find a lambda allowing to sign client CSR for mTLS with API Gateway.

The multiple options available will hopefully allow you to configure the EST service according to your use case, and
in just a few minutes. We will go in details in the next sections, but for now lets take care of the impatient ones.

## Flash Start
If you don't know what an EST Server is and/or you are not familiar with the AWS Cloud Development Kit (CDK) nor 
AWS services (Amazon API Gateway, Amazon S3, AWS Iot Core, AWS Certificate Manager ) stop reading and skip to the next 
sections.

1. Clone this repo on your development environment
1. Log-in your dev environment on you AWS account
1. Get a certificate for the API Gateway (AGW) custom domain name
1. If you didn't use AWS Certificate Manager (ACM) to generate the certificate:
   1. Import it in ACM and not its ARN.
   1. Request an [ownership verification certificate](https://docs.aws.amazon.com/acm/latest/userguide/domain-ownership-validation.html) 
      from ACM, as [this is required by AGW](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html).
   

You have 2 options for quick start, depending on how you will handle mTLS for the EST server, IoT device certificate
signing and JITP.

### You don't have any Root CA Certificate except for API Gateway custom domain name
No worries, they will be generated for you

1. Copy the file `config/config-sample-all-generated.yaml` to `config/config.yaml`
1. Edit `config/config.yaml` looking for the strings in CAPITAL letter
   1. AGW domain name
   1. AGW domain certificate
   1. AGW ownership verification certificate
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
pfx file have been generated and signed by this CA. They are all stored in ASM, and a set of sample client files is also
present in the Truststore bucket (see AWS CloudFormation stack outputs). You can install the client cert in postman for 
testing. Best is to have the client certs generated and signed at the device factory.

### You already have a CA Trust Chain for mTLS and you use an external PKI for signing the devices
In this case, you just have to pass the files in the config file. Make sure they are available locally in your dev
environment.

You'll have to implement the interface to your PKI... do you like python3? 

1. Copy the file `config/config-sample-all-external.yaml` to `config/config.yaml`
1. Edit `config/config.yaml` looking for the strings in CAPITAL letter
   1. AGW domain name
   1. AGW domain certificate
   1. AGW ownership verification certificate if required
   1. Path to your mTLS CA trust chain (to be provisioned in AGW)
   1. Path to your IoT PKI CA (to be provisioned in IoT Core)
1. Check if the duration of the various certificates is suitable for your application (default 10 years)
1. Give a look at the IoT Provisioning Template `config/iot_template_default.json`, make a copy and modify as necessary
1. If you copied the Provisioning Template input its new path/name in the configuration file
1. Give a look at the IoT Policy `config/iot_policy_default.json`, make a copy and modify as necessary
1. If you copied the IoT Policy input its new path/name in the configuration file
1. Open the file `layer/utils/est_common.py`
   1. Find the function `sign_externally` - this is where you will implement the interface to your external PKI.

### Pro-tips
The lambda `function/simpleenroll/lambda.py` has `pre_enroll` and  `post_enroll` functions which are placeholders to 
perform additional tasks. There you can, for example, check if a device is not in a forbidden list before signing it 
CSR and record the transaction in a DB... or anything else you like.

It is the same for `function/simplereenroll/lambda.py` with `pre_reenroll` and `post_reenroll`.

### About re-enrollment
The first time a device obtains a certificates and connects to IoT Core, it will be enrolled automatically by JITP.
Later on, when the device renews its certificate it will try to connect to IoT Core with this new certificate but would
fail if the new certificate has not been associated with the matching IoT Thing.
This project makes an attempt to find a matching IoT Thing and attach the new certificate to it. Of course, if this
EST server is not hosted in the same account and the IoT Things, it will fail (without raising an Exception). You will
then have to figure out how to do that!

## Setting-up your environment

### Pre-requisites
* Node.js version 18.x or above, as supported by the current version of aws-cdk (tested with 18.19)
* Python (tested with 3.12)
* You have fresh credentials to the target AWS Account

### Clone the repo
```bash
git clone git@github.com:aws-samples/UPDATE_ME
```

### Install dependencies
```bash
# Install the AWS CDK and the dependencies with Node.js
npm install
# Install the python3 packages required by CDK to generate the CloudFormation template
pip3 install -r requirements.txt
# If new account, you need to bootstrap the CDK (there is no risk to run it regularly...)
cdk bootstrap
```
### Deployment commands
```bash
cdk deploy --all
```
You can also specify a custom configuration file location:
```bash
cdk deploy --context configFile=my_custom_location/my_custom_config.yaml --all
```
You can find more commands nd options for `cdk` here: https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd.html

## Establishing the bases
This project is all about certificates and this can get confusing. So we need to define a terminology to limit the 
confusion. There are three groups of certificates involved:

### Everything related to the IoT Operations
We are here looking at IoT Core and the IoT Devices identification. The main purpose of an EST Server is "delivering
certificates to IoT devices" so they can start doing their job securely. When we will discuss this part of the project 
we will refer to it with the word "device" and/or "IoT". 
To operate securely IoT Core needs Certificate Authority (CA) registered. Then the IoT device can send a 
Certificate Signing Request (CSR) to receive in return a *Device Certificate* signed by the CA that was registered in IoT Core.
Note that it doesn't mean that the signature is effectively done by IoT Core. We'll get back to this later.

### A server or an API must be secure
This EST Server must also be secure, so it needs to have a Certificate of its own, which matches the domain name of 
the server. This "custom domain name" and certificate are installed in API Gateway so the clients can authenticate the
EST Server (the API in fact, since there is no webserver) and establish a trusted secure connection via TLS. 
Here we are referring to the "EST Server Certificate".

### The users of the EST Server also need to be identified
Finally, the [[RFC7030](https://datatracker.ietf.org/doc/html/rfc7030)] specification for EST also requires that the
clients be identified via mutual TLS (mTLS). It means that the client must present a certificate that is known by the
EST Server. In other terms the EST Server (API Gateway) must have a *Certificate Chain of Trust* which allows verifying
the certificate presented by the client. This *Certificate Chain of Trust* is called a *Truststore* in API Gateway 
terminology. 
The client must possess a *client certificate for mTLS* matching the *Truststore* (signed by one CA in the chain), 
which we will refer to as the *Client Certificate*. 

We are here looking at the calls to the EST API endpoints by the client. 
And this is not to be confused with the *Device Certificate* used for the IoT operations (interaction with IoT Core).

## Understanding the project features and architecture

### Features
The main goal of this code sample is to easily deploy an EST Server, a service which is capable of:
* Providing the current CA Certificate of the IoT Service (IoT Core in our case).
* Signing a CSR and returning the corresponding Certificate to an IoT Device for a first enrollment and a certificate 
renewal.

Signing a CSR for an IoT Device can be done locally on AWS or by an external PKI. This project allows both:
* If you are comfortable using a local PKI, it will create a self-signed Root CA and will use it to sign the Device
 Certificates
* If you prefer to use an external CA, you will provide the CA Certificate of your PKI, and it will be registered  
in IoT Core. You will have to implement the interface to your external PKI (more on this later).

As we saw earlier, mTLS requires a Truststore and matching client certificates. You also have two options here:
* Recommended: your mTLS Client Certificates are generated at the factory during the configuration of the IoT Device 
by your own PKI. In this case you just have to provide the Truststore as
[documented by API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-mutual-tls.html).
* For testing: you can also create a PKI for mTLS Certificates generation. In this case you will be able to generate 
mTLS client certificates (sign a CSR) with the serf-signed root CA that was created for you. 
Signing an mTLS CSR is a manual action and a Lambda function is provided for this.

* Just in Time Provisioning (JITP): JITP is a feature of AWS IoT Core allowing a new device to be automatically
provisioned at first connection. When valid certificate, signed by the CA registered in IoT Core, is presented by a new 
device, IoT automatically provisions the device according to pre-configured provisioning template and IoT policy. More
details are available [here](https://docs.aws.amazon.com/iot/latest/developerguide/jit-provisioning.html). By setting the
configuration parameter `configureJITP` to `true` JITP will be configured in the account when the CDK is deployed.

All the above feature options are controlled by a few configuration parameters of the configuration file you'll have to 
create. This is the single point of configuration, except if you need to use an external PKI for signing the IoT Device CSR.

### Architecture
This CDK project deploys serverless AWS resources, limiting the run costs of the service and reducing the efforts to keep
it secure and up-to-date. The Lambda functions are writen in Python 3.

