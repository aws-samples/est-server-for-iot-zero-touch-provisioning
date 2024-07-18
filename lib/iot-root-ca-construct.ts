/*
This constructs registers and configures the CA Certificate for IoT Core
Three options:
* Use an external CA Certificate from an external PKI. In this case the signature of a device certificate will be
delegated to this PKI.
* Use an external intermediate certificate (with a private key). In this case the signature
of a device certificate will be delegated managed directly by the EST server.
* Generate a new CA Certificate along with a root private key. In this case the signature
of a device certificate will be delegated managed directly by the EST server.
See readme for instructions on how to configure this option.
Secrets are stored in AWS Secrets Manager
 */

import * as cdk from "aws-cdk-lib";
import {Construct} from "constructs";
import {NagSuppressions} from "cdk-nag";
import {EstConfig} from "./interfaces"
import {MakeLambda} from "./make-lambda-construct";
import {ProvisioningTemplate} from "./provisioning-template-construct"

export interface IotRootCaProps {
    encryptionKey: cdk.aws_kms.Key;
    secretsEncryptionKey: cdk.aws_kms.Key;
    accessLogsBucket: cdk.aws_s3.Bucket;
    estUtilsLambdaLayer: cdk.aws_lambda.ILayerVersion;
    estConfig: EstConfig;
}

export class IotRootCa  extends Construct {
    public readonly iotCoreCaCertSecret: cdk.aws_secretsmanager.ISecret;
    public readonly iotCoreCaKeySecret: cdk.aws_secretsmanager.ISecret;

    constructor(scope: Construct, id: string, props: IotRootCaProps) {
        super(scope, id);
        // A few constants
        const encryptionKey = props.encryptionKey;
        const secretsEncryptionKey = props.secretsEncryptionKey;
        const accessLogsBucket = props.accessLogsBucket;
        const estConfig = props.estConfig;
        const estUtilsLambdaLayer = props.estUtilsLambdaLayer;
        let rootCaCertSecretValue: string = ""

        const prov_template = new ProvisioningTemplate(this, "prov-tplt-ct", {
            estConfig: estConfig
        });

        // Lambda triggerred during deployment to update the secrets (will do only if they are not defined ="")
        const ld_iot_ca = new MakeLambda(this, "lambda_iot_ca",
        {
            encryptionKey: encryptionKey,
            entry: "function/make_iotcore_ca",
            layers: [estUtilsLambdaLayer],
            environment: {
                LOG_LEVEL: "DEBUG",
                GENERATE_CERT: estConfig.DeploymentOptions.generateIotCaCertificate.toString(),
                CA_CERT_SECRET_NAME: estConfig.Properties.iotCoreEstCaCertSecretName,
                CA_KEY_SECRET_NAME: estConfig.Properties.iotCoreEstCaKeySecretName,
                CA_VALIDITY_YEARS: estConfig.Properties.iotCoreEstCaValidityYears.toString(),
                KMS_KEY_ARN: secretsEncryptionKey.keyArn,
                REGISTER_CA: estConfig.DeploymentOptions.configureJITP.toString(),
                PROV_TEMPLATE_NAME: estConfig.Properties.iotTemplateName,
            },
            timeout: cdk.Duration.seconds(50),
        });
        secretsEncryptionKey.grantEncryptDecrypt(ld_iot_ca.lambda)

        // Grant create, read and write for the two secrets to the Lambda function
        const resource_base = `arn:aws:secretsmanager:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:secret:`
        const createSecretsPolicyStatement = new cdk.aws_iam.PolicyStatement({
            effect: cdk.aws_iam.Effect.ALLOW,
            actions: [
                "secretsmanager:CreateSecret",
                "secretsmanager:GetSecretValue",
                "secretsmanager:PutSecretValue"
            ],
            resources: [
                resource_base + estConfig.Properties.iotCoreEstCaCertSecretName + "-??????",
                resource_base + estConfig.Properties.iotCoreEstCaKeySecretName + "-??????",
            ],
        });
        ld_iot_ca.role.addToPrincipalPolicy(createSecretsPolicyStatement)

        const provisionCaPolicyStatement = new cdk.aws_iam.PolicyStatement({
            effect: cdk.aws_iam.Effect.ALLOW,
            actions: [
                "iot:RegisterCACertificate",
                "iot:ListCACertificates",
                "iot:DescribeCACertificate"
            ],

            resources: ["*"],
        });
        ld_iot_ca.role.addToPrincipalPolicy(provisionCaPolicyStatement)

        // Be aware that the trigger is only executed on handler change.
        // https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.triggers-readme.html
        const lambdaTrigger = new cdk.triggers.Trigger(this, "IotCaTrigger", {
            handler: ld_iot_ca.lambda,
            timeout: cdk.Duration.seconds(55),
            invocationType: cdk.triggers.InvocationType.REQUEST_RESPONSE,
        });
        lambdaTrigger.executeAfter(prov_template)
        this.iotCoreCaCertSecret = cdk.aws_secretsmanager.Secret.fromSecretNameV2(this, "IoTCoreCertSecret",
            estConfig.Properties.iotCoreEstCaCertSecretName)
        this.iotCoreCaKeySecret = cdk.aws_secretsmanager.Secret.fromSecretNameV2(this, "IoTCoreKeySecret",
            estConfig.Properties.iotCoreEstCaKeySecretName)


        NagSuppressions.addResourceSuppressions(
            this.iotCoreCaCertSecret,
            [
                {
                    id: "AwsSolutions-SMG4",
                    reason: "This secret should not be rotated automatically"
                },
            ]
        );
        NagSuppressions.addResourceSuppressions(
            this.iotCoreCaKeySecret,
            [
                {
                    id: "AwsSolutions-SMG4",
                    reason: "This secret should not be rotated automatically"
                },
            ]
        );
        NagSuppressions.addResourceSuppressions(
            ld_iot_ca.role, [
                {
                    id: 'AwsSolutions-IAM5',
                    reason: 'The application requires to access all the registered CA in IoT Core.',
                },
            ], true
        );

         new cdk.CfnOutput(this, "Secret KMS key ARN", {
            exportName: "EST-Server-Secrets-KMS-Key-ARN",
            key: "ESTServerSecretsKmsKeyArn",
            value: secretsEncryptionKey.keyArn,
        });

         new cdk.CfnOutput(this, "IoT CA Certificate Secret", {
            exportName: "EST-Server-iot-ca-cert-secret",
            key: "ESTServerIotCaCertSecretArn",
            value: this.iotCoreCaCertSecret.secretArn,
        });

         new cdk.CfnOutput(this, "IoT CA Key Secret", {
            exportName: "EST-Server-iot-ca-key-secret",
            key: "ESTServerIotCaKeySecretArn",
            value: this.iotCoreCaKeySecret.secretArn,
        });

    }
}
