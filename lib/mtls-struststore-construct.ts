/*
This module populates the Amazon API Gateway mTLS Truststore.
Two options are available:
- Use an existing Certificates Chain as teh Truststore, allowing clients to use their own client certificate.
- Generate a Truststore: This creates CA certificate and keys for the server side and a client certificate and private key.
See readme for instructions on how to configure both options.
Files location:

Truststore certificate chain (name depends on the option):
<truststoreBucketName>/<truststorePemFile>
Server-side mTLS secrets (no keys if using existing CA certificates chain):
<truststoreBucketName>/<truststoreSecretsPath>/mtlsServer/
Client-side mTLS secrets (empty if using existing CA certificates chain):
<truststoreBucketName>/<truststoreSecretsPath>/mtlsClient/
 */

import * as cdk from "aws-cdk-lib";
import { aws_s3_deployment as s3dep } from "aws-cdk-lib";
import {Construct} from "constructs";
import {MakeLambda} from "./make-lambda-construct";
import {EstConfig} from "./interfaces"
import * as path from "node:path";

export interface MtlsTruststoreProps {
    encryptionKey: cdk.aws_kms.Key;
    secretsEncryptionKey: cdk.aws_kms.Key;
    accessLogsBucket: cdk.aws_s3.Bucket;
    estUtilsLambdaLayer: cdk.aws_lambda.ILayerVersion;
    estConfig: EstConfig;
}

export class MtlsTruststore extends Construct {
    public readonly truststoreBucket: cdk.aws_s3.Bucket;
    public readonly truststorePemFile: string
    constructor(scope: Construct, id: string, props: MtlsTruststoreProps) {
        super(scope, id);

        // A few constants
        const encryptionKey = props.encryptionKey;
        const secretsEncryptionKey = props.secretsEncryptionKey;
        const accessLogsBucket = props.accessLogsBucket;
        const estConfig = props.estConfig;
        const estUtilsLambdaLayer = props.estUtilsLambdaLayer;
        const truststoreBucketName = "estTruststoreBucket";
        const truststoreSecretsPath = "est-mtls-secrets";
        this.truststorePemFile = "truststore/est-mtls-truststore.pem";

        // Bucket for the truststore
        this.truststoreBucket = new cdk.aws_s3.Bucket(this, truststoreBucketName, {
            //FIXME: enable versioning when problems resolved
            versioned: true,
            // encryption: cdk.aws_s3.BucketEncryption.KMS,
            // encryptionKey: encryptionKey,
            // bucketKeyEnabled: true,
            publicReadAccess: false,
            blockPublicAccess: cdk.aws_s3.BlockPublicAccess.BLOCK_ALL,
            objectOwnership: cdk.aws_s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            serverAccessLogsBucket: accessLogsBucket,
            serverAccessLogsPrefix: truststoreBucketName + '/',
            enforceSSL: true,
            removalPolicy: cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
        });

        if (!estConfig.DeploymentOptions.mTlsTruststoreCertificatesChainFile) {
            // Generate the server and client secrets

            const ld_truststore = new MakeLambda(this, "lambda_truststore",
                {
                    encryptionKey: encryptionKey,
                    entry: "function/mtls_truststore",
                    layers: [estUtilsLambdaLayer],
                    environment: {
                        LOG_LEVEL: "DEBUG",
                        TRUSTSTORE_S3_KEY: this.truststorePemFile,
                        SECRETS_PATH: truststoreSecretsPath,
                        BUCKET: this.truststoreBucket.bucketName,
                        DOMAIN: estConfig.Properties.apiCustomDomainName,
                        CA_SECRETS_NAME: estConfig.Properties.estMtlsCaSecretsName,
                        CA_CERT_VALIDITY:estConfig.Properties.estMtlsCaCertValidity.toString(),
                        CLIENT_SECRETS_NAME: estConfig.Properties.estMtlsClientSecretsName,
                        CLIENT_PFX_SECRET_NAME: estConfig.Properties.estMtlsClientPfxSecretName,
                        CLIENT_CERT_VALIDITY: estConfig.Properties.estMtlsClientCertValidity.toString(),
                        KMS_KEY_ARN: secretsEncryptionKey.keyArn
                    },
                    timeout: cdk.Duration.seconds(50),
                });
            this.truststoreBucket.grantReadWrite(ld_truststore.role)
            secretsEncryptionKey.grantEncryptDecrypt(ld_truststore.role)

            // Grant create, read and write for the two secrets to the Lambda function
            const resource_base = `arn:aws:secretsmanager:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:secret:`
            const createSecretsPolicyStatement = new cdk.aws_iam.PolicyStatement({
                effect: cdk.aws_iam.Effect.ALLOW,
                actions: [
                    "secretsmanager:CreateSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                ],
                resources: [
                    resource_base + estConfig.Properties.estMtlsCaSecretsName + "-??????",
                    resource_base + estConfig.Properties.estMtlsClientSecretsName + "-??????",
                    resource_base + estConfig.Properties.estMtlsClientPfxSecretName + "-??????"
                ],
            });
            ld_truststore.role.addToPrincipalPolicy(createSecretsPolicyStatement);

            // Trigger the function during deployment
            const lambdaTrigger = new cdk.triggers.Trigger(this, "TruststoreTrigger", {
                handler: ld_truststore.lambda,
                timeout: cdk.Duration.seconds(55),
                invocationType: cdk.triggers.InvocationType.REQUEST_RESPONSE
            });

            lambdaTrigger.executeAfter(this.truststoreBucket)
        }
        else {
            // User provided truststore certificates chain
            const full_path = path.parse(path.resolve(estConfig.DeploymentOptions.mTlsTruststoreCertificatesChainFile))
            const deployment = new s3dep.BucketDeployment(this, "truststore_deployment", {
                sources: [s3dep.Source.asset(full_path.dir, { exclude: ["**", "!" + full_path.base] })],
                destinationBucket: this.truststoreBucket,
                destinationKeyPrefix: "truststore/",
                prune: false,
            });
            this.truststorePemFile = "truststore/" + full_path.base
        }

        new cdk.CfnOutput(this, "TruststoreBucket", {
        exportName: "EST-Server-truststore-bucket",
        key: "ESTServerTruststoreBucketArn",
        value: this.truststoreBucket.bucketArn,
    });

        new cdk.CfnOutput(this, "truststorePemFile", {
        exportName: "EST-Server-truststore-pem-file",
        key: "ESTServerTruststorePemFile",
        value: this.truststorePemFile,
    });
    }
}
