import * as cdk from 'aws-cdk-lib';
import {Construct} from 'constructs';
import {NagSuppressions} from "cdk-nag";
import * as python from "@aws-cdk/aws-lambda-python-alpha";
import { parse as yamlParse } from "yaml";
import * as fs from 'node:fs';
import * as path from "node:path";
import {CommonResources} from './common-resources-construct';
import {MakeLambda} from "./make-lambda-construct";
import {ApiBase} from "./api-base-construct";
import {EstConfig} from "./interfaces";
import {IotRootCa} from "./iot-root-ca-construct";


export class EstServerForAwsIotStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // Parse the YAML file and get the build parameters
        const configFile: string = this.node.tryGetContext('configFile') as string
        const unparsedParams = fs.readFileSync(path.resolve(configFile), "utf-8")
        const estConfig = yamlParse(unparsedParams) as EstConfig

        // Create the resources used at large by this application
        const common = new CommonResources(this, "Common Resources");
        const encryptionKey = common.encryptionKey;
        const secretsEncryptionKey = common.secretsEncryptionKey
        const accessLogsBucket = common.accessLogsS3Bucket;

        // Useful constants
        const strictHeadersCheck = estConfig.Properties.apiStrictHeadersCheck;

        // Create the Lambda layers containing reusable functions
        const CommonLambdaLayer = new python.PythonLayerVersion(this, "est-layer-utils" + id, {
            layerVersionName: "est-layer-utils",
            entry: "layer/utils/",
            compatibleRuntimes: [cdk.aws_lambda.Runtime.PYTHON_3_12],
            description: "Utils for the EST Server",
            removalPolicy: cdk.RemovalPolicy.DESTROY,
            compatibleArchitectures: [cdk.aws_lambda.Architecture.X86_64]
        });

       // Register the IoT CA and configure JITP if enabled
        const iot_ca = new IotRootCa(this, "iotRootCa", {
            encryptionKey: encryptionKey,
            secretsEncryptionKey: secretsEncryptionKey,
            accessLogsBucket: accessLogsBucket,
            estUtilsLambdaLayer: CommonLambdaLayer,
            estConfig: estConfig,
        });

        // Lambda functions responding to the API endpoints
        const ld_cacerts = new MakeLambda(this, "lambda_cacerts",
            {
                description: "EST Server Lambda for /cacerts endpoint",
                encryptionKey: encryptionKey,
                entry: "function/cacerts/",
                layers: [CommonLambdaLayer],
                environment: {
                    LOG_LEVEL: estConfig.Properties.lambdaLoggerLevel,
                    CA_CERT_SECRET_ARN: iot_ca.iotCoreCaCertSecret.secretArn,
                    STRICT_HEADERS_CHECK: strictHeadersCheck.toString(),
                    },
                timeout: cdk.Duration.seconds(10),
            }
        );
        iot_ca.iotCoreCaCertSecret.grantRead(ld_cacerts.lambda)
        secretsEncryptionKey.grantDecrypt(ld_cacerts.lambda)

        const ld_csrattrs = new MakeLambda(this, "lambda_csrattrs",
            {
                description: "EST Server Lambda for /csrattrs endpoint",
                encryptionKey: encryptionKey,
                entry: "function/csrattrs/",
                layers: [CommonLambdaLayer],
                environment: {
                    LOG_LEVEL: estConfig.Properties.lambdaLoggerLevel,
                    STRICT_HEADERS_CHECK: strictHeadersCheck.toString(),
                },
                timeout: cdk.Duration.seconds(10),
            }
        );

        const ld_serverkeygen = new MakeLambda(this, "lambda_serverkeygen",
            {
                description: "EST Server Lambda for /serverkeygen endpoint",
                encryptionKey: encryptionKey,
                entry: "function/serverkeygen/",
                layers: [CommonLambdaLayer],
                environment: {
                    LOG_LEVEL: estConfig.Properties.lambdaLoggerLevel,
                    STRICT_HEADERS_CHECK: strictHeadersCheck.toString(),
                },
                timeout: cdk.Duration.seconds(10),
            }
        );

        const ld_simpleenroll = new MakeLambda(this, "lambda_simpleenroll",
            {
                description: "EST Server Lambda for /simpleenroll endpoint",
                encryptionKey: encryptionKey,
                entry: "function/simpleenroll/",
                layers: [CommonLambdaLayer],
                environment: {
                    LOG_LEVEL: estConfig.Properties.lambdaLoggerLevel,
                    CA_CERT_SECRET_ARN: iot_ca.iotCoreCaCertSecret.secretArn,
                    CA_KEY_SECRET_ARN: iot_ca.iotCoreCaKeySecret.secretArn,
                    STRICT_HEADERS_CHECK: strictHeadersCheck.toString(),
                },
                timeout: cdk.Duration.seconds(10),
            }
        );
        iot_ca.iotCoreCaCertSecret.grantRead(ld_simpleenroll.lambda)
        iot_ca.iotCoreCaKeySecret.grantRead(ld_simpleenroll.lambda)
        secretsEncryptionKey.grantDecrypt(ld_simpleenroll.lambda)

       const ld_simplereenroll = new MakeLambda(this, "lambda_simplereenroll",
            {
                description: "EST Server Lambda for /simpleREenroll endpoint",
                encryptionKey: encryptionKey,
                entry: "function/simplereenroll/",
                layers: [CommonLambdaLayer],
                environment: {
                    LOG_LEVEL: estConfig.Properties.lambdaLoggerLevel,
                    CA_CERT_SECRET_ARN: iot_ca.iotCoreCaCertSecret.secretArn,
                    CA_KEY_SECRET_ARN: iot_ca.iotCoreCaKeySecret.secretArn,
                    IOT_POLICY_NAME: estConfig.Properties.iotPolicyName,
                    STRICT_HEADERS_CHECK: strictHeadersCheck.toString(),
                },
                timeout: cdk.Duration.seconds(10),
            }
        );
        iot_ca.iotCoreCaCertSecret.grantRead(ld_simplereenroll.lambda)
        iot_ca.iotCoreCaKeySecret.grantRead(ld_simplereenroll.lambda)
        secretsEncryptionKey.grantDecrypt(ld_simplereenroll.lambda)

        // Policy allowing attaching a renewed certification to a Thing
        const reenrollmentPolicy = new cdk.aws_iam.PolicyStatement({
            effect: cdk.aws_iam.Effect.ALLOW,
            actions: [
                "iot:DescribeThing",
                "iot:AttachThingPrincipal",
                "iot:RegisterCertificate",
                "iot:AttachPolicy",
                "iot:ListCertificates",
            ],
            resources: ["*"],
        });
        ld_simplereenroll.role.addToPolicy(reenrollmentPolicy)

        // Get the API base from the construct
        const api = new ApiBase(this, "rest-api-base", {
            encryptionKey: encryptionKey,
            secretsEncryptionKey: secretsEncryptionKey,
            accessLogsBucket: accessLogsBucket,
            estUtilsLambdaLayer: CommonLambdaLayer,
            estConfig: estConfig,
        }).api;

        // Set a default request validator - body is usually base64 encoded so no validation by API Gateway
        const requestValidator = new cdk.aws_apigateway.RequestValidator(this,
            "generic-request-validator", {
                restApi: api,
                validateRequestBody: false,
                validateRequestParameters: true,
            });

        // API resources & methods
        const PostReqParams = {
                    'method.request.header.Accept': strictHeadersCheck,
                    'method.request.header.Content-Type': strictHeadersCheck,
                    'method.request.header.Content-Transfer-Encoding': strictHeadersCheck,
                    'method.request.header.Content-Disposition': strictHeadersCheck,
                    'method.request.querystring.tenant-id': false
                }

        const est_res = api.root.addResource(".well-known").addResource("est")

        // CA Certificate request
        const re_cacerts =est_res.addResource("cacerts");
        re_cacerts.addCorsPreflight({
            allowHeaders: ["Origin", "Accept", "Content-Type"],
            allowMethods: ["OPTIONS", "GET"],
            allowCredentials: true,
            allowOrigins: cdk.aws_apigateway.Cors.ALL_ORIGINS,
            }
        );
        re_cacerts.addMethod("GET",
            new cdk.aws_apigateway.LambdaIntegration(ld_cacerts.lambda, {
                passthroughBehavior: cdk.aws_apigateway.PassthroughBehavior.WHEN_NO_TEMPLATES,
                proxy: true,
                }),
    {
                requestValidator: requestValidator,
                requestParameters: {
                    'method.request.header.Accept': strictHeadersCheck,
                }
            });

        // CSR Attributes request
        const re_csrattrs = est_res.addResource("csrattrs");
        re_csrattrs.addCorsPreflight({
            allowHeaders: ["Origin", "Accept", "Content-Type"],
            allowMethods: ["OPTIONS", "GET"],
            allowCredentials: true,
            allowOrigins: cdk.aws_apigateway.Cors.ALL_ORIGINS,
            }
        );
        re_csrattrs.addMethod("GET", new cdk.aws_apigateway.LambdaIntegration(ld_csrattrs.lambda, {
                passthroughBehavior: cdk.aws_apigateway.PassthroughBehavior.WHEN_NO_TEMPLATES,
                proxy: true
            }));

        // Server Key Generation request
        const re_serverkeygen = est_res.addResource("serverkeygen");
        re_serverkeygen.addCorsPreflight({
            allowHeaders: ["Origin", "Accept", "Content-Type"],
            allowMethods: ["OPTIONS", "POST"],
            allowCredentials: true,
            allowOrigins: cdk.aws_apigateway.Cors.ALL_ORIGINS,
            }
        );
        re_serverkeygen.addMethod("POST",
            new cdk.aws_apigateway.LambdaIntegration(ld_serverkeygen.lambda, {
                passthroughBehavior: cdk.aws_apigateway.PassthroughBehavior.WHEN_NO_TEMPLATES,
                proxy: true,
            }),
    {
                requestValidator: requestValidator,
                requestParameters: PostReqParams,
            });

        // Simple Enrollment request
        const re_simpleenroll = est_res.addResource("simpleenroll");
        re_simpleenroll.addCorsPreflight({
            allowHeaders: ["Origin", "Accept", "Content-Type", "Content-Transfer-Encoding", "Content-Disposition", "Content-Length"],
            allowMethods: ["OPTIONS", "POST"],
            allowCredentials: true,
            allowOrigins: cdk.aws_apigateway.Cors.ALL_ORIGINS,
            }
        );
        re_simpleenroll.addMethod("POST",
            new cdk.aws_apigateway.LambdaIntegration(ld_simpleenroll.lambda, {
                passthroughBehavior: cdk.aws_apigateway.PassthroughBehavior.WHEN_NO_TEMPLATES,
                proxy: true,
            }),
    {
                requestValidator: requestValidator,
                requestParameters: PostReqParams,
            });

        // Simple Re-enrollment request
        const re_simplereenroll = est_res.addResource("simplereenroll");
        re_simplereenroll.addCorsPreflight({
            allowHeaders: ["Origin", "Accept", "Content-Type", "Content-Transfer-Encoding", "Content-Disposition", "Content-Length"],
            allowMethods: ["OPTIONS", "POST"],
            allowCredentials: true,
            allowOrigins: cdk.aws_apigateway.Cors.ALL_ORIGINS,
            }
        );
        re_simplereenroll.addMethod("POST",
            new cdk.aws_apigateway.LambdaIntegration(ld_simplereenroll.lambda, {
                passthroughBehavior: cdk.aws_apigateway.PassthroughBehavior.WHEN_NO_TEMPLATES,
                proxy: true,
            }),
    {
                requestValidator: requestValidator,
                requestParameters: PostReqParams,
            });

       // Suppress findings for acceptable CDK-NAG warnings and errors - doesn't work from API construct
        NagSuppressions.addResourceSuppressions(
            api,
            [
                {
                    id: "AwsSolutions-APIG2",
                    reason: "The API has a request validator for query parameters and headers. Cannot do on body.",
                },
                {
                    id: "AwsSolutions-APIG4",
                    reason: "This API must be public. mTLS is used.",
                },
                {
                    id: "AwsSolutions-COG4",
                    reason: "This API must be public. mTLS is used.",
                },
            ],
            true
        );

        NagSuppressions.addResourceSuppressions(
            ld_simpleenroll.role,
            [
                {
                    id: "AwsSolutions-IAM5",
                    reason: "Wildcard required for iot:CreateCertificateFromCsr.",
                },
            ],
            true,
        );

        NagSuppressions.addResourceSuppressions(
            ld_simplereenroll.role,
            [
                {
                    id: "AwsSolutions-IAM5",
                    reason: "Wildcard required for iot:CreateCertificateFromCsr.",
                },
            ],
            true,
        );
    }
}

