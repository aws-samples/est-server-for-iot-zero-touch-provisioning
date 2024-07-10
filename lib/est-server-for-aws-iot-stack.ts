import * as cdk from 'aws-cdk-lib';
import {Construct} from 'constructs';
import {NagSuppressions} from "cdk-nag";
import {CommonResources} from './common-resources-construct';
import {MakeLambda} from "./make-lambda-construct"
import {ApiBase} from "./api-base-construct"

export class EstServerForAwsIotStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // Create the resources used at large by this application
        const common = new CommonResources(this, "Common Resources");
        const encryptionKey = common.encryptionKey;
        const accessLogsBucket = common.accessLogsS3Bucket;

        // Create the Lambda layers containing reusable functions
        const CommonLambdaLayer = new cdk.aws_lambda.LayerVersion(this, "est-layer-utils" + id, {
            layerVersionName: "est-layer-utils",
            code: cdk.aws_lambda.Code.fromAsset("layer/utils"),
            compatibleRuntimes: [cdk.aws_lambda.Runtime.PYTHON_3_12],
            description: "Layer of reusable functions for EST Server",
            removalPolicy: cdk.RemovalPolicy.DESTROY,
            compatibleArchitectures: [cdk.aws_lambda.Architecture.X86_64, cdk.aws_lambda.Architecture.ARM_64]
        });
        /*
        const ExtDepLambdaLayer = new cdk.aws_lambda.LayerVersion(this, "est-layer-ext" + id, {
            layerVersionName: "est-layer-ext",
            code: cdk.aws_lambda.Code.fromAsset("layer/ext_dependencies"),
            compatibleRuntimes: [cdk.aws_lambda.Runtime.PYTHON_3_12],
            description: "External dependencies from requirements.txt for EST Server",
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        });
        */
        // Lambda functions responding to the API endpoints
        const ld_cacerts = new MakeLambda(this, "lambda_cacerts",
            {
                encryptionKey: encryptionKey,
                entry: "function/cacerts/",
                layers: [CommonLambdaLayer],
                environment: {LOG_LEVEL: "INFO"},
                timeout: cdk.Duration.seconds(3),
            }
        );

        const ld_csrattrs = new MakeLambda(this, "lambda_csrattrs",
            {
                encryptionKey: encryptionKey,
                entry: "function/csrattrs/",
                layers: [CommonLambdaLayer],
                environment: {LOG_LEVEL: "INFO"},
                timeout: cdk.Duration.seconds(3),
            }
        );

        const ld_serverkeygen = new MakeLambda(this, "lambda_serverkeygen",
            {
                encryptionKey: encryptionKey,
                entry: "function/serverkeygen/",
                layers: [CommonLambdaLayer],
                environment: {LOG_LEVEL: "INFO"},
                timeout: cdk.Duration.seconds(3),
            }
        );

        const ld_simpleenroll = new MakeLambda(this, "lambda_simpleenroll",
            {
                encryptionKey: encryptionKey,
                entry: "function/simpleenroll/",
                layers: [CommonLambdaLayer],
                environment: {LOG_LEVEL: "INFO"},
                timeout: cdk.Duration.seconds(3),
            }
        );

        // Policy allowing creating Certificate from  CSR
        const createCertFromCsrPolicy = new cdk.aws_iam.PolicyStatement({
            effect: cdk.aws_iam.Effect.ALLOW,
            actions: [
                "iot:CreateCertificateFromCsr"
            ],
            resources: ["*"],
        });

        ld_simpleenroll.role.addToPolicy(createCertFromCsrPolicy);

        const ld_simplereenroll = new MakeLambda(this, "lambda_simplereenroll",
            {
                encryptionKey: encryptionKey,
                entry: "function/simplereenroll/",
                layers: [CommonLambdaLayer],
                environment: {LOG_LEVEL: "INFO"},
                timeout: cdk.Duration.seconds(3),
            }
        );

        ld_simplereenroll.role.addToPolicy(createCertFromCsrPolicy)

        // Get the API base from the construct
        const api = new ApiBase(this, "rest-api-base", {encryptionKey: encryptionKey}).api

        // Set a default request validator - body is usually base64 encoded so no validation by API Gateway
        const requestValidator = new cdk.aws_apigateway.RequestValidator(this,
            "generic-request-validator", {
                restApi: api,
                validateRequestBody: false,
                validateRequestParameters: true,
            });

        // API resources & methods
        const PostReqParams = {
                    'method.request.header.Accept': true,
                    'method.request.header.Content-Type': true,
                    'method.request.header.Content-Transfer-Encoding': true,
                    'method.request.header.Content-Disposition': true,
                    'method.request.querystring.tenant-id': true
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
                    'method.request.header.Accept': true,
                    'method.request.querystring.certificate-type': false
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

       // Suppress findings for acceptable CDK-NAG warnings and errors
        NagSuppressions.addResourceSuppressions(
            api,
            [
                {
                    id: "AwsSolutions-APIG2",
                    reason: "The API has a request validator for query parameters and headers. Cannot do on body.",
                },
                {
                    // TODO: check if still necessary after client cert implementation
                    id: "AwsSolutions-APIG4",
                    reason: "This API is public. Client certificate is used.",
                },
                {
                    // TODO: check if still necessary after client cert implementation
                    id: "AwsSolutions-COG4",
                    reason: "This API is public. Client certificate is used.",
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