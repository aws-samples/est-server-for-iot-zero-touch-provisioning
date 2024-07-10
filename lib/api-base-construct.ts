import * as cdk from 'aws-cdk-lib';
import {Construct} from 'constructs';
import {NagSuppressions} from "cdk-nag";

export interface ApiBaseProps {
    encryptionKey: cdk.aws_kms.Key;
}

export class ApiBase extends Construct {
    public readonly api: cdk.aws_apigateway.RestApi;

    constructor(scope: Construct, id: string, props: ApiBaseProps) {
        super(scope, id);

        const encryptionKey = props.encryptionKey

        // Create a REST API with Lambda Proxy for python and CloudWatch logs enabled

        const apiLogGroup = new cdk.aws_logs.LogGroup(this, "apiLogGroup" + id, {
            logGroupName: "/aws/apigateway/accesslog/EST-Server_" + id,
            retention: cdk.aws_logs.RetentionDays.SIX_MONTHS,
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        });

        this.api = new cdk.aws_apigateway.RestApi(this, "est-api" + id, {
            restApiName: "EST-Server",
            description: "API for EST Server for AWS IoT",
            cloudWatchRole: true,
            deployOptions: {
                stageName: "prod",
                description: "Production stage of the EST Server REST API",
                // Throttle the API to limit DDoS risk
                // Low limit is acceptable because device provisioning is slow
                throttlingBurstLimit: 2,
                throttlingRateLimit: 4,
                //Execution logs settings
                loggingLevel: cdk.aws_apigateway.MethodLoggingLevel.INFO,
                dataTraceEnabled: false,
                //Access logs settings
                accessLogDestination: new cdk.aws_apigateway.LogGroupLogDestination(apiLogGroup),
                accessLogFormat: cdk.aws_apigateway.AccessLogFormat.jsonWithStandardFields(
                    {
                        caller: true,
                        httpMethod: true,
                        ip: true,
                        protocol: true,
                        requestTime: true,
                        resourcePath: true,
                        responseLength: true,
                        status: true,
                        user: true,
                    }
                ),
            },
            endpointTypes: [cdk.aws_apigateway.EndpointType.REGIONAL],
            retainDeployments: false,
            deploy: true,
            disableExecuteApiEndpoint: false,
        });

        //Add WAF in front of the API with the managed common rule set
        const waf = new cdk.aws_wafv2.CfnWebACL(this, "est-api-waf" + id, {
            defaultAction: {
                allow: {}
            },
            rules: [
                {
                    name: "AWSManagedRulesCommonRuleSet",
                    priority: 1,
                    statement: {
                        managedRuleGroupStatement: {
                            vendorName: "AWS",
                            name: "AWSManagedRulesCommonRuleSet"
                        }
                    },
                    overrideAction: {
                        none: {}
                    },
                    visibilityConfig: {
                        cloudWatchMetricsEnabled: true,
                        metricName: "EST-SERVER-WAF-CRS",
                        sampledRequestsEnabled: true
                    }
                }
            ],
            scope: "REGIONAL",
            visibilityConfig: {
                cloudWatchMetricsEnabled: true,
                metricName: "EST-SERVER-WAF",
                sampledRequestsEnabled: true
            }
        });

        // Attach WAF to the API
        const association = new cdk.aws_wafv2.CfnWebACLAssociation(this, "est-api-waf-association" + id, {
            resourceArn: this.api.deploymentStage.stageArn,
            webAclArn: waf.attrArn,
        });

        // Suppress acceptable CDK-NAG errors and warnings
        NagSuppressions.addResourceSuppressions(
            this.api,
            [
                {
                    id: "AwsSolutions-IAM4",
                    reason: "Managed policy is used by CDK when creating the API CloudWatch role",
                },
            ],
            true
        );

        // Stack outputs
        new cdk.CfnOutput(this, "EST Server API URL", {
            exportName: "EST-Server-API-URL-base",
            key: "ESTServerAPIBaseURL",
            value: this.api.url
        });

    }
}

