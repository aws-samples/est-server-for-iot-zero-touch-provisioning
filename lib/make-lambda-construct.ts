import * as python from "@aws-cdk/aws-lambda-python-alpha";
import {Construct} from "constructs";
import * as cdk from "aws-cdk-lib";
import {NagSuppressions} from "cdk-nag";

export interface MakeLambdaProps {
    encryptionKey: cdk.aws_kms.Key;
    entry: string;
    layers:  cdk.aws_lambda.ILayerVersion[];
    environment: { [key: string]: string };
    timeout: cdk.Duration;
}

export class MakeLambda extends Construct {
    public readonly lambda: python.PythonFunction;
    public readonly role: cdk.aws_iam.Role;
    constructor(scope: Construct, id: string, props: MakeLambdaProps) {
        super(scope, id);

        const encryptionKey = props.encryptionKey;
        const entry = props.entry;
        const layers = props.layers;
        const environment = props.environment;
        const timeout = props.timeout;

        // Create a Log group
        const logGroup = new cdk.aws_logs.LogGroup(this, id + "_lg", {
            logGroupName: "/aws/lambda/est-server/" + id,
            retention: cdk.aws_logs.RetentionDays.ONE_MONTH,
            removalPolicy: cdk.RemovalPolicy.RETAIN,
            encryptionKey: encryptionKey,
        });

        // Policy statement to access the log group
        const policyStatement = new cdk.aws_iam.PolicyStatement({
            effect: cdk.aws_iam.Effect.ALLOW,
            actions: [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            resources: [`${logGroup.logGroupArn}`]
        });


        this.role = new cdk.aws_iam.Role(this, id + "_rl", {
            assumedBy: new cdk.aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            roleName: "ESTServerLambdaRole_" + id,
            description: "Role for EST Server Lambda " + id + "_ld",
            inlinePolicies: {
                uploadResponseLambdaPolicy: new cdk.aws_iam.PolicyDocument({
                    statements: [policyStatement],
                })
            }
        });

        encryptionKey.grantEncryptDecrypt(this.role);

        // And the Lambda
        this.lambda = new python.PythonFunction(this, "ld_" + id, {
            entry: entry,
            runtime: cdk.aws_lambda.Runtime.PYTHON_3_12,
            handler: "lambda_handler",
            index: "lambda.py",
            layers: layers,
            role: this.role,
            architecture: cdk.aws_lambda.Architecture.X86_64,
            environmentEncryption: encryptionKey,
            environment: environment,
            timeout: timeout,
            logGroup: logGroup,
        });

        // Suppress CDK-NAG error for wildcard to GenerateDataKey and ReEncrypt
        NagSuppressions.addResourceSuppressions(
            this.role, [
                {
                    id: 'AwsSolutions-IAM5',
                    reason: 'The policy is generated automatically by CDK grantEncryptDecrypt.',
                },
            ], true
        )
    }
}