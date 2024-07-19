import * as cdk from "aws-cdk-lib";
import {Construct} from "constructs";

import {NagSuppressions} from "cdk-nag";
import * as fs from 'node:fs';
import * as path from "node:path";
import {EstConfig, provisioningTemplate} from "./interfaces";
import {IotRootCaProps} from "./iot-root-ca-construct";

export interface ProvisioningTemplateProps {
    estConfig: EstConfig;
}

export class ProvisioningTemplate extends Construct {
    constructor(scope: Construct, id: string, props: ProvisioningTemplateProps) {
        super(scope, id);

        const estConfig = props.estConfig;
        let provTemplateArn: string
        // Configure JITP if enabled
        if (estConfig.DeploymentOptions.configureJITP) {
            // Load the IoT Policy from the json file and replace placeholders by their value
            let policy_str = fs.readFileSync(path.resolve(estConfig.Properties.iotPolicyPath), 'utf-8')
            const re_a = /<ACCOUNT_ID>/gi
            policy_str = policy_str.replace(re_a, cdk.Stack.of(this).account)
            const re_r = /<REGION>/gi
            policy_str = policy_str.replace(re_r, cdk.Stack.of(this).region)
            const policyDoc = JSON.parse(policy_str);

            // Create the IoT Policy
            const iotPolicy = new cdk.aws_iot.CfnPolicy(this, 'IotPolicy', {
                policyName: estConfig.Properties.iotPolicyName,
                policyDocument: policyDoc,
            });
            // Load the IoT Template from the json file
            let template: provisioningTemplate = JSON.parse(fs.readFileSync(path.resolve(estConfig.Properties.iotTemplatePath), 'utf-8'));
            // Add the reference to the IoT Policy if nothing is already in the template
            if (template.Resources.policy.Properties.PolicyDocument == "") {
                template.Resources.policy.Properties.PolicyDocument = iotPolicy.policyName as string
            }

            // Create the Role for automatic devices provisioning
            const registrationRole = new cdk.aws_iam.Role(this, "deviceProvisioningRole", {
                assumedBy: new cdk.aws_iam.ServicePrincipal("iot.amazonaws.com"),
                roleName: "ESTServerDeviceProvisioningRole",
                description: "Role allowing automatic device provisioning from Template aka JITP",
                managedPolicies: [
                    cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSIoTThingsRegistration")
                ]
            });
            NagSuppressions.addResourceSuppressions(
                registrationRole, [
                    {
                        id: 'AwsSolutions-IAM4',
                        reason: 'Device registration policy needs to be open.',
                    },
                ], true
            );

            // Register the CA in IoT Core and enable Just-In-Time Provisioning
            const provTemplate = new cdk.aws_iot.CfnProvisioningTemplate(this, "IoTCoreProvisioningTemplate", {
                description: "EST Server JITP Provisioning Template",
                provisioningRoleArn: registrationRole.roleArn,
                templateBody: JSON.stringify(template),
                templateName: estConfig.Properties.iotTemplateName,
                templateType: "JITP",
                enabled: true,
            });
            provTemplateArn = provTemplate.attrTemplateArn
        }
        else {
            provTemplateArn = "Skipped"
        }
        new cdk.CfnOutput(this, "Provisioning Template ARN", {
            exportName: "EST-Server-Provisioning-Template-ARN",
            key: "ESTProvisioningTemplateArn",
            value: provTemplateArn,
        });
    }
}
