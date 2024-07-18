#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { EstServerForAwsIotStack } from '../lib/est-server-for-aws-iot-stack';
import {AwsSolutionsChecks, NagSuppressions} from "cdk-nag";

const app = new cdk.App();
const estStack = new EstServerForAwsIotStack(app, 'EstServerForAwsIotStack', {
  /* If you don't specify 'env', this stack will be environment-agnostic.
   * Account/Region-dependent features and context lookups will not work,
   * but a single synthesized template can be deployed anywhere. */

  /* Uncomment the next line to specialize this stack for the AWS Account
   * and Region that are implied by the current CLI configuration. */
  // env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },

  /* Uncomment the next line if you know exactly what Account and Region you
   * want to deploy the stack to. */
  // env: { account: '123456789012', region: 'us-east-1' },

  /* For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html */
});

// Create an application in AWS Service Catalog
cdk.Tags.of(estStack).add("APPLICATION", "EST Server for AWS IoT")
// Use cdk-nag to inspect the stack for common problems
cdk.Aspects.of(app).add(new AwsSolutionsChecks( {verbose: true} ));
// TODO: Remove when python3.12 builds the Layer without failure
        NagSuppressions.addStackSuppressions(
            estStack,
            [
                {
                    id: "AwsSolutions-L1",
                    reason: "Building layer fails on python3.12",
                }
            ],
            true
        )
