import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {NagSuppressions} from "cdk-nag";

export class EstServerForAwsIotStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // The code that defines your stack goes here

    // example resource
    // const queue = new sqs.Queue(this, 'EstServerForAwsIotQueue', {
    //   visibilityTimeout: cdk.Duration.seconds(300)
    // });
  }
}
