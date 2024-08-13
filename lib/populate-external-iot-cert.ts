import * as cdk from "aws-cdk-lib";
import {Construct} from "constructs";
import * as path from "node:path";
import {EstConfig} from "./interfaces";
import {aws_s3_deployment as s3dep} from "aws-cdk-lib";


export interface PopulateExternalIotCertificateProps {
    estConfig: EstConfig;
    encryptionKey: cdk.aws_kms.Key;
    accessLogsBucket: cdk.aws_s3.Bucket;
}

export class PopulateExternalIotCertificate extends Construct {
    public readonly iotProvisioningBucket: cdk.aws_s3.Bucket;
    public readonly iotCaCertS3Key: string = "";
    public readonly iotCaPKeyS3Key: string = "";
    public readonly registerExternalCa: Boolean;

    constructor(scope: Construct, id: string, props: PopulateExternalIotCertificateProps) {
        super(scope, id);

        // A few constants
        const estConfig = props.estConfig;
        const encryptionKey = props.encryptionKey;
        const accessLogsBucket = props.accessLogsBucket;

        // Create an S3 Bucket and transfer the IoT CA Certificate file so Lambda can provision it
        this.registerExternalCa = Boolean(estConfig.DeploymentOptions.iotCoreCaCertificatePath) &&
            Boolean(estConfig.DeploymentOptions.configureJITP);

        // Create S3 Bucket for "provisioning" of the IoT CA Certificate
        const bucketNamePrefix = "est-iot-provisioning"
        this.iotProvisioningBucket = new cdk.aws_s3.Bucket(this, bucketNamePrefix, {
            versioned: false,
            encryption: cdk.aws_s3.BucketEncryption.KMS,
            encryptionKey: encryptionKey,
            publicReadAccess: false,
            blockPublicAccess: cdk.aws_s3.BlockPublicAccess.BLOCK_ALL,
            objectOwnership: cdk.aws_s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            serverAccessLogsBucket: accessLogsBucket,
            serverAccessLogsPrefix: bucketNamePrefix + '/',
            enforceSSL: true,
            removalPolicy: cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
        });

        if (this.registerExternalCa) {
            // Copy to S3 the user-provider CA Certificate
            const destinationPrefix = "iot-ca-cert/";
            const full_cert_path = path.parse(path.resolve(estConfig.DeploymentOptions.iotCoreCaCertificatePath));

            let sources: s3dep.ISource[] = [s3dep.Source.asset(full_cert_path.dir, {exclude: ["**", "!" + full_cert_path.base]})];

            this.iotCaCertS3Key = destinationPrefix + full_cert_path.base

            if (Boolean(estConfig.DeploymentOptions.iotCoreCaPrivateKeyPath)) {
                const full_key_path = path.parse(path.resolve(estConfig.DeploymentOptions.iotCoreCaPrivateKeyPath));
                sources.push(s3dep.Source.asset(full_key_path.dir, {exclude: ["**", "!" + full_key_path.base]}));
                this.iotCaPKeyS3Key = destinationPrefix + full_key_path.base
            }
            const populate = new s3dep.BucketDeployment(this, "populate-iotca", {
                sources: sources,
                destinationBucket: this.iotProvisioningBucket,
                destinationKeyPrefix: destinationPrefix,
                prune: false,
            });
        }
        new cdk.CfnOutput(this, "IoT Provisioning Bucket", {
            exportName: "EST-Server-iot-provisioning-bucket",
            key: "ESTServerIotProvisioningBucketArn",
            value: this.iotProvisioningBucket.bucketArn,
        });

    }
}