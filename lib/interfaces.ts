
export interface EstConfig {
    // Interface for the .configuration file
    Properties: {
        // EST Service
        apiCustomDomainName: NonNullable<string>
        apiCertificateArn: NonNullable<string>
        apiOwnershipVerificationCertificateArn: NonNullable<string>
        // EST mTLS server side
        estMtlsCaSecretsName: NonNullable<string>
        estMtlsCaCertValidity: NonNullable<number>
        // EST mTLS client side
        estMtlsClientSecretsName: NonNullable<string>
        estMtlsClientPfxSecretName: NonNullable<string>
        estMtlsClientCertValidity: NonNullable<number>
        // IoT Core
        iotCoreEstCaCertSecretName: NonNullable<string>
        iotCoreEstCaKeySecretName: NonNullable<string>
        iotCoreEstCaValidityYears: NonNullable<number>
        iotTemplatePath: NonNullable<string>
        iotTemplateName: NonNullable<string> // 36 characters max !!
        iotPolicyPath: NonNullable<string>
        iotPolicyName: NonNullable<string>
        // Lambda functions (applies to all, can be modified individually with function environment variable)
        lambdaLoggerLevel: NonNullable<string>
    },
    DeploymentOptions: {
        // mTLS Truststore certificate chain - generated if ""
        mTlsTruststoreCertificatesChainFile: NonNullable<string>
        // Path to the IoT Core CA Certificate if provided or ""
        iotCoreCaCertificatePath: NonNullable<string>
        // Path to the IoT Core CA Private Key if provided or ""
        iotCoreCaPrivateKeyPath: NonNullable<string>
        // Generates Iot Core self-signed certificate and private key for signing CSR
        // Ignored if iotCoreCaCertificatePath (just above) is not ""
        generateIotCaCertificate: NonNullable<boolean>
        // If 'true' IoT Core will be configured for JITP
        configureJITP: NonNullable<boolean>
    }
}

export interface provisioningTemplate {
    // Interface for the IoT Core Provisioning Template
    "Parameters": {
      "AWS::IoT::Certificate::CommonName": {
         "Type": String
      },
      "AWS::IoT::Certificate::SerialNumber": {
         "Type": String
      },
      "AWS::IoT::Certificate::Country": {
         "Type": String
      },
      "AWS::IoT::Certificate::Id": {
         "Type": String
      }
    },
    "Resources": {
      "thing": {
         "Type": string,
         "Properties": {
            "ThingName": {
               "Ref": string
            },
            "AttributePayload": {
               "version": string,
               "serialNumber": {
                  "Ref": string
               }
            }
         }
      },
      "certificate": {
         "Type": string,
         "Properties": {
            "CertificateId": {
               "Ref": string
            },
            "Status": string
         }
      },
      "policy": {
         "Type": string,
         "Properties": {
            "PolicyDocument": string
         }
      }
    }
}
