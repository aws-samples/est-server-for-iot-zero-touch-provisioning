import * as forge from 'node-forge';
import { pki } from 'node-forge';

interface response {
    ca: {
        key: string,
        cert: string
    },
    fingerprint: string
}

export function genCA(bits: number, validity: number, subject: pki.CertificateField[]):  response {

    const keyPair = pki.rsa.generateKeyPair({ bits: bits })

    let cert = pki.createCertificate()
    cert.publicKey = keyPair.publicKey
    //cert.serialNumber = crypto.randomUUID().replace(/-/g, '')

    cert.validity.notBefore = new Date()
    cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1)
    cert.validity.notAfter = new Date()
    // Certificate valid for
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + Math.ceil(validity))

    cert.setSubject(subject)
    cert.setExtensions([{name: 'basicConstraints', CA: true}])
    cert.setIssuer(subject)
    cert.sign(keyPair.privateKey, forge.md.sha256.create())

    return {
        ca: {
            key: pki.privateKeyToPem(keyPair.privateKey),
            cert: pki.certificateToPem(cert)
        },
        fingerprint: forge.util.encode64(
            pki.getPublicKeyFingerprint(keyPair.publicKey, {
                type: 'SubjectPublicKeyInfo',
                md: forge.md.sha256.create(),
                encoding: 'binary'
            })
        )
    }
}