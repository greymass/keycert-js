import {ProgressCallback} from 'eosio-key-encryption'
import {GenerationArguments, KeyCertificate, KeyCertificateType} from './key-certificate'

export async function generate(args: GenerationArguments, progress?: ProgressCallback) {
    return KeyCertificate.generate(args, progress)
}

export async function decrypt(
    cert: KeyCertificateType,
    encryptionWords: string[],
    progress?: ProgressCallback
) {
    const c = KeyCertificate.from(cert)
    const privateKey = await c.decrypt(encryptionWords, progress)
    return {privateKey, account: c.account, chainId: c.chainId}
}

export * from './key-certificate'
