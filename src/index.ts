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
    return KeyCertificate.from(cert).decrypt(encryptionWords, progress)
}

export * from './key-certificate'
