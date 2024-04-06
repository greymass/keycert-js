import {
    EncryptedPrivateKey,
    EncryptedPrivateKeyType,
    ProgressCallback,
    SecurityLevelType,
} from '@greymass/antelope-key-encryption'
import {Base64u, ChainId, ChainIdType} from '@wharfkit/signing-request'
import {
    Checksum256,
    isInstanceOf,
    PermissionLevel,
    PermissionLevelType,
    PrivateKey,
    PrivateKeyType,
    Serializer,
    Struct,
    UInt32,
} from '@wharfkit/antelope'

import mnemonic, {wordlist} from './mnemonic'
import PRNG from './prng'

export interface GenerationArguments {
    /** Chain id where account exists. */
    chainId: ChainIdType
    /** Account name and permission. */
    account: PermissionLevelType
    /** The private key that can sign for given account permission. */
    privateKey: PrivateKeyType
    /** Security level, how hard the key will be to brute-force. */
    securityLevel?: SecurityLevelType
    /** Pre-determined encryption keywords, if omitted they will be randomly generated. */
    encryptionWords?: string[]
    /** Whether to derive the encryption words from the private key, incompatible with the encryptionWords option. */
    deterministicWords?: boolean
}

export interface GenerationResult {
    /** The resulting key certificate instance. */
    cert: KeyCertificate
    /** The encryption words that encrypts the private key in the certificate. */
    encryptionWords: string[]
}

export type KeyCertificateType =
    | KeyCertificate
    | string
    | {chainId: ChainIdType; account: PermissionLevelType; key: EncryptedPrivateKeyType | string[]}

@Struct.type('key_certificate')
export class KeyCertificate extends Struct {
    @Struct.field(ChainId) chainId!: ChainId
    @Struct.field(PermissionLevel) account!: PermissionLevel
    @Struct.field(EncryptedPrivateKey) key!: EncryptedPrivateKey

    /** Create a new KeyCertificate instance. */
    static from(value: KeyCertificateType) {
        if (isInstanceOf(value, this)) {
            return value
        }
        if (typeof value === 'string') {
            return this.fromString(value)
        }
        if (
            value.key &&
            Array.isArray(value.key) &&
            value.key.every((v) => typeof v === 'string')
        ) {
            return super.from({
                ...value,
                key: Serializer.decode({
                    data: mnemonic.decode(value.key),
                    type: EncryptedPrivateKey,
                }),
            }) as KeyCertificate
        }
        return super.from(value) as KeyCertificate
    }

    /** Create a new KeyCertificate instance from a anchorcert: string. */
    static fromString(string: string) {
        if (!string.startsWith('anchorcert:')) {
            throw new Error('Not an anchor key certificate string')
        }
        string = string.slice(11)
        while (string[0] === '/') {
            string = string.slice(1)
        }
        const data = Base64u.decode(string)
        return Serializer.decode({data, type: this})
    }

    /** Draw 6 encryption words from the wordlist. */
    static randomEncryptionWords(rng?: () => number) {
        const rv: string[] = []
        if (!rng) {
            rng = () => UInt32.random().toNumber()
        }
        while (rv.length < 6) {
            const word = wordlist[rng() % 2048]
            if (rv.includes(word)) {
                continue
            }
            rv.push(word)
        }
        return rv
    }

    /** Get 6 encryption words for a given private key. */
    static deterministicEncryptionWords(key: PrivateKeyType) {
        const seed = new Uint32Array(
            Checksum256.hash(PrivateKey.from(key).data).array.buffer
        ).slice(0, 4)
        return this.randomEncryptionWords(PRNG(seed))
    }

    /** Generate a new key certificate. */
    static async generate(
        args: GenerationArguments,
        progress?: ProgressCallback
    ): Promise<GenerationResult> {
        let encryptionWords: string[]
        if (args.deterministicWords) {
            if (args.encryptionWords) {
                throw new Error('Cannot use deterministicWords and encryptionWords together')
            }
            encryptionWords = this.deterministicEncryptionWords(args.privateKey)
        } else {
            encryptionWords = args.encryptionWords || this.randomEncryptionWords()
        }
        if (encryptionWords.length !== 6) {
            throw new Error(`Expected 6 encryption words, got ${encryptionWords.length || 0}`)
        }
        const password = mnemonic.decode(encryptionWords)
        const key = await EncryptedPrivateKey.encrypt(
            args.privateKey,
            password,
            progress,
            args.securityLevel
        )
        const cert = this.from({
            chainId: args.chainId,
            account: args.account,
            key,
        })
        return {cert, encryptionWords}
    }

    /** The encrypted private key as a list of base2048 words. */
    get encryptedPrivateKeyMnemonic() {
        return mnemonic.encode(Serializer.encode({object: this.key}).array)
    }

    /**
     * Encode this certificate to a JavaScript object containing chain id,
     * account permission and the encrypted private key as mnemonic words.
     */
    toMnemonic() {
        return Serializer.objectify({
            chainId: this.chainId,
            account: this.account,
            key: this.encryptedPrivateKeyMnemonic,
        }) as {chainId: string; account: {actor: string; permission: string}; key: string[]}
    }

    /** Encode this certificate to a anchorcert: string for embedding in QR code. */
    toString() {
        return 'anchorcert:' + Base64u.encode(Serializer.encode({object: this}).array)
    }

    /** Decrypt the private key using the 6 encryption keywords. */
    async decrypt(key: string[], progress?: ProgressCallback) {
        if (key.length !== 6) {
            throw new Error(`Expected 6 encryption words, got ${key.length || 0}`)
        }
        const password = mnemonic.decode(key)
        return this.key.decrypt(password, progress)
    }
}
