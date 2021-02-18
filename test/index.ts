import {strict as assert} from 'assert'
import 'mocha'

import {KeyCertificate} from '../src/key-certificate'

suite('KeyCertificate', function () {
    this.timeout(60 * 1000)

    test('decode', function () {
        const cert = KeyCertificate.from(
            'anchorcert://KgKgBT5ajPc6VroP2hHk2S4COKSiqnT8z0bVqRB0aEAAJANs0sSmSwAAAACAqyanAER8IsLg2SvYygVCJ1oC8OBfv4IQnP2lL1ygTly0bkvLpJbOVL4'
        )
        assert(
            cert.equals({
                chainId: '2a02a0053e5a8cf73a56ba0fda11e4d92e0238a4a2aa74fccf46d5a910746840',
                account: {actor: 'dingdong.gm', permission: 'owner'},
                key: 'SEC_K1_G28QZY99rSND9TEpXjKWQVfwVFDhrew1u7ZQaTjW5PuvYCFgoWs7ojTE',
            })
        )
        assert(
            cert.equals({
                chainId: '2a02a0053e5a8cf73a56ba0fda11e4d92e0238a4a2aa74fccf46d5a910746840',
                account: {actor: 'dingdong.gm', permission: 'owner'},
                key: [
                    'abandon',
                    'captain',
                    'vacuum',
                    'flame',
                    'this',
                    'sing',
                    'wage',
                    'neglect',
                    'feature',
                    'beauty',
                    'gym',
                    'fun',
                    'theory',
                    'worth',
                    'they',
                    'cancel',
                    'sound',
                    'spoon',
                    'runway',
                    'neglect',
                    'exact',
                    'toss',
                    'breeze',
                    'nurse',
                    'ripple',
                    'enter',
                    'deer',
                    'oak',
                ],
            })
        )
    })

    test('encode', function () {
        const cert = KeyCertificate.from({
            chainId: '2a02a0053e5a8cf73a56ba0fda11e4d92e0238a4a2aa74fccf46d5a910746840',
            account: {actor: 'dingdong.gm', permission: 'owner'},
            key: 'SEC_K1_G28QZY99rSND9TEpXjKWQVfwVFDhrew1u7ZQaTjW5PuvYCFgoWs7ojTE',
        })
        assert.equal(
            cert.toString(),
            'anchorcert:KgKgBT5ajPc6VroP2hHk2S4COKSiqnT8z0bVqRB0aEAAJANs0sSmSwAAAACAqyanAER8IsLg2SvYygVCJ1oC8OBfv4IQnP2lL1ygTly0bkvLpJbOVL4'
        )
        assert.deepEqual(cert.toMnemonic(), {
            chainId: '2a02a0053e5a8cf73a56ba0fda11e4d92e0238a4a2aa74fccf46d5a910746840',
            account: {actor: 'dingdong.gm', permission: 'owner'},
            key: [
                'abandon',
                'captain',
                'vacuum',
                'flame',
                'this',
                'sing',
                'wage',
                'neglect',
                'feature',
                'beauty',
                'gym',
                'fun',
                'theory',
                'worth',
                'they',
                'cancel',
                'sound',
                'spoon',
                'runway',
                'neglect',
                'exact',
                'toss',
                'breeze',
                'nurse',
                'ripple',
                'enter',
                'deer',
                'oak',
            ],
        })
    })

    test('decrypt', async function () {
        this.slow(5 * 1000)

        const cert = KeyCertificate.from(
            'anchorcert:KgKgBT5ajPc6VroP2hHk2S4COKSiqnT8z0bVqRB0aEAAJANs0sSmSwAAAACAqyanAER8IsLg2SvYygVCJ1oC8OBfv4IQnP2lL1ygTly0bkvLpJbOVL4'
        )
        const privateKey = await cert.decrypt([
            'pepper',
            'craft',
            'chat',
            'march',
            'slim',
            'exchange',
        ])
        assert.equal(String(privateKey), 'PVT_K1_zVFeDTSxD6KDCjQomkzZMdB5AiaR3EnCZLrxmsx5tDzH937km')
        assert.equal(privateKey.toWif(), '5JomqKfYXQn5aDb1T1Df5c6kPfzdnYuKW1d868pdBxjs9quS1xE')

        await assert.rejects(
            () => cert.decrypt(['this', 'sing', 'wage', 'gym', 'deer']),
            /Expected 6/
        )
        await assert.rejects(
            () => cert.decrypt(['this', 'sing', 'wage', 'gym', 'deer', 'pancetta']),
            /Unknown word: pancetta/
        )
        await assert.rejects(
            () => cert.decrypt(['this', 'sing', 'wage', 'gym', 'deer', 'oak']),
            /Invalid password/
        )
    })

    test('generate', async function () {
        this.slow(5 * 1000)

        const {cert, encryptionWords} = await KeyCertificate.generate({
            chainId: '2a02a0053e5a8cf73a56ba0fda11e4d92e0238a4a2aa74fccf46d5a910746840',
            account: {actor: 'dingdong.gm', permission: 'owner'},
            privateKey: 'PVT_K1_zVFeDTSxD6KDCjQomkzZMdB5AiaR3EnCZLrxmsx5tDzH937km',
            encryptionWords: ['pepper', 'craft', 'chat', 'march', 'slim', 'exchange'],
            securityLevel: {N: 65536, r: 16, p: 1},
        })
        assert.equal(
            String(cert),
            'anchorcert:KgKgBT5ajPc6VroP2hHk2S4COKSiqnT8z0bVqRB0aEAAJANs0sSmSwAAAACAqyanAER8IsLg2SvYygVCJ1oC8OBfv4IQnP2lL1ygTly0bkvLpJbOVL4'
        )
        assert.deepEqual(encryptionWords, ['pepper', 'craft', 'chat', 'march', 'slim', 'exchange'])
    })
})

suite('misc', function () {
    test('random words', function () {
        this.slow(2 * 1000)
        for (let i = 0; i < 4096; i++) {
            const words = KeyCertificate.randomEncryptionWords()
            assert.equal(words.length, 6)
            assert.deepEqual(
                words.filter((v, i, a) => a.indexOf(v) === i),
                words
            )
        }
    })
})
