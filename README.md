@greymass/keycert
=================

Anchor key certificate encoding and decoding library for JavaScript.

## Installation

The `@greymass/keycert` package is distributed as a module on [npm](https://www.npmjs.com/package/@greymass/keycert).

```
yarn add @greymass/keycert
# or
npm install --save @greymass/keycert
```

## Usage

```ts
import {generate, decrypt} from '@greymass/keycert'

generate({
    privateKey: '5KYnSy2U9y8Ua1AbWYDQxuEa6Smc9WPtBNsQ6TZRPsZBqFB3AqS',
    account: {actor: 'foobar', permission: 'owner'},
    chainId: '2a02a0053e5a8cf73a56ba0fda11e4d92e0238a4a2aa74fccf46d5a910746840',
}).then(({cert, encryptionWords}) => {
    console.log(String(cert)) // anchorcert:KgKgBT5ajPc6VroP2hHk2S4COKSiqnT8z0bVqRB0aEAAAAAAXHMoXQAAAACAqyanACTh3X6hzLZx-dGsO0swCpi2WDg_Xd8mSK-C2kY_gygHpHe8jNk
    console.log(encryptionWords) // [ 'number', 'arrow', 'twenty', 'permit', 'much', 'caution' ]
})

decrypt(
    'anchorcert:KgKgBT5ajPc6VroP2hHk2S4COKSiqnT8z0bVqRB0aEAAAAAAXHMoXQAAAACAqyanACTh3X6hzLZx-dGsO0swCpi2WDg_Xd8mSK-C2kY_gygHpHe8jNk',
    ['number', 'arrow', 'twenty', 'permit', 'much', 'caution']
).then(({chainId, account, privateKey}) => {
    console.log(String(chainId)) // 2a02a0053e5a8cf73a56ba0fda11e4d92e0238a4a2aa74fccf46d5a910746840
    console.log(JSON.stringify(account)) // {"actor": "foobar", "permission": "owner"}
    console.log(privateKey.toWif()) // 5KYnSy2U9y8Ua1AbWYDQxuEa6Smc9WPtBNsQ6TZRPsZBqFB3AqS
})
```

## Developing

You need [Make](https://www.gnu.org/software/make/), [node.js](https://nodejs.org/en/) and [yarn](https://classic.yarnpkg.com/en/docs/install) installed.

Clone the repository and run `make` to checkout all dependencies and build the project. See the [Makefile](./Makefile) for other useful targets. Before submitting a pull request make sure to run `make lint`.

---

Made with ☕️ & ❤️ by [Greymass](https://greymass.com), if you find this useful please consider [supporting us](https://greymass.com/support-us).
