const HDPrivateKey = require('./HDPrivateKey')
const HDPublicKey = require('./HDPublicKey')
const PrivateKey = require('./PrivateKey')
const { getSeedFromMnemonic } = require('./Mnemonic')
const EC = require('elliptic').ec
const ec = new EC('p256', { hash: 'sha256' })

const getMasterPublicKey = seed => {
    const prvKey = HDPrivateKey.fromSeed(seed)
    const parent = new HDPrivateKey(prvKey.xprivkey)

    const multiWallet = parent
        .deriveChild(44, true)
        .deriveChild(0, true)
        .deriveChild(0, true)

    return multiWallet.xpubkey
}

const getIdChainMasterPublicKey = seed => {
    const prvKey = HDPrivateKey.fromSeed(seed)
    const parent = new HDPrivateKey(prvKey.xprivkey)
    const idChain = parent.deriveChild(0, true)

    return idChain
}

const testSeed =
    '5fd595530517ae121ee90ff09e48977c2c07b39a6b51d61148154cc8c4fb086c2ccb27b823cbb2735b886298dc12ccaf321055adee14c0dd4f803bbc53893af3'

// rst pubkey = '0296a25e91434a17b323bdb9c944c96479f07ba06342bf8370ef5f8769f32150b7'
const seed1 = getSeedFromMnemonic('juice corn task still demise bundle east trim glare choose onion scan')
const m = getIdChainMasterPublicKey(seed1.toString('hex'))
console.log(m)

const getDidWallet = (seed, i) => {
    const prvKey = HDPrivateKey.fromSeed(seed)
    const parent = new HDPrivateKey(prvKey.xprivkey)

    const didWallet = parent
        .deriveChild(0, true)
        .deriveChild(0, false)
        .deriveChild(i, false)

    return didWallet
}

const generateIdChainSubPrivateKey = (seed, i) => getDidWallet(seed, i).privateKey
const generateIdChainSubPublicKey = (masterPublicKey, i) => getDidWallet(seed, i).publicKey

const getSingleWallet = seed => {
    const prvKey = HDPrivateKey.fromSeed(seed)
    const parent = new HDPrivateKey(prvKey.xprivkey)
    return parent.deriveChild(1, true).deriveChild(0)
}
const getMultiWallet = (seed, i) => {
    const prvKey = HDPrivateKey.fromSeed(seed)
    const parent = new HDPrivateKey(prvKey.xprivkey)
    return parent
        .deriveChild(44, true)
        .deriveChild(0, true)
        .deriveChild(0, true)
        .deriveChild(0, false)
        .deriveChild(i, false)
}

const getSinglePrivateKey = seed => getSingleWallet(seed).privateKey
const getSinglePublicKey = seed => getSingleWallet(seed).publicKey
const getPublicKeyFromPrivateKey = prvKey => PrivateKey.fromBuffer(prvKey).publicKey
const generateSubPrivateKey = (seed, i) => getMultiWallet(seed, i).privateKey
const generateSubPublicKey = (seed, i) => getMultiWallet(seed, i).publicKey

// ===================== sign example ==========================
const sign = (data, prvKey) => {
    const key = ec.keyFromPrivate(prvKey)
    return ec.sign(data, prvKey)
}
const verify = (data, sig, pubKey) => {
    const pubKeyObj = ec.keyFromPublic(pubKey, 'hex')
    return ec.verify(data, sig, pubKeyObj)
}

const prvKey = '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'
const sig = sign('helloworld', prvKey)

console.log('rst', verify('helloworld', sig, '02924e304a876c9b22256c8210a618ccc9db72d7b92b071c0b7c7041afaabc8368'))
// ============================================================

module.exports = {
    getMasterPublicKey,
    getSinglePrivateKey,
    getSinglePublicKey,
    getPublicKeyFromPrivateKey,
    generateSubPrivateKey,
    generateSubPublicKey,
    getIdChainMasterPublicKey,
    generateIdChainSubPrivateKey,
    generateIdChainSubPublicKey,
}
