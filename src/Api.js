const { HDPrivateKey, HDPublicKey, PublicKey, PrivateKey, crypto } = require('bitcore-lib')
const { Buffer } = require('buffer')
const { ecdsa, hash } = crypto
const { getSeedFromMnemonic } = require('./Mnemonic')
const { getAddress } = require('./Address')
const rs = require('jsrsasign')

const uncompress = key => {
    var x = key.point.getX()
    var y = key.point.getY()

    var xbuf = x.toBuffer({
        size: 32,
    })

    var ybuf = y.toBuffer({
        size: 32,
    })

    if (!key.compressed) {
        throw new Error('Publick key is not compressed.')
    }

    return Buffer.concat([Buffer.from([0x04]), xbuf, ybuf])
}

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

    return idChain.publicKey
}

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

const sign = (data, prvKey) => {
    var signer = new rs.KJUR.crypto.Signature({ alg: 'SHA256withECDSA' })
    signer.init({ d: prvKey, curve: 'secp256r1' })
    signer.updateString(data)
    var signature = signer.sign()
    return rs.ECDSA.asn1SigToConcatSig(signature) // return a hex string
}

const verify = (data, signature, pubKey) => {
    const pubKeyObj = PublicKey.fromString(pubKey)

    const signer = new rs.KJUR.crypto.Signature({ alg: 'SHA256withECDSA' })
    signer.init({ xy: uncompress(pubKeyObj).toString('hex'), curve: 'secp256r1' })
    signer.updateString(data)

    return signer.verify(rs.ECDSA.concatSigToASN1Sig(signature))
}

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
    sign,
    verify,
}
