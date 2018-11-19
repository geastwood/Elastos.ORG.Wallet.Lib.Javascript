const { Buffer } = require('buffer')
const Hash = require('./crypto/hash')
const bn = require('./BigNumber')
const Base58Check = require('./encoding/base58check.js')
const PublicKey = require('./PublicKey')

const signTypeMap = {
    ELA_STANDARD: { type: 0xac, address: 0x21 },
    ELA_MULTISIG: { type: 0xae, address: 0x12 },
    ELA_CROSSCHAIN: { type: 0xaf, address: 0x48 },
    ELA_IDCHAIN: { type: 0xad, address: 0x67 },
    ELA_DESTROY: {
        type: 0xaa,
        address: 0x0,
    },
}

// a, b => public key
const sortBigNumber = (a, b) => {
    const bBigInt = bn.fromBuffer(Buffer.from(a, 'hex').slice(1))
    const aBigInt = bn.fromBuffer(Buffer.from(b, 'hex').slice(1))
    return bBigInt.gt(aBigInt)
}

const toCode = (pubKeyBuf, signType) => {
    return Buffer.concat([Buffer.from([0x21]), pubKeyBuf, Buffer.from([signType])])
}

const getAddressBase = (pubKey, signType) => {
    const pubKeyBuf = new Buffer(pubKey, 'hex')
    const code = toCode(pubKeyBuf, signTypeMap[signType].type)
    const hashBuf = Hash.sha256ripemd160(code)
    const programHashBuf = Buffer.concat([Buffer.from([signTypeMap[signType].address]), hashBuf])

    return Base58Check.encode(programHashBuf)
}

const getAddress = pubKey => getAddressBase(pubKey, 'ELA_STANDARD')
const getDid = pubKey => getAddressBase(pubKey, 'ELA_IDCHAIN')

const getMultiSignAddress = (pubKeys, requiredCount) => {
    const keysCount = pubKeys.length

    const sortedPubKeys = pubKeys.sort(sortBigNumber)

    let buf = Buffer.from([0x51 + requiredCount - 1])

    sortedPubKeys.forEach(pub => {
        const pubInHex = Buffer.from(pub, 'hex')
        buf = Buffer.concat([buf, Buffer.from([pubInHex.length]), pubInHex])
    })

    buf = Buffer.concat([buf, Buffer.from([0x51 + keysCount - 1, 0xae])])

    const hashBuf = Hash.sha256ripemd160(buf)
    const programHashBuf = Buffer.concat([Buffer.from([0x12]), hashBuf])

    return Base58Check.encode(programHashBuf)
}

module.exports = {
    toCode,
    getAddress,
    getDid,
    getMultiSignAddress,
}
