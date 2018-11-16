const { Buffer } = require('buffer')
const Hash = require('./crypto/hash')
const Base58Check = require('./encoding/base58check.js')

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
const getMultiSignAddress = pubKey => getAddressBase(pubKey, 'ELA_MULTISIG')

module.exports = {
    toCode,
    getAddress,
    getDid,
    getMultiSignAddress,
}
