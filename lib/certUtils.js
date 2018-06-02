"use strict";

require("babel-polyfill"); // TODO: hopefully one day I can replace pkjs with a library that doesn't require babel or babel will no longer be required
const asn1js = require("asn1js");
const pkijs = require("pkijs");
const WebCrypto = require("node-webcrypto-ossl");
const webcrypto = new WebCrypto();
const {
    CryptoEngine,
    Certificate: PkijsCertificate
} = pkijs;
const {
    printHex,
    ab2str
} = require("./utils");

const { coerceToArrayBuffer } = require("./utils");

// install crypto engine in pkijs
pkijs.setEngine("newEngine", webcrypto, new CryptoEngine({
    name: "",
    crypto: webcrypto,
    subtle: webcrypto.subtle
}));

class Certificate {
    constructor(cert) {
        cert = coerceToArrayBuffer(cert, "certificate");
        if (cert.byteLength === 0) {
            throw new Error("cert was empty (0 bytes)");
        }

        let asn1 = asn1js.fromBER(cert);
        if (asn1.offset === -1) {
            throw new Error("error parsing ASN.1");
        }

        this._cert = new PkijsCertificate({ schema: asn1.result });
        this.warning = new Map();
        this.info = new Map();
    }

    verify() {
        var issuerSerial = this.getIssuer();
        var issuerCert = CertManager.getCertBySerial(issuerSerial);
        var _issuerCert = issuerCert ? issuerCert._cert : undefined;
        return this._cert.verify(_issuerCert)
            .catch((err) => {
                // who the hell throws a string?
                if (typeof err === "string") {
                    err = new Error(err);
                }

                return Promise.reject(err);
            });
    }

    getPublicKey() {
        var key;
        return this._cert.getPublicKey()
            .then((k) => {
                key = k;
                return webcrypto.subtle.exportKey("jwk", key);
            });
    }

    getIssuer() {
        return this._cert.issuer.typesAndValues[0].value.valueBlock.value;
    }

    getSerial() {
        return this._cert.subject.typesAndValues[0].value.valueBlock.value;
    }

    getVersion() {
        // x.509 versions:
        // 0 = v1
        // 1 = v2
        // 2 = v3
        return (this._cert.version + 1);
    }

    getSubject() {
        var ret = new Map();
        var subjectItems = this._cert.subject.typesAndValues;
        for (let subject of subjectItems) {
            let kv = resolveOid(subject.type, decodeValue(subject.value.valueBlock));
            ret.set(kv.id, kv.value);
        }

        return ret;
    }

    getExtensions() {
        var ret = new Map();

        if (this._cert.extensions === undefined) return ret;

        for (let ext of this._cert.extensions) {

            var kv;

            let v = ext.parsedValue || ext.extnValue;
            if (v.valueBlock) v = decodeValue(v.valueBlock);
            try {
                kv = resolveOid(ext.extnID, v);
            } catch (err) {
                if (ext.critical === false) {
                    this.warning.set("x509-extension-error", ext.extnID + ": " + err.message);
                    continue;
                } else {
                    throw err;
                }
            }

            ret.set(kv.id, kv.value);
        }

        return ret;
    }
}

function resolveOid(id, value) {
    /* eslint complexity: ["off"] */
    var ret = {
        id,
        value
    };

    // console.log("resolveOid id", id, "value", value);

    switch (id) {
        // FIDO
        case "1.3.6.1.4.1.45724.2.1.1":
            ret.id = "fido-u2f-transports";
            ret.value = decodeU2FTransportType(value);
            return ret;
        case "1.3.6.1.4.1.45724.1.1.4":
            ret.id = "fido-aaguid";
            ret.value = decodeFidoAaguid(value);
            return ret;

        // Subject
        case "2.5.4.6":
            ret.id = "country-name";
            return ret;
        case "2.5.4.10":
            ret.id = "organization-name";
            return ret;
        case "2.5.4.11":
            ret.id = "organizational-unit-name";
            return ret;
        case "2.5.4.3":
            ret.id = "common-name";
            return ret;

        // cert attributes
        case "2.5.29.14":
            ret.id = "subject-key-identifier";
            return ret;
        case "2.5.29.15":
            ret.id = "key-usage";
            ret.value = decodeKeyUsage(value);
            return ret;
        case "2.5.29.19":
            ret.id = "basic-constraints";
            return ret;
        case "2.5.29.35":
            var retMap = new Map();
            ret.id = "authority-key-identifier";
            retMap.set("key-identifier", decodeValue(value.keyIdentifier));
            // TODO: other values
            ret.value = retMap;
            return ret;
        case "2.5.29.32":
            ret.id = "certificate-policies";
            ret.value = decodeCertificatePolicies(value);
            return ret;
        case "1.3.6.1.4.1.311.21.31":
            ret.id = "policy-qualifiers";
            ret.value = decodePolicyQualifiers(value);
            return ret;
        case "2.5.29.37":
            ret.id = "ext-key-usage";
            return ret;
        case "2.5.29.17":
            ret.id = "subject-alt-name";
            return ret;
        case "1.3.6.1.5.5.7.1.1":
            ret.id = "authority-info-access";
            ret.value = resolveOid(value.policyQualifierId, value.qualifier);
            return ret;
        case "1.3.6.1.5.5.7.2.2":
            ret.id = "policy-qualifier";
            ret.value = decodeValue(value.valueBlock);
            return ret;

        // Yubico
        case "1.3.6.1.4.1.41482.2":
            ret.id = "yubico-device-id";
            ret.value = resolveOid(ab2str(value)).id;
            return ret;
        case "1.3.6.1.4.1.41482.1.1":
            ret.id = "Security Key by Yubico";
            return ret;
        case "1.3.6.1.4.1.41482.1.2":
            ret.id = "YubiKey NEO/NEO-n";
            return ret;
        case "1.3.6.1.4.1.41482.1.3":
            ret.id = "YubiKey Plus";
            return ret;
        case "1.3.6.1.4.1.41482.1.4":
            ret.id = "YubiKey Edge";
            return ret;
        case "1.3.6.1.4.1.41482.1.5":
            ret.id = "YubiKey 4/YubiKey 4 Nano";
            return ret;

        // TODO
        // 1.3.6.1.4.1.45724.1.1.4 FIDO AAGUID
        // basic-constraints Yubico FIDO2, ST Micro
        // 2.5.29.35 ST Micro
        // subject-key-identifier ST Micro
        // 1.3.6.1.4.1.41482.3.3 Yubico Firmware version, encoded as 3 bytes, like: 040300 for 4.3.0
        // 1.3.6.1.4.1.41482.3.7 Yubico serial number of the YubiKey, encoded as an integer
        // 1.3.6.1.4.1.41482.3.8 Yubico two bytes, the first encoding pin policy and the second touch policy
            // Pin policy: 01 - never, 02 - once per session, 03 - always
            // Touch policy: 01 - never, 02 - always, 03 - cached for 15s

        default:
            return ret;
    }
}

function decodeValue(valueBlock) {
    var blockType = Object.getPrototypeOf(valueBlock).constructor.name;
    // console.log("blockType", blockType);
    // console.log("valueBlock", valueBlock);
    switch (blockType) {
        case "LocalOctetStringValueBlock":
            return valueBlock.valueHex;
        case "LocalUtf8StringValueBlock":
            return valueBlock.value;
        case "LocalSimpleStringValueBlock":
            return valueBlock.value;
        case "OctetString":
            return valueBlock.valueBlock.valueHex;
        case "LocalBitStringValueBlock":
            return new Uint8Array(valueBlock.valueHex)[0];
        case "LocalBmpStringValueBlock":
            console.log("LocalBmpStringValueBlock.valueBlock", valueBlock);
            return valueBlock.value;
        case "LocalConstructedValueBlock":
            console.log("valueBlock.value", valueBlock.value);
            if (typeof valueBlock === "object" &&
                Array.isArray(valueBlock.value)) {
                return valueBlock.value.map((v) => decodeValue(v));
            }
            return valueBlock;
        case "BmpString":
            console.log("BmpString", valueBlock);
            return decodeValue(valueBlock.valueBlock);
        default:
            throw new TypeError("unknown value type when decoding certificate: " + blockType);
    }
}

function decodeU2FTransportType(u2fRawTransports) {
    if (!(u2fRawTransports instanceof ArrayBuffer) ||
                u2fRawTransports.byteLength !== 4) {
        throw new Error("u2fRawTransports was malformatted");
    }
    u2fRawTransports = new Uint8Array(u2fRawTransports);
    if (u2fRawTransports[0] !== 0x03 ||
                u2fRawTransports[1] !== 0x02 ||
                u2fRawTransports[2] > 7) {
        throw new Error("u2fRawTransports had unknown data");
    }
    var bitLen = u2fRawTransports[2];
    var bitCount = 8 - bitLen - 1;
    var type = (u2fRawTransports[3] >> bitLen);

    var ret = new Set();
    for (let i = bitCount; i >= 0; i--) {
        // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-authenticator-transports-extension-v1.2-ps-20170411.html
        if (type & 0x1) switch (i) {
            case 0:
                ret.add("bluetooth-classic");
                break;
            case 1:
                ret.add("bluetooth-low-energy");
                break;
            case 2:
                ret.add("usb");
                break;
            case 3:
                ret.add("nfc");
                break;
            case 4:
                ret.add("usb-internal");
                break;
            default:
                throw new Error("unknown U2F transport type: " + type);
            }
        type >>= 1;
    }
    return ret;
}

function decodeKeyUsage(value) {
    if (typeof value !== "number") {
        throw new Error("certificate: expected 'keyUsage' value to be number");
    }

    var retSet = new Set();

    if (value & 0x80) retSet.add("digitalSignature");
    if (value & 0x40) retSet.add("contentCommitment");
    if (value & 0x20) retSet.add("keyEncipherment");
    if (value & 0x10) retSet.add("dataEncipherment");
    if (value & 0x08) retSet.add("keyAgreement");
    if (value & 0x04) retSet.add("keyCertSign");
    if (value & 0x02) retSet.add("cRLSign");
    if (value & 0x01) retSet.add("encipherOnly");
    if (value & 0x01) retSet.add("decipherOnly");


    return retSet;
}

function decodeFidoAaguid(value) {
    if (!(value instanceof ArrayBuffer)) {
        throw new Error("expected AAGUID to be ArrayBuffer");
    }

    if (value.byteLength !== 18) {
        throw new Error("AAGUID ASN.1 was wrong size. Should be 18, got " + value.byteLength);
    }

    var aaguidBuf = new Uint8Array(value);
    if (aaguidBuf[0] !== 0x04) {
        throw new Error("AAGUID ASN.1 should start with 0x04 (octet string)");
    }

    if (aaguidBuf[1] !== 0x10) {
        throw new Error("AAGUID ASN.1 should have length 16");
    }

    return aaguidBuf.buffer.slice(2);
}

function decodeCertificatePolicies(value) {
    if (value && Array.isArray(value.certificatePolicies)) {
        value = value.certificatePolicies.map((policy) => resolveOid(value.certificatePolicies[0].policyIdentifier, value.certificatePolicies[0].policyQualifiers));
    }

    return value;
}

function decodePolicyQualifiers(value) {
    if (value && Array.isArray(value)) {
        value = value.map((qual) => resolveOid(qual.policyQualifierId, qual.qualifier));
    }

    return value;
}


const certMap = new Map();
class CertManager {
    static addCert(certBuf) {
        var cert = new Certificate(certBuf);
        var serial = cert.getSerial();
        certMap.set(serial, cert);

        return true;
    }

    static getCerts() {
        return new Map([...certMap]);
    }

    static getCertBySerial(serial) {
        return certMap.get(serial);
    }

    static removeAll() {
        certMap.clear();
    }
}

module.exports = {
    Certificate,
    CertManager,
    helpers: {
        resolveOid
    }
};
