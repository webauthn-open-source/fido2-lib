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

    getExtensions() {
        var ret = new Map();

        if (this._cert.extensions === undefined) return ret;

        for (let ext of this._cert.extensions) {

            var kv;
            try {
                kv = resolveOid(ext.extnID, decodeValue(ext.extnValue.valueBlock));
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
    var ret = {
        id,
        value
    };

    switch (id) {
        case "1.3.6.1.4.1.45724.2.1.1":
            ret.id = "fido-u2f-transports";
            ret.value = decodeU2FTransportType(value);
            return ret;
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
        case "2.5.29.14":
            ret.id = "subject-key-identifier";
            // printHex("subject-key-identifier value", ret.value);
            return ret;
        case "2.5.29.19":
            ret.id = "basic-constraints";
            // printHex("basic-constraints value", ret.value);
            return ret;
        case "2.5.29.15":
            ret.id = "key-usage";
            // printHex("key-usage value", ret.value);
            return ret;
        // TODO
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
    if (valueBlock.isHexOnly) {
        return valueBlock.valueHex;
    }

    throw Error("couldn't decode x509 extension");
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
