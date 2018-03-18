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
    printHex
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
        if (asn1.offset === (-1)) {
            throw new Error("Error parsing ASN.1");
        }

        this._cert = new PkijsCertificate({ schema: asn1.result });
    }

    verify() {
        var issuerSerial = this.getIssuer();
        var issuerCert = CertManager.getCertBySerial(issuerSerial);
        var _issuerCert = issuerCert ? issuerCert._cert : undefined;
        return this._cert.verify(_issuerCert).catch((err) => {
            // who the hell throws a string?
            if (typeof err === "string") {
                err = new Error(err);
            }

            return Promise.reject(err);
        });
    }

    getPublicKey() {
        console.log("certificate getPublicKey");
    }

    getIssuer() {
        return this._cert.issuer.typesAndValues[0].value.valueBlock.value;
    }

    getSerial() {
        return this._cert.subject.typesAndValues[0].value.valueBlock.value;
    }

    getCertVersion() {

    }

    getExtensions() {
        for (let ext of this._cert.extensions) {
            // console.log("EXT", ext);
            console.log("RESOLVED", resolveOid(ext.extnID, ext.extnValue));
            // extnID: '2.5.29.15'
            // critical: true
            // extnValue: ...
            // parsedValue: ...
            // parsedValue: BasicConstraints { cA: true, pathLenConstraint: 0 } }
        }
    }
}

function resolveOid(id, value) {
    var ret = {
        id,
        value
    };

    var v;
    switch (id) {
        case "1.3.6.1.4.1.45724.2.1.1":
            ret.id = "fidoU2FTransports";
            v = value.valueBlock.valueHex;
            printHex("fidoU2FTransports", v);
            v = asn1js.fromBER(v);
            console.log("v", v);

            // console.log("VALUE:", v);
            return ret;
        case "1.3.6.1.4.1.41482.2":
            ret.id = "yubicoDeviceId";
            v = value.valueBlock.valueHex;
            printHex("yubicoDeviceId", v);
            return ret;
        default:
            return ret;
    }
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
        return [...certMap].map((kv) => kv[0]);
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
    CertManager
};