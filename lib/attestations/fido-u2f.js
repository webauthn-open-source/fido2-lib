const {
    printHex,
    coerceToArrayBuffer,
    coerceToBase64
} = require("../utils");



function fidoU2fParseFn(attStmt) {
    var ret = new Map();
    var x5c = attStmt.x5c;
    var sig = attStmt.sig;

    if (!Array.isArray(x5c)) {
        throw new TypeError("expected U2F attestation x5c field to be of type Array");
    }

    if (x5c.length < 1) {
        throw new TypeError("no certificates in U2F x5c field");
    }

    var newX5c = [];
    for (let cert of x5c) {
        cert = coerceToArrayBuffer(cert, "U2F x5c cert");
        newX5c.push(cert);
    }
    // first certificate MUST be the attestation cert
    ret.set("attCert", newX5c.shift());
    // the rest of the certificates (if any) are the certificate chain
    ret.set("x5c", newX5c);

    sig = coerceToArrayBuffer(sig, "U2F signature");
    ret.set("sig", sig);

    return ret;
}

function fidoU2fValidateFn() {
    console.log("fidoU2fValidateFn");
    var x5c = this.authnrData.get("x5c");
    var attCert = this.authnrData.get("attCert");
    var sig = this.authnrData.get("sig");

    console.log("x5c", x5c);
    printHex("attCert", attCert);
    printHex("sig", sig);
    console.log("attCert", coerceToBase64(attCert));

    // validate cert chain
    if (x5c.length > 0) {
        throw new Error("cert chain not validated");
    }
    this.audit.journal.add("x5c");

    // decode attestation cert
    var asn1 = fromBER(attCert);
    var certificate = new Certificate({ schema: asn1.result });

    // https: //fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-authenticator-transports-extension-v1.2-ps-20170411.html
    // cert MUST be x.509v3
}

module.exports = {
    name: "fido-u2f",
    parseFn: fidoU2fParseFn,
    validateFn: fidoU2fValidateFn
};