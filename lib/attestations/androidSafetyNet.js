/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

"use strict";

const {
    printHex,
    coerceToArrayBuffer,
    coerceToBase64,
    abToBuf,
    abToPem,
    ab2str,
    b64ToJsObject
} = require("../utils");
const crypto = require("crypto");
const {
    CertManager
} = require("../certUtils");
const jose = require("node-jose");

async function androidSafetyNetParseFn(attStmt) {
    var ret = new Map();

    console.log("androidSafetyNetParseFn");
    console.log("attStmt", attStmt);

    ret.set("ver", attStmt.ver);

    console.log("response:", ab2str(attStmt.response));
    ret.set("response", ab2str(attStmt.response));

    var parsedJws = await jose.JWS.createVerify().verify(attStmt.response, { allowEmbeddedKey: true });
    ret.set("payload", JSON.parse(ab2str(coerceToArrayBuffer(parsedJws.payload, "MDS TOC payload"))));

    ret.set("attCert", parsedJws.x5c.shift());
    ret.set("x5c", parsedJws.x5c);

    return ret;
}

function androidSafetyNetValidateFn() {
    // // verify cert chain
    // var rootCerts;
    // if (Array.isArray(rootCert)) rootCerts = rootCert;
    // else rootCerts = [rootCert];
    // var ret = await CertManager.verifyCertChain(header.x5c, rootCerts, crls);
}

module.exports = {
    name: "android-safetynet",
    parseFn: androidSafetyNetParseFn,
    validateFn: androidSafetyNetValidateFn
};
