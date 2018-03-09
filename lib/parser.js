const cbor = require("cbor");
const jwkToPem = require("jwk-to-pem");
const coseToJwk = require("cose-to-jwk");
const {
    printHex,
    coerceToBase64Url,
    coerceToArrayBuffer
} = require("./utils");
var { URL } = require("url");

function parseExpectations(exp) {
    if (typeof exp !== "object") {
        throw new TypeError("expected 'expectations' to be of type object, got " + typeof exp);
    }

    var ret = new Map();

    // origin
    if (typeof exp.origin !== "string") {
        throw new TypeError("expected 'origin' should be string, got " + typeof exp.origin);
    }

    new URL(exp.origin);
    ret.set("origin", exp.origin);

    // challenge
    var challenge = exp.challenge;

    challenge = coerceToBase64Url(challenge, "expected challenge");

    ret.set("challenge", challenge);

    // flags
    ret.set("flags", exp.flags);

    return ret;
}

function parseRequest() {

}

/**
 * Parses the clientData JSON byte stream into an Object
 * @param  {ArrayBuffer} clientDataJSON The ArrayBuffer containing the properly formatted JSON of the clientData object
 * @return {Object}                The parsed clientData object
 */
function parseClientData(clientDataJSON) {
    if (!(clientDataJSON instanceof ArrayBuffer)) {
        throw new TypeError("expected 'clientDataJSON' to be ArrayBuffer");
    }

    // printHex("clientDataJSON", clientDataJSON);

    // convert to string
    var clientDataJson = String.fromCharCode.apply(null, new Uint8Array(clientDataJSON));

    // parse JSON string
    var parsed;
    try {
        parsed = JSON.parse(clientDataJson);
    } catch (err) {
        throw new Error("couldn't parse clientDataJson: " + err);
    }

    var ret = new Map([
        ["challenge", parsed.challenge],
        // ["clientExtensions", parsed.clientExtensions], // removed in WD-08
        // ["hashAlgorithm", parsed.hashAlgorithm], // removed in WD-08
        ["origin", parsed.origin],
        ["type", parsed.type],
        ["tokenBinding", parsed.tokenBinding],
        ["rawClientDataJson", clientDataJSON]
    ]);

    return ret;
}

/**
 * Parses the CBOR attestation statement
 * @param  {ArrayBuffer} attestationObject The CBOR byte array representing the attestation statement
 * @return {Object}                   The Object containing all the attestation information
 * @see https://w3c.github.io/webauthn/#generating-an-attestation-object
 * @see  https://w3c.github.io/webauthn/#defined-attestation-formats
 */
function parseAttestationObject(attestationObject) {
    // printHex ("attestationObject", attestationObject);

    // parse attestation
    var parsed;
    try {
        parsed = cbor.decodeAllSync(Buffer.from(attestationObject));
    } catch (err) {
        throw new TypeError("couldn't parse attestationObject CBOR");
    }

    if (!Array.isArray(parsed) || typeof parsed[0] !== "object") {
        throw new TypeError("invalid parsing of attestationObject CBOR");
    }

    if (typeof parsed[0].fmt !== "string") {
        throw new Error("expected attestation CBOR to contain a 'fmt' string");
    }

    if (typeof parsed[0].attStmt !== "object") {
        throw new Error("expected attestation CBOR to contain a 'attStmt' object");
    }

    if (!(parsed[0].authData instanceof Buffer)) {
        throw new Error("expected attestation CBOR to contain a 'authData' byte sequence");
    }

    var ret = new Map([
        ...parseAttStmt(parsed[0].fmt, parsed[0].attStmt),
        // return raw buffer for future signature verification
        ["rawAuthData", coerceToArrayBuffer(parsed[0].authData, "authData")],
        // parse authData
        ...parseAuthenticatorData(parsed[0].authData)
    ]);

    return ret;
}

function parseAttStmt(fmt, attStmt) {
    var ret;

    switch (fmt) {
        case "none":
            ret = new Map();
            break;
        case "fido-u2f":
            ret = parseFidoU2fAttStmt(attStmt);
            break;
        default:
            throw new TypeError("don't know how to parse attStmt: " + fmt);
    }
    ret.set("fmt", fmt);

    return ret;
}

function parseFidoU2fAttStmt(attStmt) {
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
    ret.set("certChain", newX5c);

    sig = coerceToArrayBuffer(sig, "U2F signature");
    ret.set("sig", sig);

    return ret;
}

function parseAuthenticatorData(authnrDataArrayBuffer) {
    // convert to ArrayBuffer
    authnrDataArrayBuffer = coerceToArrayBuffer(authnrDataArrayBuffer, "authnrDataArrayBuffer");

    var ret = new Map();

    // console.log("authnrDataArrayBuffer", authnrDataArrayBuffer);
    // console.log("typeof authnrDataArrayBuffer", typeof authnrDataArrayBuffer);
    // printHex("authnrDataArrayBuffer", authnrDataArrayBuffer);

    var authnrDataBuf = new DataView(authnrDataArrayBuffer);
    var offset = 0;
    ret.set("rpIdHash", authnrDataBuf.buffer.slice(offset, offset + 32));
    offset += 32;
    var flags = authnrDataBuf.getUint8(offset);
    var flagsSet = new Set();
    ret.set("flags", flagsSet);
    if (flags & 0x01) flagsSet.add("UP");
    if (flags & 0x02) flagsSet.add("RFU1");
    if (flags & 0x04) flagsSet.add("UV");
    if (flags & 0x08) flagsSet.add("RFU3");
    if (flags & 0x10) flagsSet.add("RFU4");
    if (flags & 0x20) flagsSet.add("RFU5");
    if (flags & 0x40) flagsSet.add("AT");
    if (flags & 0x80) flagsSet.add("ED");
    offset++;
    ret.set("counter", authnrDataBuf.getUint32(offset, false));
    offset += 4;

    // see if there's more data to process
    var attestation = flagsSet.has("AT");
    var extensions = flagsSet.has("ED");

    if (attestation) {
        ret.set("aaguid", authnrDataBuf.buffer.slice(offset, offset + 16));
        offset += 16;
        var credIdLen = authnrDataBuf.getUint16(offset, false);
        ret.set("credIdLen", credIdLen);
        offset += 2;
        ret.set("credId", authnrDataBuf.buffer.slice(offset, offset + credIdLen));
        offset += credIdLen;
        var credentialPublicKeyCose = authnrDataBuf.buffer.slice(offset, authnrDataBuf.buffer.byteLength);
        ret.set("credentialPublicKeyCose", credentialPublicKeyCose);
        var jwk = coseToJwk(credentialPublicKeyCose);
        // convert JWK Buffer values to ArrayBuffer
        for (let key of Object.keys(jwk)) {
            if (jwk[key] instanceof Buffer) {
                jwk[key] = new Uint8Array(jwk[key]).buffer;
            }
        }
        ret.set("credentialPublicKeyJwk", jwk);
        ret.set("credentialPublicKeyPem", jwkToPem(jwk));
    }

    // TODO: parse extensions
    if (extensions) {
        // extensionStart = offset
        throw new Error("extensions not supported");
    }

    return ret;
}

function parseAttestationStatement(fmt, attStmt) {
    if (typeof fmt !== "string") {
        throw new TypeError("expected 'fmt' to be of type string, got " + typeof fmt);
    }

    if (typeof attStmt !== "object") {
        throw new TypeError("expected 'attStmt' to be of type object, got " + typeof attStmt);
    }

    var ret = {};

    switch (fmt) {
        case "none":
            ret.sig = null;
            return ret;
        default:
            throw new Error(`attestation type ${fmt} unknown`);
    }
}

module.exports = {
    parseExpectations,
    parseClientData,
    parseAttestationObject,
    parseAuthenticatorData,
    parseAttestationStatement
};