var crypto = require("crypto");
var psl = require("psl");
var { URL } = require("url");
var {
    printHex,
    isBase64Url,
    checkOrigin
} = require("./utils");

function validateExpectations() {
    var req = this.requiredExpectations;
    var exp = this.expectations;
    if (!(exp instanceof Map)) {
        throw new Error("expectations should be of type Map");
    }

    if (!(req instanceof Set)) {
        throw new Error("requiredExpectaions should be of type Map");
    }

    for (let field of req) {
        if (!exp.has(field)) {
            throw new Error(`expectation did not contain value for '${field}'`);
        }
    }

    if (req.size !== exp.size) {
        throw new Error(`wrong number of expectations: should have ${req.size} but got ${exp.size}`);
    }

    // origin - isValid
    if (req.has("origin")) {
        var expectedOrigin = exp.get("origin");
        checkOrigin(expectedOrigin);
    }

    // challenge - is valid base64url string
    if (req.has("challenge")) {
        var challenge = exp.get("challenge");
        if (typeof challenge !== "string") {
            throw new Error("expected challenge should be of type String, got: " + typeof challenge);
        }

        if (!isBase64Url(challenge)) {
            throw new Error("expected challenge should be properly encoded base64url String");
        }
    }

    // flags - is iterable
    if (req.has("flags")) {
        var validFlags = new Set(["UP", "UV", "UP-or-UV", "AT", "ED"]);
        var flags = exp.get("flags");

        if (!Array.isArray(flags) && !(flags instanceof Set)) {
            throw new Error("expected flags to be Array or Set");
        }

        for (let flag of flags) {
            if (!validFlags.has(flag)) {
                throw new Error(`expected flag unknown: ${flag}`);
            }
        }
    }

    // TODO: counter

    this.audit.validExpectations = true;

    return true;
}

function validateCreateRequest(req) {
    if (typeof req !== "object") {
        throw new TypeError("expected request to be Object, got " + typeof req);
    }

    if (typeof req.id !== "string") {
        throw new TypeError("expected 'id' field of request to be String, got " + typeof req.id);
    }

    if (typeof req.response !== "object") {
        throw new TypeError("expected 'response' field of request to be Object, got " + typeof req.response);
    }

    if (typeof req.response.attestationObject !== "string" &&
        !(req.response.attestationObject instanceof ArrayBuffer)) {
        throw new TypeError("expected 'response.attestationObject' to be base64 String or ArrayBuffer");
    }

    if (typeof req.response.clientDataJSON !== "string" &&
        !(req.response.clientDataJSON instanceof ArrayBuffer)) {
        throw new TypeError("expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
    }

    this.audit.validRequest = true;

    return true;
}

function validateGetRequest() {

}

function validateRawClientDataJson() {
    // XXX: this isn't very useful, since this has already been parsed...
    var rawClientDataJson = this.clientData.get("rawClientDataJson");

    if (!(rawClientDataJson instanceof ArrayBuffer)) {
        throw new Error("clientData clientDataJson should have be ArrayBuffer");
    }

    this.audit.journal.add("rawClientDataJson");

    return true;
}

function validateOrigin() {
    var expectedOrigin = this.expectations.get("origin");
    var clientDataOrigin = this.clientData.get("origin");

    var origin = checkOrigin(clientDataOrigin);

    if (origin !== expectedOrigin) {
        throw new Error("clientData origin did not match expected origin");
    }

    this.audit.journal.add("origin");

    return true;
}

function validateCreateType() {
    var type = this.clientData.get("type");

    if (type !== "webauthn.create") {
        throw new Error("clientData type should be 'webauthn.create'");
    }

    this.audit.journal.add("type");

    return true;
}

function validateGetType() {
    var type = this.clientData.get("type");

    if (type !== "webauthn.get") {
        throw new Error("clientData type should be 'webauthn.get'");
    }

    this.audit.journal.add("type");

    return true;
}

function validateChallenge() {
    var expectedChallenge = this.expectations.get("challenge");
    var challenge = this.clientData.get("challenge");

    if (typeof challenge !== "string") {
        throw new Error("clientData challenge was not a string");
    }

    if (!isBase64Url(challenge)) {
        throw new TypeError("clientData challenge was not properly encoded base64url");
    }

    challenge = challenge.replace(/={1,2}$/, "");

    if (challenge !== expectedChallenge) {
        throw new Error("clientData challenge mismatch");
    }

    this.audit.journal.add("challenge");

    return true;
}

function validateRawAuthData() {
    // XXX: this isn't very useful, since this has already been parsed...
    var rawAuthData = this.authnrData.get("rawAuthData");

    if (!(rawAuthData instanceof ArrayBuffer)) {
        throw new Error("authnrData rawAuthData should have be ArrayBuffer");
    }

    this.audit.journal.add("rawAuthData");

    return true;
}

function validateSignature() {
    var fmt = this.authnrData.get("fmt");

    switch (fmt) {
        case "none":
            this.audit.journal.add("fmt");
            return true;
        default:
            throw new Error("unknown clientData fmt: " + fmt);
    }
}

function validateRpIdHash() {
    var rpIdHash = this.authnrData.get("rpIdHash");

    if (rpIdHash instanceof Buffer) {
        rpIdHash = new Uint8Array(rpIdHash).buffer;
    }

    if (!(rpIdHash instanceof ArrayBuffer)) {
        throw new Error("couldn't coerce clientData rpIdHash to ArrayBuffer");
    }

    var domain = new URL(this.clientData.get("origin")).hostname;
    var createdHash = new Uint8Array(crypto.createHash("sha256").update(domain).digest()).buffer;

    // wouldn't it be weird if two SHA256 hashes were different lengths...?
    if (rpIdHash.byteLength !== createdHash.byteLength) {
        throw new Error("authnrData rpIdHash length mismatch");
    }

    rpIdHash = new Uint8Array(rpIdHash);
    createdHash = new Uint8Array(createdHash);
    for (let i = 0; i < rpIdHash.byteLength; i++) {
        if (rpIdHash[i] !== createdHash[i]) {
            throw new TypeError("authnrData rpIdHash mismatch");
        }
    }

    this.audit.journal.add("rpIdHash");

    return true;
}

function validateFlags() {
    var expectedFlags = this.expectations.get("flags");
    var flags = this.authnrData.get("flags");

    for (let expFlag of expectedFlags) {
        if (expFlag === "UP-or-UV") {
            if (flags.has("UP") || flags.has("UV")) {
                continue;
            } else {
                throw new Error("expected User Presence (UP) or User Verification (UV) flag to be set and neither was");
            }
        }

        if (!flags.has(expFlag)) {
            throw new Error(`expected flag was not set: ${expFlag}`);
        }
    }

    this.audit.journal.add("flags");

    return true;
}

function validateCounter() {
    var counter = this.authnrData.get("counter");

    // TODO: does counter need to be zero initially? probably not... I guess..
    if (typeof counter !== "number") {
        throw new Error("authnrData counter wasn't a number");
    }

    this.audit.journal.add("counter");

    return true;
}

function validateAaguid() {
    var aaguid = this.authnrData.get("aaguid");

    if (!(aaguid instanceof ArrayBuffer)) {
        throw new Error("authnrData AAGUID is not ArrayBuffer");
    }

    if (aaguid.byteLength !== 16) {
        throw new Error("authnrData AAGUID was wrong length");
    }

    this.audit.journal.add("aaguid");

    return true;
}

function validateCredId() {
    var credId = this.authnrData.get("credId");
    var credIdLen = this.authnrData.get("credIdLen");

    if (!(credId instanceof ArrayBuffer)) {
        throw new Error("authnrData credId should be ArrayBuffer");
    }

    if (typeof credIdLen !== "number") {
        throw new Error("authnrData credIdLen should be number, got " + typeof credIdLen);
    }

    if (credId.byteLength !== credIdLen) {
        throw new Error("authnrData credId was wrong length");
    }

    this.audit.journal.add("credId");
    this.audit.journal.add("credIdLen");

    return true;
}

function validatePublicKey() {
    // XXX: the parser has already turned this into PEM at this point
    // if something were malformatted or wrong, we probably would have
    // thrown an error well before this.
    // Maybe we parse the ASN.1 and make sure attributes are correct?
    // Doesn't seem very worthwhile...

    var cbor = this.authnrData.get("credentialPublicKeyCose");
    var jwk = this.authnrData.get("credentialPublicKeyJwk");
    var pem = this.authnrData.get("credentialPublicKeyPem");

    // cbor
    if (!(cbor instanceof ArrayBuffer)) {
        throw new Error("authnrData credentialPublicKeyCose isn't of type ArrayBuffer");
    }
    this.audit.journal.add("credentialPublicKeyCose");

    // jwk
    if (typeof jwk !== "object") {
        throw new Error("authnrData credentialPublicKeyJwk isn't of type Object");
    }

    if (typeof jwk.crv !== "string") {
        throw new Error("authnrData credentialPublicKeyJwk.crv isn't of type String");
    }

    if (typeof jwk.alg !== "string") {
        throw new Error("authnrData credentialPublicKeyJwk.alg isn't of type String");
    }

    if (typeof jwk.kty !== "string") {
        throw new Error("authnrData credentialPublicKeyJwk.kty isn't of type String");
    }
    this.audit.journal.add("credentialPublicKeyJwk");

    // pem
    if (typeof pem !== "string") {
        throw new Error("authnrData credentialPublicKeyPem isn't of type String");
    }

    var pemRegex = /^-----BEGIN PUBLIC KEY-----$\n([A-Za-z0-9+/=]|\n)*^-----END PUBLIC KEY-----$/m;
    if (!pem.match(pemRegex)) {
        throw new Error("authnrData credentialPublicKeyPem was malformatted");
    }
    this.audit.journal.add("credentialPublicKeyPem");

    return true;
}

function validateTokenBinding() {
    // TODO: node.js can't support token binding right now :(
    var tokenBinding = this.clientData.get("tokenBinding");

    if (tokenBinding !== undefined) {
        throw new Error("Token binding not currently supported. Please submit a GitHub issue.");
    }

    this.audit.journal.add("tokenBinding");

    return true;
}

function validateCertChain() {

}

function validateClientData(clientData, op, expectedChallenge, expectedOrigin) {
    if (clientData.challenge !== expectedChallenge) {
        throw new Error("clientData: challenge mismatch");
    }

    if (clientData.origin !== expectedOrigin) {
        throw new Error("clientData: origin mismatch");
    }

    if (clientData.type !== op) {
        throw new Error("clientData: type mismatch");
    }
}

function oldValidateSignature(sigBuf, alg, publicKeyPem, authenticatorDataBuf, clientDataJsonBuf) {
    var nodeAlg;
    switch (alg) {
        case "ECDSA_w_SHA256":
            nodeAlg = "SHA256";
            break;
        default:
            throw new Error("algorithm not supported: " + alg);
    }

    // console.log ("sigBuf", sigBuf instanceof ArrayBuffer);
    // console.log ("authenticatorDataBuf", authenticatorDataBuf instanceof ArrayBuffer);
    // console.log ("clientDataJsonBuf", clientDataJsonBuf instanceof ArrayBuffer);
    // printHex ("sigBuf", sigBuf);
    // printHex ("authenticatorDataBuf", authenticatorDataBuf);
    // printHex ("clientDataJsonBuf", clientDataJsonBuf);

    // if ArrayBuffers, convert to node Buffers
    if (sigBuf instanceof ArrayBuffer) {
        sigBuf = Buffer.from(sigBuf);
    }
    if (authenticatorDataBuf instanceof ArrayBuffer) {
        authenticatorDataBuf = Buffer.from(authenticatorDataBuf);
    }
    if (clientDataJsonBuf instanceof ArrayBuffer) {
        clientDataJsonBuf = Buffer.from(clientDataJsonBuf);
    }

    // create client data hash
    var clientDataHash = crypto.createHash("sha256").update(clientDataJsonBuf).digest();

    // verify signature
    var verify = crypto.createVerify(nodeAlg);
    printHex("authenticatorDataBuf", authenticatorDataBuf);
    verify.update(authenticatorDataBuf);
    printHex("clientDataHash", clientDataHash);
    verify.update(clientDataHash);
    console.log("publicKeyPem", publicKeyPem);
    printHex("sigBuf", sigBuf);
    var ret = verify.verify(publicKeyPem, sigBuf);

    if (!ret) {
        throw new Error("validateSignature: signature validation failed");
    }

    return ret;
}

function validateAudit() {
    var journal = this.audit.journal;
    var clientData = this.clientData;
    var authnrData = this.authnrData;

    for (let kv of clientData) {
        let val = kv[0];
        if (!journal.has(val)) {
            throw new Error(`internal audit failed: ${val} was not validated`);
        }
    }

    for (let kv of authnrData) {
        let val = kv[0];
        if (!journal.has(val)) {
            throw new Error(`internal audit failed: ${val} was not validated`);
        }
    }

    if (journal.size !== (clientData.size + authnrData.size)) {
        throw new Error(`internal audit failed: ${journal.size} fields checked; expected ${clientData.size + authnrData.size}`);
    }

    if (!this.audit.validExpectations) {
        throw new Error("internal audit failed: expectations not validated");
    }

    if (!this.audit.validRequest) {
        throw new Error("internal audit failed: request not validated");
    }

    this.audit.complete = true;

    return true;
}

function attach(o) {
    var mixins = {
        validateExpectations,
        validateCreateRequest,
        // clientData validators
        validateRawClientDataJson,
        validateOrigin,
        validateCreateType,
        validateGetType,
        validateChallenge,
        // authnrData validators
        validateRawAuthData,
        validateSignature,
        validateRpIdHash,
        validateAaguid,
        validateCredId,
        validatePublicKey,
        validateTokenBinding,
        validateFlags,
        validateCounter,
        // audit structures
        audit: {
            validExpectations: false,
            validRequest: false,
            complete: false,
            journal: new Set()
        },
        validateAudit
    };

    for (let key of Object.keys(mixins)) {
        o[key] = mixins[key];
    }
}

module.exports = {
    attach
};