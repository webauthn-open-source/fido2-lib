var _ = require("lodash");
var crypto = require("crypto");
var cbor = require("cbor");
// var jwk2pem = require('pem-jwk').jwk2pem;
var jwkToPem = require('jwk-to-pem');

class Fido2LibError extends Error {
    constructor(message, type) {
        super();
        Error.captureStackTrace(this, this.constructor);
        this.name = this.constructor.name;
        this.message = message;
        this.extra = type;
    }
}

class Fido2Lib {
    /**
     * [constructor description]
     * @param  {Object} opts The options for the Fido2Lib
     * @return {FIDOServer}      Returns a new Fido2Lib object
     */
    constructor(opts) {
        if (typeof opts !== "object") {
            throw new TypeError("constructor requires configuration object");
        }

        if (typeof opts.serverDomain !== "string") {
            throw new TypeError("must specify serverDomain (eTLD+1)");
        }

        // set defaults
        this.config = {};
        this.config.timeout = opts.timeout || 60000; // 1 minute
        this.config.challengeSize = opts.challengSize || 64;
        this.config.serverDomain = opts.serverDomain;
        this.config.serverName = opts.serverName || opts.serverDomain;
        this.config.serverIcon = opts.serverIcon;
    }

    /**
     * Gets a challenge and any other parameters for the credentials.create() call
     */
    getAttestationChallenge() {
        return new Promise((resolve) => {
            console.log("getAttestationChallenge");

            // https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
            // challenge.rp
            // challenge.user
            // challenge.excludeCredentials
            // challenge.authenticatorSelection
            // challenge.attestation
            // challenge.extensions
            var challenge = {
                rp: {
                    id: this.config.serverDomain,
                    name: this.config.serverName
                },
                challenge: crypto.randomBytes(this.config.challengeSize),
                timeout: this.config.timeout
            };

            resolve(challenge);
        });
    }

    /**
     * Processes the makeCredential response
     */
    makeCredentialResponse(res, expectedChallenge, expectedOrigin) {
        return new Promise((resolve, reject) => {

            // validate inputs
            if (typeof res !== "object") {
                throw new TypeError("makeCredentialResponse: expected res to be a object");
            }

            if (typeof res.response !== "object") {
                throw new TypeError("makeCredentialResponse: expected res.response to be a object");
            }

            if (!(res.response.clientDataJSON instanceof ArrayBuffer)) {
                throw new TypeError("expected result to contain clientDataJSON of type ArrayBuffer");
            }

            if (!(res.response.attestationObject instanceof ArrayBuffer)) {
                throw new TypeError("expected result to contain attestationObject of type ArrayBuffer");
            }

            // parse arguments
            var clientData = this.parseClientData(res.response.clientDataJSON);
            console.log("CLIENT DATA:\n", clientData);
            var attObj = this.parseAttestationObject(res.response.attestationObject);
            console.log("ATTESTATION:\n", attObj);
            var authnrData = this.parseAuthenticatorData(attObj.authData);
            console.log("AUTH DATA:\n", authnrData);
            var attestation = this.parseAttestationStatement(attObj.fmt, attObj.attStmt);

            // validate client data
            this.validateClientData(clientData, "webauthn.create", expectedChallenge, expectedOrigin);
            // validate attestation
            // validate signature

            // validate data
            // var pemPk = this.attestationDataToPem(authnrData.attestationData);
            // if (!this.validateSignature(attObj.attStmt.sig, authnrData.attestationData.alg, pemPk, authnrDataTypedArray.buffer, res.response.clientDataJSON)) {
            //     throw new Error("makeCredentialResponse: signature validation failed");
            // }

            // SECURITY TODO:
            //     https://w3c.github.io/webauthn/#rp-operations
            // SECURITY TODO:
            // - make sure attestation matches
            // - lastAttestationUpdate must be somewhat recent (per some definable policy)
            // -- timeout for lastAttestationUpdate may be tied to the timeout parameter of makeCredential
            // - verify challenge in attestation matches challege that was sent
            // SECURITY TODO: validate TUP & UV
            // SECURITY TODO: validate public key based on key type
            // SECURITY TODO: verify that publicKey.alg is an algorithm type supported by server
            // SECURITY TODO: validate attestations
            // SECURITY TODO: validate origin
            // SECURITY TODO: validate RPID hash
            // SECURITY TODO: validate extensions are a subset of requested extensions

            // TODO: return pass / fail
            // TODO: return publicKeyPem
            resolve(true);
        });
    }

    /**
     * Creates an assertion challenge and any other parameters for the getAssertion call
     */
    getAssertionChallenge(userId) {
        return new Promise(function(resolve, reject) {
            console.log("getAssertionChallenge");
            // validate response
            if (typeof userId !== "string") {
                return reject(new TypeError("makeCredentialResponse: expected userId to be a string"));
            }

            var ret = {};
            // SECURITY TODO: ret.assertionExtensions = [];
            ret.assertionChallenge = crypto.randomBytes(this.challengeSize).toString("hex");
            ret.timeout = this.assertionTimeout;
            // lookup credentials for whitelist
            console.log("Getting user");
            this.account.updateUserChallenge(userId, ret.assertionChallenge)
                .then(function(user) {
                    // updateUserChallenge doesn't populate credentials so we have to re-lookup here
                    return this.account.getUserById(userId);
                }.bind(this))
                .then(function(user) {
                    if (user === undefined) return (reject(new Error("User not found")));
                    console.log("getAssertionChallenge user:", user);
                    ret.whitelist = _.map(user.credentials, function(o) {
                        return _.pick(o, ["type", "id"]);
                    });
                    console.log("getAssertionChallenge returning:", ret);
                    resolve(ret);
                })
                .catch(function(err) {
                    console.log("ERROR:");
                    console.log(err);
                    reject(err);
                });

        }.bind(this));
    }

    /**
     * Processes a getAssertion response
     */
    getAssertionResponse(res, challenge, publicKeyPem, origin, counter) {
        return new Promise((resolve, reject) => {
            console.log("getAssertionResponse");
            console.log("res:", res);
            // validate response

            console.log("res", res);
            console.log("challenge", challenge);
            console.log("publicKeyPem", publicKeyPem);
            console.log("origin", origin);

            if (typeof res !== "object") {
                throw new TypeError("getAssertionResponse: expected response to be an object");
            }

            if (typeof res.credential !== "object" ||
                res.credential.type !== "ScopedCred" ||
                !(res.credential.id instanceof ArrayBuffer)) {
                throw new TypeError("getAssertionResponse: got an unexpected credential format: " + res.credential);
            }

            if (!(res.clientDataJSON instanceof ArrayBuffer)) {
                throw new TypeError("getAssertionResponse: expected clientData to be an ArrayBuffer");
            }

            // SECURITY TODO: clientData must contain challenge, facet, hashAlg

            if (!(res.authenticatorData instanceof ArrayBuffer)) {
                throw new TypeError("getAssertionResponse: expected authenticatorData to be an ArrayBuffer");
            }

            if (!(res.signature instanceof ArrayBuffer)) {
                throw new TypeError("getAssertionResponse: expected signature to be an ArrayBuffer");
            }

            if (!(challenge instanceof ArrayBuffer)) {
                throw new TypeError("getAssertionResponse: expected challenge to be an ArrayBuffer");
            }

            if (typeof publicKeyPem !== "string") {
                throw new TypeError("getAssertionResponse: expected publicKey to be a String");
            }

            if (typeof origin !== "string") {
                throw new TypeError("getAssertionResponse: expected origin to be a String");
            }

            // parse arguments
            var attestation, clientData, authnrData;
            clientData = this.parseClientData(res.clientDataJSON);
            authnrData = this.parseAuthenticatorData(res.authenticatorData);
            console.log("authnrData", authnrData);

            // validate signature
            if (!this.validateSignature(res.signature, "RS256", publicKeyPem, res.authenticatorData, res.clientDataJSON)) {
                throw new Error("getAssertionResponse: signature validation failed");
            }

            // SECURITY TODO: if now() > user.lastChallengeUpdate + this.assertionTimeout, reject()
            // SECURITY TODO: if res.challenge !== user.challenge, reject()
            // SECURITY TODO: verify signature
            // publicKey.alg = RSA256, ES256, PS256, ED256
            // crypto.createVerify('RSA-SHA256');
            // jwkToPem();
            // SECURITY TODO: verify counter
            // SECURITY TODO: verify tokenBinding, if it exists
            // TODO: process extensions
            // TODO: riskengine.evaluate
            reject(false);
        });
    }

    /**
     * Parses the clientData JSON byte stream into an Object
     * @param  {ArrayBuffer} clientDataJSON The ArrayBuffer containing the properly formatted JSON of the clientData object
     * @return {Object}                The parsed clientData object
     */
    parseClientData(clientDataJSON) {
        var ret;

        // printHex("clientDataJSON", clientDataJSON);

        // parse clientData
        var clientDataJson = String.fromCharCode.apply(null, new Uint8Array(clientDataJSON));
        try {
            ret = JSON.parse(clientDataJson);
        } catch (err) {
            throw new TypeError("couldn't parse clientDataJson");
        }

        return ret;
    }

    validateClientData(clientData, op, expectedChallenge, expectedOrigin) {
        if (clientData.challenge !== expectedChallenge) {
            throw new Error("clientData: challenge mismatch");
        }

        if (clientData.origin !== expectedOrigin) {
            throw new Error("clientData: origin mismatch");
        }

        if(clientData.type !== op) {
            throw new Error("clientData: type mismatch")
        }
    }

    /**
     * Parses the CBOR attestation statement
     * @param  {ArrayBuffer} attestationObject The CBOR byte array representing the attestation statement
     * @return {Object}                   The Object containing all the attestation information
     * @see https://w3c.github.io/webauthn/#generating-an-attestation-object
     * @see  https://w3c.github.io/webauthn/#defined-attestation-formats
     */
    parseAttestationObject(attestationObject) {
        var ret;

        // parse attestation
        try {
            ret = cbor.decodeAllSync(Buffer.from(attestationObject));
        } catch (err) {
            throw new TypeError("couldn't parse attestationObject CBOR");
        }
        if (!Array.isArray(ret) || typeof ret[0] !== "object") {
            throw new TypeError("invalid parsing of attestationObject CBOR");
        }
        ret = ret[0];

        return ret;
    }

    parseAuthenticatorData(authnrDataArrayBuffer) {
        if (authnrDataArrayBuffer instanceof Buffer) {
            console.log("was buffer!");
            var tmp = new Uint8Array(authnrDataArrayBuffer);
            authnrDataArrayBuffer = tmp.buffer;
        }

        console.log("authnrDataArrayBuffer", authnrDataArrayBuffer);
        console.log("typeof authnrDataArrayBuffer", typeof authnrDataArrayBuffer);
        printHex("authnrDataArrayBuffer", authnrDataArrayBuffer);
        var attestation = false,
            extensions = false;
        if (authnrDataArrayBuffer.byteLength > 37) { // TODO: this will break if there are extensions
            attestation = true;
        }

        var authnrDataBuf = new DataView(authnrDataArrayBuffer);
        var authnrData = {};
        var offset = 0;
        authnrData.rpIdHash = authnrDataBuf.buffer.slice(offset, offset + 32);
        offset += 32;
        authnrData.flags = authnrDataBuf.getUint8(offset);
        offset++;
        authnrData.counter = authnrDataBuf.getUint32(offset, false);
        offset += 4;

        // TODO: refactor into parseAttestationData function
        if (attestation) {
            authnrData.aaguid = authnrDataBuf.buffer.slice(offset, offset + 16);
            offset += 16;
            authnrData.credIdLen = authnrDataBuf.getUint16(offset, false);
            offset += 2;
            authnrData.credId = authnrDataBuf.buffer.slice(offset, offset + authnrData.credIdLen);
            offset += authnrData.credIdLen;
            authnrData.attestationDataCbor = authnrDataBuf.buffer.slice(offset, authnrDataBuf.buffer.byteLength);
            try {
                authnrData.attestationData = cbor.decodeAllSync(Buffer.from(authnrData.attestationDataCbor));
            } catch (err) {
                throw new TypeError("couldn't parse authenticator.authData.attestationData CBOR");
            }
            if (!Array.isArray(authnrData.attestationData) || !(authnrData.attestationData[0] instanceof Map)) {
                throw new TypeError("invalid parsing of authenticator.authData.attestationData CBOR");
            }
            authnrData.attestationDataCoseMap = authnrData.attestationData[0];
            authnrData.attestationData = this.decodeCoseKey(authnrData.attestationDataCoseMap);
        }

        // TODO: parse extensions
        if (extensions) {
            throw new Fido2LibError("extensions not supported");
        }

        return authnrData;
    }

    // TODO: refactor this into its own npm module
    decodeCoseKey(coseMap) {
        console.log("PARSING COSE");
        console.log("coseMap", coseMap);

        // main COSE labels
        // defined here: https://tools.ietf.org/html/rfc8152#section-7.1
        const coseLabels = {
            "1": {
                name: "kty",
                values: {
                    "2": "EC2",
                    "3": "RSA"
                }
            },
            "2": {
                name: "kid",
                values: {}
            },
            "3": {
                name: "alg",
                values: {
                    "-7": "ECDSA_w_SHA256",
                    "-8": "EdDSA",
                    "-35": "ECDSA_w_SHA384",
                    "-36": "ECDSA_w_SHA512"
                }
            },
            "4": {
                name: "key_ops",
                values: {}
            },
            "5": {
                name: "base_iv",
                values: {}
            }
        };

        // key-specific parameters
        const keyParamList = {
            // ECDSA key parameters
            // defined here: https://tools.ietf.org/html/rfc8152#section-13.1.1
            "EC2": {
                "-1": {
                    name: "crv",
                    values: {
                        "1": "P-256",
                        "2": "P-384",
                        "3": "P-521",
                        "4": "X25519",
                        "5": "X448",
                        "6": "Ed25519",
                        "7": "Ed448"
                    }
                },
                "-2": {
                    name: "x"
                    // value = Buffer
                },
                "-3": {
                    name: "y"
                    // value = Buffer
                },
                "-4": {
                    name: "d"
                    // value = Buffer
                }
            },
            // RSA key parameters
            // defined here: https://tools.ietf.org/html/rfc8230#section-4
            "RSA": {
                "-1": {
                    name: "n"
                    // value = Buffer
                },
                "-2": {
                    name: "e"
                    // value = Buffer
                },
                "-3": {
                    name: "d"
                    // value = Buffer
                },
                "-4": {
                    name: "p"
                    // value = Buffer
                },
                "-5": {
                    name: "q"
                    // value = Buffer
                },
                "-6": {
                    name: "dP"
                    // value = Buffer
                },
                "-7": {
                    name: "dQ"
                    // value = Buffer
                },
                "-8": {
                    name: "qInv"
                    // value = Buffer
                },
                "-9": {
                    name: "other"
                    // value = Array
                },
                "-10": {
                    name: "r_i"
                    // value = Buffer
                },
                "-11": {
                    name: "d_i"
                    // value = Buffer
                },
                "-12": {
                    name: "t_i"
                    // value = Buffer
                }
            }

        };

        var extraMap = new Map();

        var retKey = {};

        // parse main COSE labels
        for (let kv of coseMap) {
            let key = kv[0].toString();
            let value = kv[1].toString();

            if (!coseLabels[key]) {
                extraMap.set(kv[0], kv[1]);
                continue;
            }

            let name = coseLabels[key].name;
            if (coseLabels[key].values[value]) value = coseLabels[key].values[value];
            retKey[name] = value;
        }

        var keyParams = keyParamList[retKey.kty];
        console.log("keyParams", keyParams);

        // parse key-specific parameters
        for (let kv of extraMap) {
            let key = kv[0].toString();
            let value = kv[1];

            if (!keyParams[key]) {
                throw new Error("unknown COSE key label: " + retKey.kty + " " + key);
            }
            console.log("key", key);
            let name = keyParams[key].name;
            console.log("name", name);

            if (keyParams[key].values) {
                value = keyParams[key].values[value.toString()];
            }

            retKey[name] = value;
        }

        console.log("returning", retKey);
        return retKey;
    }

    parseAttestationStatement(fmt, attStmt) {
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

    attestationDataToPem(attestationDataObj) {
        // console.log("For PEM:", attestationDataObj);
        var jwk = {};
        switch (attestationDataObj.kty) {
            case "RSA":
                jwk.alg = attestationDataObj.alg;
                jwk.kty = attestationDataObj.kty;
                jwk.n = b64NormalEncode(attestationDataObj.n);
                jwk.e = b64NormalEncode(attestationDataObj.e);
                break;
            case "EC2":
                jwk.alg = attestationDataObj.alg;
                jwk.kty = "EC";
                jwk.crv = attestationDataObj.crv;
                jwk.x = b64NormalEncode(attestationDataObj.x);
                jwk.y = b64NormalEncode(attestationDataObj.y);
                break;
            default:
                throw new TypeError(`${attestationDataObj.kty} not supported in attestationDataToPem`);
        }

        console.log("jwk", jwk);

        var pem = jwkToPem(jwk);
        console.log("PEM:\n", pem);

        return pem;
    }

    validateSignature(sigBuf, alg, publicKeyPem, authenticatorDataBuf, clientDataJsonBuf) {
        // TODO: use crypto algorithm specified in authenticator data
        // if (kty !== "RSA" && kty !== "EC2") {
        //     throw new TypeError("only RSA and ECDSA attestation signatures are supported");
        // }

        var nodeAlg;
        switch (alg) {
            case "ECDSA_w_SHA256":
                nodeAlg = "SHA256";
                break;
            default:
                throw new Error("algorithm not supported: " + alg);
        }

        // TODO: turn jwk into nodejs alg

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
            throw new Fido2LibError("validateSignature: signature validation failed");
        }

        return ret;
    }
}

// borrowed from:
// https://github.com/niklasvh/base64-arraybuffer/blob/master/lib/base64-arraybuffer.js
// modified to base64url by Yuriy :)
/*
 * base64-arraybuffer
 * https://github.com/niklasvh/base64-arraybuffer
 *
 * Copyright (c) 2012 Niklas von Hertzen
 * Licensed under the MIT license.
 */
var b64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
var b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Use a lookup table to find the index.
var lookupNormal = new Uint8Array(256);
for (var i = 0; i < b64Chars.length; i++) {
    lookupNormal[b64Chars.charCodeAt(i)] = i;
}
var lookupUrl = new Uint8Array(256);
for (var i = 0; i < b64UrlChars.length; i++) {
    lookupUrl[b64UrlChars.charCodeAt(i)] = i;
}

function b64decode(base64) {
    var bufferLength = base64.length * 0.75,
        len = base64.length,
        i, p = 0,
        encoded1, encoded2, encoded3, encoded4;

    if (base64[base64.length - 1] === "=") {
        bufferLength--;
        if (base64[base64.length - 2] === "=") {
            bufferLength--;
        }
    }

    var arraybuffer = new ArrayBuffer(bufferLength),
        bytes = new Uint8Array(arraybuffer);

    for (i = 0; i < len; i += 4) {
        encoded1 = lookup[base64.charCodeAt(i)];
        encoded2 = lookup[base64.charCodeAt(i + 1)];
        encoded3 = lookup[base64.charCodeAt(i + 2)];
        encoded4 = lookup[base64.charCodeAt(i + 3)];

        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }

    return arraybuffer;
}

function b64encode(chars, lookup, arraybuffer) {
    console.log("b64encode");
    var bytes = new Uint8Array(arraybuffer),
        i, len = bytes.length,
        base64 = "";

    for (i = 0; i < len; i += 3) {
        base64 += chars[bytes[i] >> 2];
        base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += chars[bytes[i + 2] & 63];
    }

    if ((len % 3) === 2) {
        base64 = base64.substring(0, base64.length - 1) + "=";
    } else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + "==";
    }

    return base64;
}
var b64NormalDecode = b64decode.bind(null, b64Chars, lookupNormal);
var b64NormalEncode = b64encode.bind(null, b64Chars, lookupNormal);
var b64UrlDecode = b64decode.bind(null, b64UrlChars, lookupUrl);
var b64UrlEncode = b64encode.bind(null, b64UrlChars, lookupUrl);

// TODO: remove this debug code
function printHex(msg, buf) {
    // if the buffer was a TypedArray (e.g. Uint8Array), grab its buffer and use that
    if (ArrayBuffer.isView(buf) && buf.buffer instanceof ArrayBuffer) {
        buf = buf.buffer;
    }

    // check the arguments
    if ((typeof msg != "string") ||
        (typeof buf != "object")) {
        console.log("Bad args to printHex");
        return;
    }
    if (!(buf instanceof ArrayBuffer)) {
        console.log("Attempted printHex with non-ArrayBuffer:", buf);
        return;
    }
    // print the buffer as a 16 byte long hex string
    var arr = new Uint8Array(buf);
    var len = buf.byteLength;
    var i, str = "";
    console.log(msg);
    for (i = 0; i < len; i++) {
        var hexch = arr[i].toString(16);
        hexch = (hexch.length == 1) ? ("0" + hexch) : hexch;
        str += hexch.toUpperCase() + " ";
        if (i && !((i + 1) % 16)) {
            console.log(str);
            str = "";
        }
    }
    // print the remaining bytes
    if ((i) % 16) {
        console.log(str);
    }
}


module.exports = {
    Fido2Lib: Fido2Lib
};