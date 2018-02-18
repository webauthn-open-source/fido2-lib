var _ = require("lodash");
var crypto = require("crypto");
var cbor = require("cbor");
var jwk2pem = require('pem-jwk').jwk2pem;

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
     * @param  {Object} opts The options for the Fido2Server
     * @return {FIDOServer}      Returns a new Fido2Server object
     */
    constructor(opts) {
        if (typeof opts !== "object") {
            throw new TypeError ("constructor requires configuration object");
        }

        if (typeof opts.rpid !== "string") {
            throw new TypeError ("must specify rpid (eTLD+1)");
        }

        var defaults = {
            // rpid: "example.com", // eTLD + 1
            blacklist: [],
            cryptoParameterPrefs: [],
            challengeSize: 32,
            attestationTimeout: 30000, // 5 minutes
            assertionTimeout: 30000, // 5 minutes
            version: { // TODO: get this from package.json
                major: 0,
                minor: 8,
                patch: 0
            },
        };

        _.defaultsDeep(opts, defaults);
        _.extend(this, opts);
    }

    /**
     * Gets a challenge and any other parameters for the makeCredential call
     */
    getAttestationChallenge() {
        return new Promise((resolve) => {
            console.log("getAttestationChallenge");

            var challenge = {};
            // TODO: ret.accountInformation = {};
            challenge.blacklist = this.blacklist;
            // TODO: ret.credentialExtensions = [];
            challenge.cryptoParameters = [];
            challenge.attestationChallenge = crypto.randomBytes(this.challengeSize);
            challenge.timeout = this.attestationTimeout;
            resolve(challenge);
        });
    }

    /**
     * Parses the clientData JSON byte stream into an Object
     * @param  {ArrayBuffer} clientDataJSON The ArrayBuffer containing the properly formatted JSON of the clientData object
     * @return {Object}                The parsed clientData object
     */
    parseClientData(clientDataJSON) {
        var ret;

        // parse clientData
        var clientDataJson = String.fromCharCode.apply(null, new Uint8Array(clientDataJSON));
        try {
            ret = JSON.parse(clientDataJson);
        } catch (err) {
            throw new TypeError("couldn't parse clientDataJson");
        }

        return ret;
    }

    /**
     * Parses the CBOR attestation statement
     * @param  {ArrayBuffer} attestationObject The CBOR byte array representing the attestation statement
     * @return {Object}                   The Object containing all the attestation information
     * @see https://w3c.github.io/webauthn/#generating-an-attestation-object
     * @see  https://w3c.github.io/webauthn/#defined-attestation-formats
     */
    parseAttestationStatement(attestationObject) {
        var ret;

        // parse attestation
        try {
            ret = cbor.decodeAllSync(Buffer.from(attestationObject));
        } catch (err) {
            throw new TypeError("couldn't parse attestationObject CBOR");
        }
        console.log(ret);
        if (!Array.isArray(ret) || typeof ret[0] !== "object") {
            throw new TypeError("invalid parsing of attestationObject CBOR");
        }
        ret = ret[0];

        return ret;
    }

    parseAuthenticatorData(authnrDataArrayBuffer) {
        var attestation = false, extensions = false;
        if (authnrDataArrayBuffer.byteLength > 37) {
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
        console.log ("offset", offset);

        // TODO: refactor into parseAttestationData function
        console.log ("attestation?");
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
            if (!Array.isArray(authnrData.attestationData) || typeof authnrData.attestationData[0] !== "object") {
                throw new TypeError("invalid parsing of authenticator.authData.attestationData CBOR");
            }
            authnrData.attestationData = authnrData.attestationData[0];
        }

        // TODO: parse extensions
        if (extensions) {
            throw new Fido2LibError ("extensions not supported");
        }

        console.log ("returning:", authnrData);
        return authnrData;
    }

    validateSignature(sigBuf, alg, publicKeyPem, authenticatorDataBuf, clientDataJsonBuf) {
        // TODO: use crypto algorithm specified in authenticator data
        if (alg !== "RS256") {
            throw new TypeError("only RS256 attestation hashes are supported");
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
        var verify = crypto.createVerify("RSA-SHA256");
        printHex ("authenticatorDataBuf", authenticatorDataBuf);
        verify.update(authenticatorDataBuf);
        printHex ("clientDataHash", clientDataHash);
        verify.update(clientDataHash);
        console.log ("publicKeyPem", publicKeyPem);
        printHex ("sigBuf", sigBuf);
        var ret = verify.verify(publicKeyPem, sigBuf);

        if(!ret) {
            throw new Fido2LibError ("validateSignature: signature validation failed");
        }

        return ret;
    }

    attestationDataToPem(attestationDataObj) {
        console.log("For PEM:", attestationDataObj);
        var jwk = {};
        switch (attestationDataObj.alg) {
            case "RS256":
                jwk.alg = attestationDataObj.alg;
                jwk.kty = "RSA";
                jwk.n = attestationDataObj.n;
                jwk.e = attestationDataObj.e;
                break;
            default:
                throw new TypeError(`${attestationDataObj.alg} not supported in attestationDataToPem`);
        }

        var pem = jwk2pem(jwk);
        console.log("PEM:\n", pem);

        return pem;
    }

    /**
     * Processes the makeCredential response
     */
    makeCredentialResponse(res, challenge, origin) {
        return new Promise((resolve, reject) => {
            console.log(res);

            // validate inputs
            if (typeof res !== "object") {
                throw new TypeError("makeCredentialResponse: expected response to be a object");
            }

            if (!(res.clientDataJSON instanceof ArrayBuffer)) {
                throw new TypeError("expected result to contain clientDataJSON of type ArrayBuffer");
            }

            if (!(res.attestationObject instanceof ArrayBuffer)) {
                throw new TypeError("expected result to contain attestationObject of type ArrayBuffer");
            }

            // parse arguments
            var attestation, clientData, authnrData;
            clientData = this.parseClientData(res.clientDataJSON);
            attestation = this.parseAttestationStatement(res.attestationObject);
            // console.log("ATTESTATION:", attestation);
            var authnrDataTypedArray = new Uint8Array(attestation.authData);
            authnrData = this.parseAuthenticatorData(authnrDataTypedArray.buffer);
            // console.log("AUTH DATA:\n", authnrData);

            // validate data
            var pemPk = this.attestationDataToPem(authnrData.attestationData);
            if (!this.validateSignature(attestation.attStmt.sig, authnrData.attestationData.alg, pemPk, authnrDataTypedArray.buffer, res.clientDataJSON)) {
                throw new Error ("makeCredentialResponse: signature validation failed");
            }

            // SECURITY TODO:
            //     https://w3c.github.io/webauthn/#rp-operations
            // SECURITY TODO:
            // - make sure attestation matches
            // - lastAttestationUpdate must be somewhat recent (per some definable policy)
            // -- timeout for lastAttestationUpdate may be tied to the timeout parameter of makeCredential
            // - verify challenge in attestation matches challege that was sent
            // SECURITY TODO: validate public key based on key type
            // SECURITY TODO: verify that publicKey.alg is an algorithm type supported by server
            // SECURITY TODO: validate attestations
            // SECURITY TODO: validate origin
            // SECURITY TODO: validate RPID hash
            // SECURITY TODO: validate extensions are a subset of requested extensions

            switch (attestation.fmt) {
                case "packed":
                    console.log("packed attestation");
                    break;
                default:
                    throw new TypeError(`${attestation.fmt} attestation format not supported`);
            }

            // TODO: return pass / fail
            // TODO: return publicKeyPem
            resolve();
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

            console.log ("res", res);
            console.log ("challenge", challenge);
            console.log ("publicKeyPem", publicKeyPem);
            console.log ("origin", origin);

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

            if(typeof publicKeyPem !== "string") {
                throw new TypeError("getAssertionResponse: expected publicKey to be a String");
            }

            if (typeof origin !== "string") {
                throw new TypeError("getAssertionResponse: expected origin to be a String");
            }

            // parse arguments
            var attestation, clientData, authnrData;
            clientData = this.parseClientData(res.clientDataJSON);
            authnrData = this.parseAuthenticatorData(res.authenticatorData);
            console.log ("authnrData", authnrData);

            // validate signature
            if (!this.validateSignature(res.signature, "RS256", publicKeyPem, res.authenticatorData, res.clientDataJSON)) {
                throw new Error ("getAssertionResponse: signature validation failed");
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
}

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