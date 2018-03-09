var _ = require("lodash");
var crypto = require("crypto");

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
    createCredentialChallenge() {
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
    createCredentialResponse(res, expectedChallenge, expectedOrigin) {
        return new Promise((resolve, reject) => {

            // validate inputs
            if (typeof res !== "object") {
                throw new TypeError("createCredentialResponse: expected res to be a object");
            }

            if (typeof res.response !== "object") {
                throw new TypeError("createCredentialResponse: expected res.response to be a object");
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
            //     throw new Error("createCredentialResponse: signature validation failed");
            // }

            // SECURITY TODO:
            //     https://w3c.github.io/webauthn/#rp-operations
            // SECURITY TODO:
            // - make sure attestation matches
            // - lastAttestationUpdate must be somewhat recent (per some definable policy)
            // -- timeout for lastAttestationUpdate may be tied to the timeout parameter of createCredential
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
                return reject(new TypeError("createCredentialResponse: expected userId to be a string"));
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
}



module.exports = {
    Fido2Lib
};