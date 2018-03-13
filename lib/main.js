const _ = require("lodash");
const crypto = require("crypto");
const {
    Fido2CreateResponse,
    Fido2GetResponse
} = require("./response");

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
    createCredentialResponse(res, expectedChallenge, expectedOrigin, expectedFactor) {
        return new Promise((resolve) => {
            var expectedFlags = factorToFlags(expectedFactor, ["AT"]);

            var ret = Fido2CreateResponse.create(res, {
                challenge: expectedChallenge,
                origin: expectedOrigin,
                flags: expectedFlags
            });

            resolve(ret);
        });
    }

    /**
     * Creates an assertion challenge and any other parameters for the getAssertion call
     */
    getAssertionChallenge() {
        return new Promise((resolve) => {

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
     * Processes a getAssertion response
     */
    getAssertionResponse(res, expectedChallenge, expectedOrigin, expectedFactor, publicKeyPem, prevCounter) {
        return new Promise((resolve, reject) => {
            var expectedFlags = factorToFlags(expectedFactor, []);

            var ret = Fido2GetResponse.create(res, {
                challenge: expectedChallenge,
                origin: expectedOrigin,
                publicKey: publicKeyPem,
                prevCounter: prevCounter,
                flags: expectedFlags
            });

            resolve(ret);
        });
    }
}

function factorToFlags(expectedFactor, flags) {
    // var flags = ["AT"];
    flags = flags || [];

    switch (expectedFactor) {
        case "first":
            flags.push("UV");
            break;
        case "second":
            flags.push("UP");
            break;
        case "either":
            flags.push("UP-or-UV");
            break;
        default:
            throw new TypeError("expectedFactor should be 'first', 'second' or 'either'");
    }

    return flags;
}



module.exports = {
    Fido2Lib
};