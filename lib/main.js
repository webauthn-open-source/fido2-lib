"use strict";

const crypto = require("crypto");
const {
    Fido2CreateResponse,
    Fido2GetResponse
} = require("./response");
const {
    coerceToArrayBuffer
} = require("./utils");


var globalAttestationMap = new Map();

class Fido2Lib {
    /**
     * [constructor description]
     * @param  {Object} opts The options for the Fido2Lib
     * @return {FIDOServer}      Returns a new Fido2Lib object
     */
    constructor(opts) {
        opts = opts || {};

        // set defaults
        this.config = {};
        this.config.timeout = opts.timeout || 60000; // 1 minute
        this.config.challengeSize = opts.challengSize || 64;
        this.config.serverDomain = opts.serverDomain;
        this.config.serverName = opts.serverName || opts.serverDomain;
        this.config.serverIcon = opts.serverIcon;

        this.attestationMap = globalAttestationMap;

        // add default attestation formats:
        // u2f
        // none

    }

    /**
     * Gets a challenge and any other parameters for the credentials.create() call
     */
    async createCredentialChallenge() {
        // https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
        // challenge.rp
        // challenge.user
        // challenge.excludeCredentials
        // challenge.authenticatorSelection
        // challenge.attestation
        // challenge.extensions
        var challenge = crypto.randomBytes(this.config.challengeSize);
        var options = {
            challenge: coerceToArrayBuffer(challenge),
            timeout: this.config.timeout
        };

        return options;
    }

    /**
     * Processes the makeCredential response
     */
    async createCredentialResponse(res, expectedChallenge, expectedOrigin, expectedFactor) {
        var expectedFlags = factorToFlags(expectedFactor, ["AT"]);

        return Fido2CreateResponse.create(res, {
            challenge: expectedChallenge,
            origin: expectedOrigin,
            flags: expectedFlags
        });
    }

    /**
     * Creates an assertion challenge and any other parameters for the getAssertion call
     */
    async getAssertionChallenge() {
        // https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
        // challenge.rp
        // challenge.user
        // challenge.excludeCredentials
        // challenge.authenticatorSelection
        // challenge.attestation
        // challenge.extensions
        var challenge = crypto.randomBytes(this.config.challengeSize);
        var options = {
            rp: {
                id: this.config.serverDomain,
                name: this.config.serverName
            },
            challenge: coerceToArrayBuffer(challenge),
            timeout: this.config.timeout
        };

        return options;
    }

    /**
     * Processes a getAssertion response
     */
    async getAssertionResponse(res, expectedChallenge, expectedOrigin, expectedFactor, publicKeyPem, prevCounter) {
        var expectedFlags = factorToFlags(expectedFactor, []);

        return Fido2GetResponse.create(res, {
            challenge: expectedChallenge,
            origin: expectedOrigin,
            publicKey: publicKeyPem,
            prevCounter: prevCounter,
            flags: expectedFlags
        });
    }

    static addAttestationFormat(fmt, parseFn, validateFn) {
        // validate input
        if (typeof fmt !== "string") {
            throw new TypeError("expected 'fmt' to be string, got: " + typeof fmt);
        }

        if (typeof parseFn !== "function") {
            throw new TypeError("expected 'parseFn' to be string, got: " + typeof parseFn);
        }

        if (typeof validateFn !== "function") {
            throw new TypeError("expected 'validateFn' to be string, got: " + typeof validateFn);
        }

        if (globalAttestationMap.has(fmt)) {
            throw new Error(`can't add format: '${fmt}' already exists`);
        }

        // add to attestationMap
        globalAttestationMap.set(fmt, {
            parseFn,
            validateFn
        });

        return true;
    }

    static deleteAllAttestationFormats() {
        globalAttestationMap.clear();
    }

    static parseAttestation(fmt, attStmt) {
        // validate input
        if (typeof fmt !== "string") {
            throw new TypeError("expected 'fmt' to be string, got: " + typeof fmt);
        }

        if (typeof attStmt !== "object") {
            throw new TypeError("expected 'attStmt' to be object, got: " + typeof attStmt);
        }

        // get from attestationMap
        var fmtObj = globalAttestationMap.get(fmt);
        if (typeof fmtObj !== "object" ||
            typeof fmtObj.parseFn !== "function" ||
            typeof fmtObj.validateFn !== "function") {
            throw new Error(`no support for attestation format: ${fmt}`);
        }

        // call fn
        var ret = fmtObj.parseFn.call(this, attStmt);

        // validate return
        if (!(ret instanceof Map)) {
            throw new Error(`${fmt} parseFn did not return a Map`);
        }

        // return result
        return new Map([
            ["fmt", fmt],
            ...ret
        ]);
    }

    // must be called with context / `this` of a response
    static async validateAttestation() {
        var fmt = this.authnrData.get("fmt");

        // validate input
        if (typeof fmt !== "string") {
            throw new TypeError("expected 'fmt' to be string, got: " + typeof fmt);
        }

        // get from attestationMap
        var fmtObj = globalAttestationMap.get(fmt);
        if (typeof fmtObj !== "object" ||
            typeof fmtObj.parseFn !== "function" ||
            typeof fmtObj.validateFn !== "function") {
            throw new Error(`no support for attestation format: ${fmt}`);
        }

        // call fn
        var ret = await fmtObj.validateFn.call(this);

        // validate return
        if (ret !== true) {
            throw new Error(`${fmt} validateFn did not return 'true'`);
        }

        // return result
        return ret;
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

// add 'none' attestation format
const noneAttestation = require("./attestations/none");
Fido2Lib.addAttestationFormat(
    noneAttestation.name,
    noneAttestation.parseFn,
    noneAttestation.validateFn
);

// add 'fido-u2f' attestation format
const u2fAttestation = require("./attestations/fidoU2F");
Fido2Lib.addAttestationFormat(
    u2fAttestation.name,
    u2fAttestation.parseFn,
    u2fAttestation.validateFn
);

module.exports = {
    Fido2Lib
};
