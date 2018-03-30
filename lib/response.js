"use strict";

const validator = require("./validator");
const parser = require("./parser");
const lockSym = Symbol();

class Fido2Response {
    constructor(sym) {
        if (sym !== lockSym) {
            throw new Error("Do not create with 'new' operator. Call 'Fido2CreateResponse.create()' or 'Fido2GetResponse.create()' instead.");
        }

        this.audit = {
            validExpectations: false,
            validRequest: false,
            complete: false,
            journal: new Set(),
            warning: new Map(),
            info: new Map()
        };

        validator.attach(this);
    }

    parse() {
        // TODO: id
        this.clientData = parser.parseClientResponse(this.request);
    }

    async validate() {
        // clientData, except type
        await this.validateRawClientDataJson();
        await this.validateOrigin();
        await this.validateChallenge();
        await this.validateTokenBinding();
        await this.validateId();

        // authenticatorData, minus attestation
        await this.validateRawAuthnrData();
        await this.validateRpIdHash();
        await this.validateFlags();
    }

    async create(req, exp) {
        console.log("CREATE ARGS:");
        console.log("REQUEST:", req);
        console.log("EXPECT:", exp);

        if (typeof req !== "object") {
            throw new TypeError("expected 'request' to be object, got: " + typeof req);
        }

        if (typeof exp !== "object") {
            throw new TypeError("expected 'expectations' to be object, got: " + typeof exp);
        }

        this.expectations = parser.parseExpectations(exp);
        this.request = req;

        // validate that input expectations and request are complete and in the right format
        await this.validateExpectations();

        // parse and validate all the request fields (CBOR, etc.)
        await this.parse();
        await this.validate();

        // ensure the parsing and validation went well
        await this.validateAudit();

        return this;
    }
}

class Fido2CreateResponse extends Fido2Response {
    constructor(sym) {
        super(sym);

        this.requiredExpectations = new Set([
            "origin",
            "challenge",
            "flags"
        ]);
    }

    parse() {
        super.parse();
        this.authnrData = parser.parseAttestationObject(this.request.response.attestationObject);
    }

    async validate() {
        await this.validateCreateRequest();
        await this.validateCreateType();
        await super.validate();
        await this.validateAttestation();
        await this.validateInitialCounter();
        await this.validatePublicKey();
        await this.validateAaguid();
        await this.validateCredId();
    }

    static create(req, exp) {
        return new Fido2CreateResponse(lockSym).create(req, exp);
    }
}

class Fido2GetResponse extends Fido2Response {
    constructor(sym) {
        super(sym);
        this.requiredExpectations = new Set([
            "origin",
            "challenge",
            "flags",
            "prevCounter",
            "publicKey"
        ]);
    }

    parse() {
        super.parse();
        this.authnrData = parser.parseAuthnrAssertionResponse(this.request);
    }

    async validate() {
        await this.validateAssertionResponse();
        await this.validateGetType();
        await super.validate();
        await this.validateAssertionSignature();
        await this.validateUserHandle();
        await this.validateCounter();
    }

    static create(req, exp) {
        return new Fido2GetResponse(lockSym).create(req, exp);
    }
}

module.exports = {
    Fido2Response,
    Fido2CreateResponse,
    Fido2GetResponse
};
