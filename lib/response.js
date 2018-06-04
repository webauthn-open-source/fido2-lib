"use strict";

const validator = require("./validator");
const parser = require("./parser");
const lockSym = Symbol();

/**
 * The base class of {@link Fido2AttestationResult} and
 */
class Fido2Result {
    constructor(sym) {
        if (sym !== lockSym) {
            throw new Error("Do not create with 'new' operator. Call 'Fido2AttestationResult.create()' or 'Fido2AssertionResult.create()' instead.");
        }

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

/**
 * A validated attesetation result
 */
class Fido2AttestationResult extends Fido2Result {
    constructor(sym) {
        super(sym);

        this.requiredExpectations = new Set([
            "origin",
            "challenge",
            "flags"
        ]);
    }

    parse() {
        this.validateCreateRequest();
        super.parse();
        this.authnrData = parser.parseAttestationObject(this.request.response.attestationObject);
    }

    async validate() {
        await this.validateCreateType();
        await super.validate();
        await this.validateAttestation();
        await this.validateInitialCounter();
        await this.validatePublicKey();
        await this.validateAaguid();
        await this.validateCredId();
    }

    static create(req, exp) {
        return new Fido2AttestationResult(lockSym).create(req, exp);
    }
}

/**
 * A validated assertion result
 */
class Fido2AssertionResult extends Fido2Result {
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
        this.validateAssertionResponse();
        super.parse();
        this.authnrData = parser.parseAuthnrAssertionResponse(this.request);
    }

    async validate() {
        await this.validateGetType();
        await super.validate();
        await this.validateAssertionSignature();
        await this.validateUserHandle();
        await this.validateCounter();
    }

    static create(req, exp) {
        return new Fido2AssertionResult(lockSym).create(req, exp);
    }
}

module.exports = {
    Fido2Result,
    Fido2AttestationResult,
    Fido2AssertionResult
};
