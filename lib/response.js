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
            journal: new Set()
        };

        validator.attach(this);
    }

    parse() {
        // TODO: id
        this.clientData = parser.parseClientResponse(this.request);
    }

    validate() {
        // clientData, except type
        this.validateRawClientDataJson();
        this.validateOrigin();
        this.validateChallenge();
        this.validateTokenBinding();
        this.validateId();

        // authenticatorData, minus attestation
        this.validateRawAuthnrData();
        this.validateRpIdHash();
        this.validateFlags();
    }

    create(req, exp) {
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
        this.validateExpectations();

        // parse and validate all the request fields (CBOR, etc.)
        this.parse();
        this.validate();

        // ensure the parsing and validation went well
        this.validateAudit();

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
        this.authnrData = parser.parseAttestationObject(this.request.response.attestationObject, this.parseAttestationFn);
    }

    validate() {
        this.validateCreateRequest();
        this.validateCreateType();
        super.validate();
        this.validateAttestation();
        this.validateInitialCounter();
        this.validatePublicKey();
        this.validateAaguid();
        this.validateCredId();
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

    validate() {
        this.validateAssertionResponse();
        this.validateGetType();
        super.validate();
        this.validateAssertionSignature();
        this.validateUserHandle();
        this.validateCounter();
    }

    static create(req, exp) {
        var ret = new Fido2GetResponse(lockSym).create(req, exp);
        return ret;
    }
}

module.exports = {
    Fido2Response,
    Fido2CreateResponse,
    Fido2GetResponse
};