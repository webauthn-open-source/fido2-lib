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
        this.clientData = parser.parseClientData(this.request.response.clientDataJSON);
    }

    validate() {
        // clientData, except type
        this.validateRawClientDataJson();
        this.validateOrigin();
        this.validateChallenge();
        this.validateTokenBinding();

        // authenticatorData, minus attestation
        this.validateRawAuthData();
        this.validateRpIdHash();
        this.validateFlags();
    }

    create(req, exp) {
        this.expectations = parser.parseExpectations(exp);
        this.request = req;

        // validate that input expectations and request are complete and in the right format
        this.validateExpectations();
        this.validateCreateRequest();

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
        this.authnrData = parser.parseAttestationObject(this.request.response.attestationObject);
    }

    validate() {
        this.validateCreateType();
        super.validate();
        this.validateAttestationSignature();
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
        this.requiredExpectations = [
            "origin",
            "challenge",
            "flags",
            "counter",
            "publicKey"
        ];
    }

    parse() {
        super.parse();
        // parseAuthenticatorData
    }

    validate() {
        super.validate();
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