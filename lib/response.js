"use strict";

const validator = require("./validator");
const parser = require("./parser");
const lockSym = Symbol();

/**
 * The base class of {@link Fido2AttestationResult} and {@link Fido2AssertionResult}
 * @property {Map} authnrData Authenticator data that was parsed and validated
 * @property {Map} clientData Client data that was parsed and validated
 * @property {Map} expectations The expectations that were used to validate the result
 * @property {Object} request The request that was validated
 * @property {Map} audit A collection of audit information, such as useful warnings and information. May be useful for risk engines or for debugging.
 * @property {Boolean} audit.validExpectations Whether the expectations that were provided were complete and valid
 * @property {Boolean} audit.validRequest Whether the request message was complete and valid
 * @property {Boolean} audit.complete Whether all fields in the result have been validated
 * @property {Set} audit.journal A list of the fields that were validated
 * @property {Map} audit.warning A set of warnings that were generated while validating the result
 * @property {Map} audit.info A set of informational fields that were generated while validating the result. Includes any x509 extensions of the attestation certificate during registration, and whether the key supports a rollback counter during authentication.
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
 * @extends {Fido2Result}
 */
class Fido2AttestationResult extends Fido2Result {
	constructor(sym) {
		super(sym);

		this.requiredExpectations = new Set([
			"origin",
			"challenge",
			"flags",
		]);
		this.optionalExpectations = new Set([
			"rpId",
		]);
	}

	parse() {
		this.validateCreateRequest();
		super.parse();
		this.authnrData = parser.parseAuthnrAttestationResponse(this.request);
	}

	async validate() {
		await this.validateCreateType();
		await this.validateAaguid();
		await this.validatePublicKey();
		await super.validate();
		await this.validateAttestation();
		await this.validateInitialCounter();
		await this.validateCredId();
		await this.validateTransports();
	}

	static create(req, exp) {
		return new Fido2AttestationResult(lockSym).create(req, exp);
	}
}

/**
 * A validated assertion result
 * @extends {Fido2Result}
 */
class Fido2AssertionResult extends Fido2Result {
	constructor(sym) {
		super(sym);
		this.requiredExpectations = new Set([
			"origin",
			"challenge",
			"flags",
			"prevCounter",
			"publicKey",
			"userHandle",
		]);
		this.optionalExpectations = new Set([
			"rpId",
			"allowCredentials",
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
	Fido2AssertionResult,
};
