/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

"use strict";

var crypto = require("crypto");
var { URL } = require("url");
var {
	isBase64Url,
	checkOrigin,
	checkRpId,
	abEqual,
	isPem,
	isPositiveInteger,
	coerceToBase64Url,
	coerceToArrayBuffer,
} = require("./utils");
var Fido2Lib;

async function validateExpectations() {
	/* eslint complexity: ["off"] */
	var req = this.requiredExpectations;
	var opt = this.optionalExpectations;
	var exp = this.expectations;

	if (!(exp instanceof Map)) {
		throw new Error("expectations should be of type Map");
	}

	if (Array.isArray(req)) {
		req = new Set([req]);
	}

	if (!(req instanceof Set)) {
		throw new Error("requiredExpectaions should be of type Set");
	}

	if (Array.isArray(opt)) {
		opt = new Set([opt]);
	}

	if (!(opt instanceof Set)) {
		throw new Error("optionalExpectations should be of type Set");
	}

	for (let field of req) {
		if (!exp.has(field)) {
			throw new Error(`expectation did not contain value for '${field}'`);
		}
	}

	let optCount = 0;
	for (const [field] of exp) {
		if (opt.has(field)) {
			optCount++;
		}
	}

	if (req.size !== exp.size - optCount) {
		throw new Error(`wrong number of expectations: should have ${req.size} but got ${exp.size - optCount}`);
	}

	// origin - isValid
	if (req.has("origin")) {
		var expectedOrigin = exp.get("origin");

		checkOrigin(expectedOrigin);
	}

	// rpId - optional, isValid
	if (exp.has("rpId")) {
		var expectedRpId = exp.get("rpId");

		checkRpId(expectedRpId);
	}

	// challenge - is valid base64url string
	if (exp.has("challenge")) {
		var challenge = exp.get("challenge");
		if (typeof challenge !== "string") {
			throw new Error("expected challenge should be of type String, got: " + typeof challenge);
		}

		if (!isBase64Url(challenge)) {
			throw new Error("expected challenge should be properly encoded base64url String");
		}
	}

	// flags - is Array or Set
	if (req.has("flags")) {
		var validFlags = new Set(["UP", "UV", "UP-or-UV", "AT", "ED"]);
		var flags = exp.get("flags");

		for (let flag of flags) {
			if (!validFlags.has(flag)) {
				throw new Error(`expected flag unknown: ${flag}`);
			}
		}
	}

	// prevCounter
	if (req.has("prevCounter")) {
		var prevCounter = exp.get("prevCounter");

		if (!isPositiveInteger(prevCounter)) {
			throw new Error("expected counter to be positive integer");
		}
	}

	// publicKey
	if (req.has("publicKey")) {
		var publicKey = exp.get("publicKey");
		if (!isPem(publicKey)) {
			throw new Error("expected publicKey to be in PEM format");
		}
	}

	// userHandle
	if (req.has("userHandle")) {
		var userHandle = exp.get("userHandle");
		if (userHandle !== null &&
			typeof userHandle !== "string") {
			throw new Error("expected userHandle to be null or string");
		}
	}


	// allowCredentials
	if (exp.has("allowCredentials")) {
		var allowCredentials = exp.get("allowCredentials");
		if (allowCredentials != null) {
			if (!Array.isArray(allowCredentials)) {
				throw new Error("expected allowCredentials to be null or array");
			} else {
				for (const index in allowCredentials) {
					if (typeof allowCredentials[index].id === "string") {
						allowCredentials[index].id = coerceToArrayBuffer(allowCredentials[index].id, "allowCredentials[" + index + "].id");
					}
					if (allowCredentials[index].id == null || !(allowCredentials[index].id instanceof ArrayBuffer)) {
						throw new Error("expected id of allowCredentials[" + index + "] to be ArrayBuffer");
					}
					if (allowCredentials[index].type == null || allowCredentials[index].type !== "public-key") {
						throw new Error("expected type of allowCredentials[" + index + "] to be string with value 'public-key'");
					}
					if (allowCredentials[index].transports != null && !Array.isArray(allowCredentials[index].transports)) {
						throw new Error("expected transports of allowCredentials[" + index + "] to be array or null");
					} else if (allowCredentials[index].transports != null && !allowCredentials[index].transports.every(el => ["usb", "nfc", "ble", "internal"].includes(el))) {
						throw new Error("expected transports of allowCredentials[" + index + "] to be string with value 'usb', 'nfc', 'ble', 'internal' or null");
					}
				}
			}
		}

	}

	this.audit.validExpectations = true;

	return true;
}

function validateCreateRequest() {
	var req = this.request;

	if (typeof req !== "object") {
		throw new TypeError("expected request to be Object, got " + typeof req);
	}

	if (!(req.rawId instanceof ArrayBuffer) &&
		!(req.id instanceof ArrayBuffer)) {
		throw new TypeError("expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId " + typeof req.rawId + " and id " + typeof req.id);
	}

	if (typeof req.response !== "object") {
		throw new TypeError("expected 'response' field of request to be Object, got " + typeof req.response);
	}

	if (typeof req.response.attestationObject !== "string" &&
		!(req.response.attestationObject instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.attestationObject' to be base64 String or ArrayBuffer");
	}

	if (typeof req.response.clientDataJSON !== "string" &&
		!(req.response.clientDataJSON instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
	}

	this.audit.validRequest = true;

	return true;
}

function validateAssertionResponse() {
	var req = this.request;

	if (typeof req !== "object") {
		throw new TypeError("expected request to be Object, got " + typeof req);
	}

	if (!(req.rawId instanceof ArrayBuffer) &&
		!(req.id instanceof ArrayBuffer)) {
		throw new TypeError("expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId " + typeof req.rawId + " and id " + typeof req.id);
	}

	if (typeof req.response !== "object") {
		throw new TypeError("expected 'response' field of request to be Object, got " + typeof req.response);
	}

	if (typeof req.response.clientDataJSON !== "string" &&
		!(req.response.clientDataJSON instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
	}

	if (typeof req.response.authenticatorData !== "string" &&
		!(req.response.authenticatorData instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.authenticatorData' to be base64 String or ArrayBuffer");
	}

	if (typeof req.response.signature !== "string" &&
		!(req.response.signature instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.signature' to be base64 String or ArrayBuffer");
	}

	if (typeof req.response.userHandle !== "string" &&
		!(req.response.userHandle instanceof ArrayBuffer) &&
		req.response.userHandle !== undefined) {
		throw new TypeError("expected 'response.userHandle' to be base64 String, ArrayBuffer, or undefined");
	}

	this.audit.validRequest = true;

	return true;
}

async function validateRawClientDataJson() {
	// XXX: this isn't very useful, since this has already been parsed...
	var rawClientDataJson = this.clientData.get("rawClientDataJson");

	if (!(rawClientDataJson instanceof ArrayBuffer)) {
		throw new Error("clientData clientDataJson should be ArrayBuffer");
	}

	this.audit.journal.add("rawClientDataJson");

	return true;
}

async function validateTransports() {
	var transports = this.authnrData.get("transports");

	if (transports != null && !Array.isArray(transports)) {
		throw new Error("expected transports to be 'null' or 'array<string>'");
	}

	for (const index in transports) {
		if (typeof transports[index] !== "string") {
			throw new Error("expected transports[" + index + "] to be 'string'");
		}
	}

	this.audit.journal.add("transports");

	return true;
}

async function validateId() {
	var rawId = this.clientData.get("rawId");

	if (!(rawId instanceof ArrayBuffer)) {
		throw new Error("expected id to be of type ArrayBuffer");
	}

	var credId = this.authnrData.get("credId");
	if (credId !== undefined && !abEqual(rawId, credId)) {
		throw new Error("id and credId were not the same");
	}
	
	var allowCredentials = this.expectations.get("allowCredentials");

	if (allowCredentials != undefined) {
		if (!allowCredentials.some(cred => {
			var result = abEqual(rawId, cred.id);
			return result;
		}
		)) {
			throw new Error("Credential ID does not match any value in allowCredentials");
		}
	}

	this.audit.journal.add("rawId");

	return true;
}


async function validateOrigin() {
	var expectedOrigin = this.expectations.get("origin");
	var clientDataOrigin = this.clientData.get("origin");

	var origin = checkOrigin(clientDataOrigin);

	if (origin !== expectedOrigin) {
		throw new Error("clientData origin did not match expected origin");
	}

	this.audit.journal.add("origin");

	return true;
}

async function validateCreateType() {
	var type = this.clientData.get("type");

	if (type !== "webauthn.create") {
		throw new Error("clientData type should be 'webauthn.create', got: " + type);
	}

	this.audit.journal.add("type");

	return true;
}

async function validateGetType() {
	var type = this.clientData.get("type");

	if (type !== "webauthn.get") {
		throw new Error("clientData type should be 'webauthn.get'");
	}

	this.audit.journal.add("type");

	return true;
}

async function validateChallenge() {
	var expectedChallenge = this.expectations.get("challenge");
	var challenge = this.clientData.get("challenge");

	if (typeof challenge !== "string") {
		throw new Error("clientData challenge was not a string");
	}

	if (!isBase64Url(challenge)) {
		throw new TypeError("clientData challenge was not properly encoded base64url");
	}

	challenge = challenge.replace(/={1,2}$/, "");

	// console.log("challenge", challenge);
	// console.log("expectedChallenge", expectedChallenge);
	if (challenge !== expectedChallenge) {
		throw new Error("clientData challenge mismatch");
	}

	this.audit.journal.add("challenge");

	return true;
}

async function validateTokenBinding() {
	// TODO: node.js can't support token binding right now :(
	var tokenBinding = this.clientData.get("tokenBinding");

	if (typeof tokenBinding === "object") {
		if (tokenBinding.status !== "not-supported" &&
			tokenBinding.status !== "supported") {
			throw new Error("tokenBinding status should be 'not-supported' or 'supported', got: " + tokenBinding.status);
		}

		if (Object.keys(tokenBinding).length != 1) {
			throw new Error("tokenBinding had too many keys");
		}
	} else if (tokenBinding !== undefined) {
		throw new Error("Token binding field malformed: " + tokenBinding);
	}

	// TODO: add audit.info for token binding status so that it can be used for policies, risk, etc.
	this.audit.journal.add("tokenBinding");

	return true;
}

async function validateRawAuthnrData() {
	// XXX: this isn't very useful, since this has already been parsed...
	var rawAuthnrData = this.authnrData.get("rawAuthnrData");

	if (!(rawAuthnrData instanceof ArrayBuffer)) {
		throw new Error("authnrData rawAuthnrData should be ArrayBuffer");
	}

	this.audit.journal.add("rawAuthnrData");

	return true;
}

async function validateAttestation() {
	// have to require here to prevent circular dependency
	if (!Fido2Lib) Fido2Lib = require("../index").Fido2Lib; // eslint-disable-line global-require

	return Fido2Lib.validateAttestation.call(this);
}

async function validateAssertionSignature() {
	var expectedSignature = this.authnrData.get("sig");
	var publicKey = this.expectations.get("publicKey");
	var rawAuthnrData = this.authnrData.get("rawAuthnrData");
	var rawClientData = this.clientData.get("rawClientDataJson");

	// console.log("publicKey", publicKey);
	// printHex("expectedSignature", expectedSignature);
	// printHex("rawAuthnrData", rawAuthnrData);
	// printHex("rawClientData", rawClientData);

	const hash = crypto.createHash("SHA256");
	hash.update(abToBuf(rawClientData));
	var clientDataHashBuf = hash.digest();
	var clientDataHash = new Uint8Array(clientDataHashBuf).buffer;

	// printHex("clientDataHash", clientDataHash);

	const verify = crypto.createVerify("SHA256");
	verify.write(abToBuf(rawAuthnrData));
	verify.write(abToBuf(clientDataHash));
	verify.end();
	var res = verify.verify(publicKey, abToBuf(expectedSignature));
	if (!res) {
		throw new Error("signature validation failed");
	}

	this.audit.journal.add("sig");

	return true;
}

function abToBuf(ab) {
	return Buffer.from(new Uint8Array(ab));
}

async function validateRpIdHash() {
	var rpIdHash = this.authnrData.get("rpIdHash");

	if (rpIdHash instanceof Buffer) {
		rpIdHash = new Uint8Array(rpIdHash).buffer;
	}

	if (!(rpIdHash instanceof ArrayBuffer)) {
		throw new Error("couldn't coerce clientData rpIdHash to ArrayBuffer");
	}

	var domain = this.expectations.has("rpId")
		? this.expectations.get("rpId")
		: new URL(this.expectations.get("origin")).hostname;
	var createdHash = new Uint8Array(crypto.createHash("sha256").update(domain).digest()).buffer;

	// wouldn't it be weird if two SHA256 hashes were different lengths...?
	if (rpIdHash.byteLength !== createdHash.byteLength) {
		throw new Error("authnrData rpIdHash length mismatch");
	}

	rpIdHash = new Uint8Array(rpIdHash);
	createdHash = new Uint8Array(createdHash);
	for (let i = 0; i < rpIdHash.byteLength; i++) {
		if (rpIdHash[i] !== createdHash[i]) {
			throw new TypeError("authnrData rpIdHash mismatch");
		}
	}

	this.audit.journal.add("rpIdHash");

	return true;
}

async function validateFlags() {
	var expectedFlags = this.expectations.get("flags");
	var flags = this.authnrData.get("flags");

	for (let expFlag of expectedFlags) {
		if (expFlag === "UP-or-UV") {
			if (flags.has("UV")) {
				if (flags.has("UP")) {
					continue;
				} else {
					throw new Error("expected User Presence (UP) flag to be set if User Verification (UV) is set");
				}
			} else if (flags.has("UP")) {
				continue;
			} else {
				throw new Error("expected User Presence (UP) or User Verification (UV) flag to be set and neither was");
			}
		}

		if (expFlag === "UV") {
			if (flags.has("UV")) {
				if (flags.has("UP")) {
					continue;
				} else {
					throw new Error("expected User Presence (UP) flag to be set if User Verification (UV) is set");
				}
			} else {
				throw new Error(`expected flag was not set: ${expFlag}`);
			}
		}

		if (!flags.has(expFlag)) {
			throw new Error(`expected flag was not set: ${expFlag}`);
		}
	}

	this.audit.journal.add("flags");

	return true;
}

async function validateInitialCounter() {
	var counter = this.authnrData.get("counter");

	// TODO: does counter need to be zero initially? probably not... I guess..
	if (typeof counter !== "number") {
		throw new Error("authnrData counter wasn't a number");
	}

	this.audit.journal.add("counter");

	return true;
}

async function validateAaguid() {
	var aaguid = this.authnrData.get("aaguid");

	if (!(aaguid instanceof ArrayBuffer)) {
		throw new Error("authnrData AAGUID is not ArrayBuffer");
	}

	if (aaguid.byteLength !== 16) {
		throw new Error("authnrData AAGUID was wrong length");
	}

	this.audit.journal.add("aaguid");

	return true;
}

async function validateCredId() {
	var credId = this.authnrData.get("credId");
	var credIdLen = this.authnrData.get("credIdLen");

	if (!(credId instanceof ArrayBuffer)) {
		throw new Error("authnrData credId should be ArrayBuffer");
	}

	if (typeof credIdLen !== "number") {
		throw new Error("authnrData credIdLen should be number, got " + typeof credIdLen);
	}

	if (credId.byteLength !== credIdLen) {
		throw new Error("authnrData credId was wrong length");
	}

	this.audit.journal.add("credId");
	this.audit.journal.add("credIdLen");

	return true;
}

async function validatePublicKey() {
	// XXX: the parser has already turned this into PEM at this point
	// if something were malformatted or wrong, we probably would have
	// thrown an error well before this.
	// Maybe we parse the ASN.1 and make sure attributes are correct?
	// Doesn't seem very worthwhile...

	var cbor = this.authnrData.get("credentialPublicKeyCose");
	var jwk = this.authnrData.get("credentialPublicKeyJwk");
	var pem = this.authnrData.get("credentialPublicKeyPem");

	// cbor
	if (!(cbor instanceof ArrayBuffer)) {
		throw new Error("authnrData credentialPublicKeyCose isn't of type ArrayBuffer");
	}
	this.audit.journal.add("credentialPublicKeyCose");

	// jwk
	if (typeof jwk !== "object") {
		throw new Error("authnrData credentialPublicKeyJwk isn't of type Object");
	}

	if (typeof jwk.kty !== "string") {
		throw new Error("authnrData credentialPublicKeyJwk.kty isn't of type String");
	}

	if (typeof jwk.alg !== "string") {
		throw new Error("authnrData credentialPublicKeyJwk.alg isn't of type String");
	}

	switch (jwk.kty) {
		case "EC":
			if (typeof jwk.crv !== "string") {
				throw new Error("authnrData credentialPublicKeyJwk.crv isn't of type String");
			}
			break;
		case "RSA":
			if (typeof jwk.n !== "string") {
				throw new Error("authnrData credentialPublicKeyJwk.n isn't of type String");
			}

			if (typeof jwk.e !== "string") {
				throw new Error("authnrData credentialPublicKeyJwk.e isn't of type String");
			}
			break;
		default:
			throw new Error("authnrData unknown JWK key type: " + jwk.kty);
	}

	this.audit.journal.add("credentialPublicKeyJwk");

	// pem
	if (typeof pem !== "string") {
		throw new Error("authnrData credentialPublicKeyPem isn't of type String");
	}

	if (!isPem(pem)) {
		throw new Error("authnrData credentialPublicKeyPem was malformatted");
	}
	this.audit.journal.add("credentialPublicKeyPem");

	return true;
}

async function validateUserHandle() {
	var userHandle = this.authnrData.get("userHandle");

	if (userHandle === undefined ||
		userHandle === null ||
		userHandle === "") {
		this.audit.journal.add("userHandle");
		return true;
	}

	userHandle = coerceToBase64Url(userHandle, "userHandle");
	var expUserHandle = this.expectations.get("userHandle");
	if (typeof userHandle === "string" &&
		userHandle === expUserHandle) {
		this.audit.journal.add("userHandle");
		return true;
	}

	throw new Error("unable to validate userHandle");
}

async function validateCounter() {
	var prevCounter = this.expectations.get("prevCounter");
	var counter = this.authnrData.get("counter");
	var counterSupported = !(counter === 0 && prevCounter === 0);

	if (counter <= prevCounter && counterSupported) {
		throw new Error("counter rollback detected");
	}

	this.audit.journal.add("counter");
	this.audit.info.set("counter-supported", "" + counterSupported);

	return true;
}

async function validateAudit() {
	var journal = this.audit.journal;
	var clientData = this.clientData;
	var authnrData = this.authnrData;

	for (let kv of clientData) {
		let val = kv[0];
		if (!journal.has(val)) {
			throw new Error(`internal audit failed: ${val} was not validated`);
		}
	}

	for (let kv of authnrData) {
		let val = kv[0];
		if (!journal.has(val)) {
			throw new Error(`internal audit failed: ${val} was not validated`);
		}
	}

	if (journal.size !== (clientData.size + authnrData.size)) {
		throw new Error(`internal audit failed: ${journal.size} fields checked; expected ${clientData.size + authnrData.size}`);
	}

	if (!this.audit.validExpectations) {
		throw new Error("internal audit failed: expectations not validated");
	}

	if (!this.audit.validRequest) {
		throw new Error("internal audit failed: request not validated");
	}

	this.audit.complete = true;

	return true;
}

function attach(o) {
	var mixins = {
		validateExpectations,
		validateCreateRequest,
		// clientData validators
		validateRawClientDataJson,
		validateOrigin,
		validateId,
		validateCreateType,
		validateGetType,
		validateChallenge,
		validateTokenBinding,
		validateTransports,
		// authnrData validators		
		validateRawAuthnrData,
		validateAttestation,
		validateAssertionSignature,
		validateRpIdHash,
		validateAaguid,
		validateCredId,
		validatePublicKey,
		validateFlags,
		validateUserHandle,
		validateCounter,
		validateInitialCounter,
		validateAssertionResponse,
		// audit structures
		audit: {
			validExpectations: false,
			validRequest: false,
			complete: false,
			journal: new Set(),
			warning: new Map(),
			info: new Map(),
		},
		validateAudit,
	};

	for (let key of Object.keys(mixins)) {
		o[key] = mixins[key];
	}
}

module.exports = {
	attach,
};
