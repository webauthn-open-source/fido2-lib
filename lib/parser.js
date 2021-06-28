"use strict";

const cbor = require("cbor");
const jwkToPem = require("jwk-to-pem");
const coseToJwk = require("cose-to-jwk");
var Fido2Lib;
const {
	coerceToBase64Url,
	coerceToArrayBuffer,
	checkOrigin,
	checkRpId,
	ab2str,
} = require("./utils");

// NOTE: throws if origin is https and has port 443
// use `new URL(originstr).origin` to create a properly formatted origin
function parseExpectations(exp) {
	if (typeof exp !== "object") {
		throw new TypeError("expected 'expectations' to be of type object, got " + typeof exp);
	}

	var ret = new Map();

	// origin
	if (exp.origin) {
		if (typeof exp.origin !== "string") {
			throw new TypeError("expected 'origin' should be string, got " + typeof exp.origin);
		}

		let origin = checkOrigin(exp.origin);
		ret.set("origin", origin);
	}

	// rpId
	if (exp.rpId) {
		if (typeof exp.rpId !== "string") {
			throw new TypeError("expected 'rpId' should be string, got " + typeof exp.rpId);
		}

		let rpId = checkRpId(exp.rpId);
		ret.set("rpId", rpId);
	}

	// challenge
	if (exp.challenge) {
		var challenge = exp.challenge;
		challenge = coerceToBase64Url(challenge, "expected challenge");
		ret.set("challenge", challenge);
	}

	// flags
	if (exp.flags) {
		var flags = exp.flags;

		if (Array.isArray(flags)) {
			flags = new Set(flags);
		}

		if (!(flags instanceof Set)) {
			throw new TypeError("expected flags to be an Array or a Set, got: " + typeof flags);
		}

		ret.set("flags", flags);
	}

	// counter
	if (exp.prevCounter !== undefined) {
		if (typeof exp.prevCounter !== "number") {
			throw new TypeError("expected 'prevCounter' should be Number, got " + typeof exp.prevCounter);
		}

		ret.set("prevCounter", exp.prevCounter);
	}

	// publicKey
	if (exp.publicKey) {
		if (typeof exp.publicKey !== "string") {
			throw new TypeError("expected 'publicKey' should be String, got " + typeof exp.publicKey);
		}

		ret.set("publicKey", exp.publicKey);
	}

	// userHandle
	if (exp.userHandle !== undefined) {
		var userHandle = exp.userHandle;
		if (userHandle !== null && userHandle !== "") userHandle = coerceToBase64Url(userHandle, "userHandle");
		ret.set("userHandle", userHandle);
	}


	// allowCredentials
	if (exp.allowCredentials !== undefined) {

		var allowCredentials = exp.allowCredentials;

		if (allowCredentials !== null && !Array.isArray(allowCredentials)) {
			throw new TypeError("expected 'allowCredentials' to be null or array, got " + typeof allowCredentials);
		}

		for (const index in allowCredentials) {
			if (allowCredentials[index].id != null) {
				allowCredentials[index].id = coerceToArrayBuffer(allowCredentials[index].id, "allowCredentials[" + index + "].id");
			}
		}
		ret.set("allowCredentials", allowCredentials);
	}

	return ret;
}

/**
 * Parses the clientData JSON byte stream into an Object
 * @param  {ArrayBuffer} clientDataJSON The ArrayBuffer containing the properly formatted JSON of the clientData object
 * @return {Object}                The parsed clientData object
 */
function parseClientResponse(msg) {
	if (typeof msg !== "object") {
		throw new TypeError("expected msg to be Object");
	}

	if (msg.id && !msg.rawId) {
		msg.rawId = msg.id;
	}
	var rawId = coerceToArrayBuffer(msg.rawId, "rawId");

	if (typeof msg.response !== "object") {
		throw new TypeError("expected response to be Object");
	}

	var clientDataJSON = coerceToArrayBuffer(msg.response.clientDataJSON, "clientDataJSON");
	if (!(clientDataJSON instanceof ArrayBuffer)) {
		throw new TypeError("expected 'clientDataJSON' to be ArrayBuffer");
	}

	// printHex("clientDataJSON", clientDataJSON);

	// convert to string
	var clientDataJson = ab2str(clientDataJSON);

	// parse JSON string
	var parsed;
	try {
		parsed = JSON.parse(clientDataJson);
	} catch (err) {
		throw new Error("couldn't parse clientDataJson: " + err);
	}

	var ret = new Map([
		["challenge", parsed.challenge],
		["origin", parsed.origin],
		["type", parsed.type],
		["tokenBinding", parsed.tokenBinding],
		["rawClientDataJson", clientDataJSON],
		["rawId", rawId],
	]);

	return ret;
}

/**
 * @deprecated
 * Parses the CBOR attestation statement
 * @param  {ArrayBuffer} attestationObject The CBOR byte array representing the attestation statement
 * @return {Object}                   The Object containing all the attestation information
 * @see https://w3c.github.io/webauthn/#generating-an-attestation-object
 * @see  https://w3c.github.io/webauthn/#defined-attestation-formats
 */
function parseAttestationObject(attestationObject) {
	// update docs to say ArrayBuffer-ish object
	attestationObject = coerceToArrayBuffer(attestationObject, "attestationObject");

	// parse attestation
	var parsed;
	try {
		parsed = cbor.decodeAllSync(Buffer.from(attestationObject));
	} catch (err) {
		throw new TypeError("couldn't parse attestationObject CBOR");
	}

	if (!Array.isArray(parsed) || typeof parsed[0] !== "object") {
		throw new TypeError("invalid parsing of attestationObject CBOR");
	}
	parsed = parsed[0];

	if (typeof parsed.fmt !== "string") {
		throw new Error("expected attestation CBOR to contain a 'fmt' string");
	}

	if (typeof parsed.attStmt !== "object") {
		throw new Error("expected attestation CBOR to contain a 'attStmt' object");
	}

	if (!(parsed.authData instanceof Buffer)) {
		throw new Error("expected attestation CBOR to contain a 'authData' byte sequence");
	}

	// have to require here to prevent circular dependency
	if (!Fido2Lib) Fido2Lib = require("../index").Fido2Lib; // eslint-disable-line global-require
	var ret = new Map([
		...Fido2Lib.parseAttestation(parsed.fmt, parsed.attStmt),
		// return raw buffer for future signature verification
		["rawAuthnrData", coerceToArrayBuffer(parsed.authData, "authData")],
		// Added for compatibility with parseAuthnrAttestationResponse
		["transports", undefined],
		// parse authData
		...parseAuthenticatorData(parsed.authData),
	]);

	return ret;
}

function parseAuthnrAttestationResponse(msg) {

	if (typeof msg !== "object") {
		throw new TypeError("expected msg to be Object");
	}

	if (typeof msg.response !== "object") {
		throw new TypeError("expected response to be Object");
	}

	var attestationObject = msg.response.attestationObject;

	// update docs to say ArrayBuffer-ish object
	attestationObject = coerceToArrayBuffer(attestationObject, "attestationObject");

	// parse attestation
	var parsed;
	try {
		parsed = cbor.decodeAllSync(Buffer.from(attestationObject));
	} catch (err) {
		throw new TypeError("couldn't parse attestationObject CBOR");
	}

	if (!Array.isArray(parsed) || typeof parsed[0] !== "object") {
		throw new TypeError("invalid parsing of attestationObject CBOR");
	}
	parsed = parsed[0];

	if (typeof parsed.fmt !== "string") {
		throw new Error("expected attestation CBOR to contain a 'fmt' string");
	}

	if (typeof parsed.attStmt !== "object") {
		throw new Error("expected attestation CBOR to contain a 'attStmt' object");
	}

	if (!(parsed.authData instanceof Buffer)) {
		throw new Error("expected attestation CBOR to contain a 'authData' byte sequence");
	}

	if (msg.transports != undefined && !Array.isArray(msg.transports)) {
		throw new Error("expected transports to be 'null' or 'array<string>'");
	}

	// have to require here to prevent circular dependency
	if (!Fido2Lib) Fido2Lib = require("../index").Fido2Lib; // eslint-disable-line global-require
	var ret = new Map([
		...Fido2Lib.parseAttestation(parsed.fmt, parsed.attStmt),
		// return raw buffer for future signature verification
		["rawAuthnrData", coerceToArrayBuffer(parsed.authData, "authData")],
		["transports", msg.transports],
		// parse authData
		...parseAuthenticatorData(parsed.authData),
	]);

	return ret;
}

function parseAuthenticatorData(authnrDataArrayBuffer) {
	// convert to ArrayBuffer
	authnrDataArrayBuffer = coerceToArrayBuffer(authnrDataArrayBuffer, "authnrDataArrayBuffer");

	var ret = new Map();

	// console.log("authnrDataArrayBuffer", authnrDataArrayBuffer);
	// console.log("typeof authnrDataArrayBuffer", typeof authnrDataArrayBuffer);
	// printHex("authnrDataArrayBuffer", authnrDataArrayBuffer);

	var authnrDataBuf = new DataView(authnrDataArrayBuffer);
	var offset = 0;
	ret.set("rpIdHash", authnrDataBuf.buffer.slice(offset, offset + 32));
	offset += 32;
	var flags = authnrDataBuf.getUint8(offset);
	var flagsSet = new Set();
	ret.set("flags", flagsSet);
	if (flags & 0x01) flagsSet.add("UP");
	if (flags & 0x02) flagsSet.add("RFU1");
	if (flags & 0x04) flagsSet.add("UV");
	if (flags & 0x08) flagsSet.add("RFU3");
	if (flags & 0x10) flagsSet.add("RFU4");
	if (flags & 0x20) flagsSet.add("RFU5");
	if (flags & 0x40) flagsSet.add("AT");
	if (flags & 0x80) flagsSet.add("ED");
	offset++;
	ret.set("counter", authnrDataBuf.getUint32(offset, false));
	offset += 4;

	// see if there's more data to process
	var attestation = flagsSet.has("AT");
	var extensions = flagsSet.has("ED");

	if (attestation) {
		ret.set("aaguid", authnrDataBuf.buffer.slice(offset, offset + 16));
		offset += 16;
		var credIdLen = authnrDataBuf.getUint16(offset, false);
		ret.set("credIdLen", credIdLen);
		offset += 2;
		ret.set("credId", authnrDataBuf.buffer.slice(offset, offset + credIdLen));
		offset += credIdLen;
		var credentialPublicKeyCose = authnrDataBuf.buffer.slice(offset, authnrDataBuf.buffer.byteLength);
		ret.set("credentialPublicKeyCose", credentialPublicKeyCose);
		var jwk = coseToJwk(credentialPublicKeyCose);
		ret.set("credentialPublicKeyJwk", jwk);
		ret.set("credentialPublicKeyPem", jwkToPem(jwk));
	}

	// TODO: parse extensions
	if (extensions) {
		// extensionStart = offset
		throw new Error("authenticator extensions not supported");
	}

	return ret;
}

function parseAuthnrAssertionResponse(msg) {
	if (typeof msg !== "object") {
		throw new TypeError("expected msg to be Object");
	}

	if (typeof msg.response !== "object") {
		throw new TypeError("expected response to be Object");
	}

	let userHandle;
	if (msg.response.userHandle !== undefined) {
		userHandle = coerceToArrayBuffer(msg.response.userHandle, "response.userHandle");
		if (userHandle.byteLength === 0) {
			userHandle = undefined;
		}
	}

	let sigAb = coerceToArrayBuffer(msg.response.signature, "response.signature");
	let ret = new Map([
		["sig", sigAb],
		["userHandle", userHandle],
		["rawAuthnrData", coerceToArrayBuffer(msg.response.authenticatorData, "response.authenticatorData")],
		...parseAuthenticatorData(msg.response.authenticatorData),
	]);

	return ret;
}

module.exports = {
	parseExpectations,
	parseClientResponse,
	parseAttestationObject,
	parseAuthenticatorData,
	parseAuthnrAssertionResponse,
	parseAuthnrAttestationResponse,
};
