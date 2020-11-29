/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

"use strict";

const {
	printHex,
	coerceToArrayBuffer,
	coerceToBase64,
	abToBuf,
	abToPem,
	ab2str,
	b64ToJsObject,
} = require("../utils");
const crypto = require("crypto");
const {
	CertManager,
	Certificate,
} = require("../certUtils");
const jose = require("node-jose");

function androidSafetyNetParseFn(attStmt) {
	var ret = new Map();

	// console.log("android-safetynet", attStmt);

	ret.set("ver", attStmt.ver);

	var response = ab2str(attStmt.response);
	ret.set("response", response);

	// console.log("returning", ret);
	return ret;
}

// Validation:
// https://www.w3.org/TR/webauthn/#android-safetynet-attestation (verification procedure)

async function androidSafetyNetValidateFn() {
	var response = this.authnrData.get("response");
	
	// parse JWS
	var parsedJws = await jose.JWS.createVerify().verify(response, { allowEmbeddedKey: true });
	parsedJws.payload = JSON.parse(ab2str(coerceToArrayBuffer(parsedJws.payload, "MDS TOC payload")));
	this.authnrData.set("payload", parsedJws.payload);

	// Required: verify that ctsProfileMatch attribute in the parsedJws.payload is true
	if (!parsedJws.payload.ctsProfileMatch){
		throw new Error("android-safetynet attestation: ctsProfileMatch: the device is not compatible");
	}

	// Required: verify nonce 
	// response.nonce === base64( sha256( authenticatorData concatenated with clientDataHash ))
	var rawClientData = this.clientData.get("rawClientDataJson");
	var rawAuthnrData = this.authnrData.get("rawAuthnrData");
	
	// create clientData SHA-256 hash
	var clientDataHash = crypto.createHash("sha256");
	clientDataHash.update(abToBuf(rawClientData));
	clientDataHash = clientDataHash.digest();
	clientDataHash = new Uint8Array(clientDataHash).buffer;
	
	// concatenate buffers
	var rawAuthnrDataBuf = Buffer.from(rawAuthnrData);
	var clientDataHashBuf = Buffer.from(clientDataHash);

	var concatenated = Buffer.concat(
		[
			rawAuthnrDataBuf, 
			clientDataHashBuf, 
		],
		clientDataHashBuf.length + rawAuthnrDataBuf.length
	);
	
	// create hash of the concatenation
	var hash = crypto.createHash("sha256");
	hash.update(abToBuf(concatenated));
	hash = hash.digest();
	hash = new Uint8Array(hash).buffer;

	var nonce = Buffer.from(hash).toString("base64");
	
	// check result
	if(nonce!==parsedJws.payload.nonce){
		throw new Error("android-safetynet attestation: nonce check hash failed");
	}

	// check for any safetynet errors
	if(parsedJws.payload.error){
		throw new Error("android-safetynet: " + parsedJws.payload.error + "advice: " + parsedJws.payload.advice);
	}

	this.audit.journal.add("payload");
	this.audit.journal.add("ver");
	this.audit.journal.add("response");

	// get certs
	this.authnrData.set("attCert", parsedJws.header.x5c.shift());
	this.authnrData.set("x5c", parsedJws.header.x5c);

	this.audit.journal.add("attCert");
	this.audit.journal.add("x5c");

	// TODO: verify attCert is issued to the hostname "attest.android.com"
	var attCert = new Certificate(coerceToBase64(parsedJws.header.x5c.shift(), "parsedAttCert"));
	this.audit.info.set("organization-name", attCert.getSubject().get("organization-name"));
	// attCert.getExtensions()

	// TODO: verify cert chain
	// var rootCerts;
	// if (Array.isArray(rootCert)) rootCerts = rootCert;
	// else rootCerts = [rootCert];
	// var ret = await CertManager.verifyCertChain(parsedJws.header.x5c, rootCerts, crls);
	
	// If successful, return attestation type Basic and attestation trust path attCert.
	this.audit.info.set("attestation-type", "basic");

	this.audit.journal.add("fmt");
	
	return true;
}

module.exports = {
	name: "android-safetynet",
	parseFn: androidSafetyNetParseFn,
	validateFn: androidSafetyNetValidateFn,
};
