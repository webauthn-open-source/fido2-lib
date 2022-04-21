import {
	coerceToArrayBuffer,
	coerceToBase64,
	tools,
	abToStr,
	base64,
	appendBuffer
} from "../utils.js";

import {
	Certificate
} from "../certUtils.js";

function androidSafetyNetParseFn(attStmt) {
	let ret = new Map();

	// console.log("android-safetynet", attStmt);

	ret.set("ver", attStmt.ver);

	let response = abToStr(attStmt.response);
	ret.set("response", response);

	// console.log("returning", ret);
	return ret;
}

// Validation:
// https://www.w3.org/TR/webauthn/#android-safetynet-attestation (verification procedure)

async function androidSafetyNetValidateFn() {
	let response = this.authnrData.get("response");
	
	// parse JWS
	let parsedJws = await tools().jwsCreateVerify().verify(response, { allowEmbeddedKey: true });
	parsedJws.payload = JSON.parse(abToStr(coerceToArrayBuffer(parsedJws.payload, "MDS TOC payload")));
	this.authnrData.set("payload", parsedJws.payload);

	// Required: verify that ctsProfileMatch attribute in the parsedJws.payload is true
	if (!parsedJws.payload.ctsProfileMatch){
		throw new Error("android-safetynet attestation: ctsProfileMatch: the device is not compatible");
	}

	// Required: verify nonce 
	// response.nonce === base64( sha256( authenticatorData concatenated with clientDataHash ))
	let rawClientData = this.clientData.get("rawClientDataJson");
	let rawAuthnrData = this.authnrData.get("rawAuthnrData");
	
	// create clientData SHA-256 hash
	let clientDataHash = await tools().hashDigest(rawClientData);
	
	// concatenate buffers
	let rawAuthnrDataBuf = new Uint8Array(rawAuthnrData);
	let clientDataHashBuf = new Uint8Array(clientDataHash);

	let concatenated = appendBuffer(rawAuthnrDataBuf,clientDataHashBuf);
	
	// create hash of the concatenation
	let hash = await tools().hashDigest(concatenated);

	let nonce = base64.fromArrayBuffer(hash);
	
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
	let attCert = new Certificate(coerceToBase64(parsedJws.header.x5c.shift(), "parsedAttCert"));
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

const androidSafetyNetAttestation = {
	name: "android-safetynet",
	parseFn: androidSafetyNetParseFn,
	validateFn: androidSafetyNetValidateFn,
};

export { androidSafetyNetAttestation };