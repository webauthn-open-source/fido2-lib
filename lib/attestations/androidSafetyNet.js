import { ab2str, appendBuffer, coerceToBase64, tools } from "../utils.js";

import { Certificate } from "../certUtils.js";

function androidSafetyNetParseFn(attStmt) {
	const ret = new Map();

	// console.log("android-safetynet", attStmt);

	ret.set("ver", attStmt.ver);

	const response = ab2str(attStmt.response);
	ret.set("response", response);

	// console.log("returning", ret);
	return ret;
}

// Validation:
// https://www.w3.org/TR/webauthn/#android-safetynet-attestation (verification procedure)

async function androidSafetyNetValidateFn() {
	const response = this.authnrData.get("response");

	// parse JWS
	const protectedHeader = await tools.decodeProtectedHeader(response);
	if (!Array.isArray(protectedHeader.x5c) || protectedHeader.x5c.length < 1) {
		throw new Error("android-safetynet attestation: x5c missing from JWS header");
	}
	// only trust the certificate chain, a self-supplied "jwk" would verify a forged response
	const publicKey = await tools.getEmbeddedJwk({ x5c: protectedHeader.x5c, alg: protectedHeader.alg });
	const parsedJws = await tools.jwtVerify(
		response,
		await tools.importJWK(publicKey),
	);

	// Append now verified header to jws
	parsedJws.header = protectedHeader;

	this.authnrData.set("payload", parsedJws.payload);

	// Required: verify that ctsProfileMatch attribute in the parsedJws.payload is true
	if (!parsedJws.payload.ctsProfileMatch){
		throw new Error("android-safetynet attestation: ctsProfileMatch: the device is not compatible");
	}

	// Required: verify nonce 
	// response.nonce === base64( sha256( authenticatorData concatenated with clientDataHash ))
	const rawClientData = this.clientData.get("rawClientDataJson");
	const rawAuthnrData = this.authnrData.get("rawAuthnrData");

	// create clientData SHA-256 hash
	const clientDataHash = await tools.hashDigest(rawClientData);

	// concatenate buffers
	const rawAuthnrDataBuf = new Uint8Array(rawAuthnrData);
	const clientDataHashBuf = new Uint8Array(clientDataHash);

	const concatenated = appendBuffer(rawAuthnrDataBuf, clientDataHashBuf);

	// create hash of the concatenation
	const hash = await tools.hashDigest(concatenated);

	const nonce = tools.base64.fromArrayBuffer(hash);

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
	const parsedAttCert = parsedJws.header.x5c.shift();
	this.authnrData.set("attCert", parsedAttCert);
	this.authnrData.set("x5c", parsedJws.header.x5c);

	this.audit.journal.add("attCert");
	this.audit.journal.add("x5c");

	const attCert = new Certificate(coerceToBase64(parsedAttCert, "parsedAttCert"));
	this.audit.info.set("organization-name", attCert.getSubject().get("organization-name"));

	this.audit.warning.set("attesation-not-validated", "android-safetynet is deprecated, its certificate chain is not validated");
	this.audit.info.set("attestation-type", "none");

	this.audit.journal.add("fmt");

	return true;
}

const androidSafetyNetAttestation = {
	name: "android-safetynet",
	parseFn: androidSafetyNetParseFn,
	validateFn: androidSafetyNetValidateFn,
};

export { androidSafetyNetAttestation };
