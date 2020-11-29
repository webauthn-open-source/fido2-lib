/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

"use strict";

const {
	printHex,
	coerceToArrayBuffer,
	coerceToBase64,
	abToBuf,
	abToPem,
} = require("../utils");

const {
	Certificate,
	CertManager,
} = require("../certUtils");

const crypto = require("crypto");
const rootCertList = require("./u2fRootCerts");

function fidoU2fParseFn(attStmt) {
	var ret = new Map();
	var x5c = attStmt.x5c;
	var sig = attStmt.sig;

	if (!Array.isArray(x5c)) {
		throw new TypeError("expected U2F attestation x5c field to be of type Array");
	}

	if (x5c.length < 1) {
		throw new TypeError("no certificates in U2F x5c field");
	}

	var newX5c = [];
	for (let cert of x5c) {
		cert = coerceToArrayBuffer(cert, "U2F x5c cert");
		newX5c.push(cert);
	}
	// first certificate MUST be the attestation cert
	ret.set("attCert", newX5c.shift());
	// the rest of the certificates (if any) are the certificate chain
	ret.set("x5c", newX5c);

	sig = coerceToArrayBuffer(sig, "U2F signature");
	ret.set("sig", sig);

	return ret;
}

async function fidoU2fValidateFn() {
	var x5c = this.authnrData.get("x5c");
	var parsedAttCert = this.authnrData.get("attCert");

	// validate cert chain
	if (x5c.length > 0) {
		throw new Error("cert chain not validated");
	}
	this.audit.journal.add("x5c");

	// make sure our root certs are loaded
	if (CertManager.getCerts().size === 0) {
		rootCertList.forEach((cert) => CertManager.addCert(cert));
	}

	// decode attestation cert
	var attCert = new Certificate(coerceToBase64(parsedAttCert, "parsedAttCert"));
	try {
		await attCert.verify();
	} catch (e) {
		let err = e;
		if (err.message === "Please provide issuer certificate as a parameter") {
			// err = new Error("Root attestation certificate for this token could not be found. Please contact your security key vendor.");
			this.audit.warning.set("attesation-not-validated", "could not validate attestation because the root attestation certification could not be found");
		} else {
			throw err;
		}
	}

	// https: //fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-authenticator-transports-extension-v1.2-ps-20170411.html
	// cert MUST be x.509v3
	if (attCert.getVersion() !== 3) {
		throw new Error("expected U2F attestation certificate to be x.509v3");
	}

	// save certificate warnings, info, and extensions in our audit information
	attCert.getExtensions().forEach((v, k) => this.audit.info.set(k, v));
	attCert.info.forEach((v, k) => this.audit.info.set(k, v));
	attCert.warning.forEach((v, k) => this.audit.warning.set(k, v));
	this.audit.journal.add("attCert");

	// https://w3c.github.io/webauthn/#fido-u2f-attestation
	// certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error
	var jwk = this.authnrData.get("credentialPublicKeyJwk");
	if (jwk.kty !== "EC" ||
        jwk.crv !== "P-256") {
		throw new Error("bad U2F key type");
	}

	// rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData.attestedCredentialData
	var rpIdHash = this.authnrData.get("rpIdHash");
	var credId = this.authnrData.get("credId");

	// create clientDataHash
	var rawClientData = this.clientData.get("rawClientDataJson");
	const hash = crypto.createHash("sha256");
	hash.update(abToBuf(rawClientData));
	var clientDataHashBuf = hash.digest();
	var clientDataHash = new Uint8Array(clientDataHashBuf).buffer;

	// Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to CTAP1/U2F public Key format [FIDO-CTAP]
	//      Let publicKeyU2F represent the result of the conversion operation and set its first byte to 0x04. Note: This signifies uncompressed ECC key format.
	//      Extract the value corresponding to the "-2" key (representing x coordinate) from credentialPublicKey, confirm its size to be of 32 bytes and concatenate it with publicKeyU2F. If size differs or "-2" key is not found, terminate this algorithm and return an appropriate error.
	var x = coerceToArrayBuffer(jwk.x, "U2F public key x component");
	if (x.byteLength !== 32) {
		throw new Error("U2F public key x component was wrong size");
	}

	//      Extract the value corresponding to the "-3" key (representing y coordinate) from credentialPublicKey, confirm its size to be of 32 bytes and concatenate it with publicKeyU2F. If size differs or "-3" key is not found, terminate this algorithm and return an appropriate error.
	var y = coerceToArrayBuffer(jwk.y, "U2F public key y component");
	if (y.byteLength !== 32) {
		throw new Error("U2F public key y component was wrong size");
	}

	// Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
	var verificationData = new Uint8Array([
		0x00,
		...new Uint8Array(rpIdHash),
		...new Uint8Array(clientDataHash),
		...new Uint8Array(credId),
		0x04,
		...new Uint8Array(x),
		...new Uint8Array(y),
	]);

	// Verify the sig using verificationData and certificate public key per [SEC1].
	var sig = this.authnrData.get("sig");
	var attCertPem = abToPem("CERTIFICATE", parsedAttCert);

	const verify = crypto.createVerify("SHA256");
	verify.write(abToBuf(verificationData));
	verify.end();
	var res = verify.verify(attCertPem, abToBuf(sig));
	if (!res) {
		throw new Error("U2F attestation signature verification failed");
	}
	this.audit.journal.add("sig");

	// If successful, return attestation type Basic with the attestation trust path set to x5c.
	this.audit.info.set("attestation-type", "basic");

	this.audit.journal.add("fmt");
	return true;
}

module.exports = {
	name: "fido-u2f",
	parseFn: fidoU2fParseFn,
	validateFn: fidoU2fValidateFn,
};
