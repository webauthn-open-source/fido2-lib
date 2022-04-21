import {
	abToPem,
	abEqual,
	coerceToArrayBuffer,
	coerceToBase64,
	appendBuffer,
	tools
} from "../utils.js";

import {
	Certificate,
	CertManager
} from "../certUtils.js";

import { u2fRootCerts as rootCertList } from "./u2fRootCerts.js";

const algMap = new Map([
	[-7, {
		algName: "ECDSA_w_SHA256",
		hashAlg: "SHA256",
	}],
	// [-8, {
	//     name: "EdDSA",
	//     hash: undefined
	// }],
	[-35, {
		algName: "ECDSA_w_SHA384",
		hashAlg: "SHA384",
	}],
	[-36, {
		algName: "ECDSA_w_SHA512",
		hashAlg: "SHA512",
	}],
]);

function packedParseFn(attStmt) {

	let ret = new Map();

	// alg
	let algEntry = algMap.get(attStmt.alg);
	if (algEntry === undefined) {
		throw new Error("packed attestation: unknown algorithm: " + attStmt.alg);
	}
	ret.set("alg", algEntry);

	// x5c
	let x5c = attStmt.x5c;
	let newX5c = [];
	if (Array.isArray(x5c)) {
		for (let cert of x5c) {
			cert = coerceToArrayBuffer(cert, "packed x5c cert");
			newX5c.push(cert);
		}
		ret.set("attCert", newX5c.shift());
		ret.set("x5c", newX5c);
	} else {
		ret.set("x5c", x5c);
	}

	// ecdaaKeyId
	let ecdaaKeyId = attStmt.ecdaaKeyId;
	if (ecdaaKeyId !== undefined) {
		ecdaaKeyId = coerceToArrayBuffer(ecdaaKeyId, "ecdaaKeyId");
		ret.set("ecdaaKeyId", ecdaaKeyId);
	}

	// sig
	let sig = attStmt.sig;
	sig = coerceToArrayBuffer(sig, "packed signature");
	ret.set("sig", sig);

	return ret;
}

async function packedValidateFn() {
	let x5c = this.authnrData.get("x5c");
	let ecdaaKeyId = this.authnrData.get("ecdaaKeyId");

	if (x5c !== undefined && ecdaaKeyId !== undefined) {
		throw new Error("packed attestation: should be 'basic' or 'ecdaa', got both");
	}

	if (x5c) return packedValidateBasic.call(this);
	if (ecdaaKeyId) return packedValidateEcdaa.call(this);
	return packedValidateSurrogate.call(this);
}

async function packedValidateBasic() {
	// see what algorithm we're working with
	let {
		algName,
		hashAlg,
	} = this.authnrData.get("alg");

	if (algName === undefined) {
		throw new Error("packed attestation: unknown algorithm " + algName);
	}

	// from: https://w3c.github.io/webauthn/#packed-attestation
	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in x5c with the algorithm specified in alg.
	let res = validateSignature(
		this.clientData.get("rawClientDataJson"),
		this.authnrData.get("rawAuthnrData"),
		this.authnrData.get("sig"),
		hashAlg,
		this.authnrData.get("attCert")
	);
	if (!res) {
		throw new Error("packed attestation signature verification failed");
	}
	this.audit.journal.add("sig");
	this.audit.journal.add("alg");

	// Verify that x5c meets the requirements in §8.2.1 Packed attestation statement certificate requirements.
	await validateCerts(
		this.authnrData.get("attCert"),
		this.authnrData.get("aaguid"),
		this.authnrData.get("x5c"),
		this.audit
	);

	// If successful, return attestation type Basic and attestation trust path x5c.
	this.audit.info.set("attestation-type", "basic");

	this.audit.journal.add("fmt");

	return true;
}

function validateSignature(rawClientData, authenticatorData, sig, hashAlg, parsedAttCert) {
	// create clientDataHash
	const hash = tools().hashDigest(rawClientData);
	let clientDataHash = new Uint8Array(hash).buffer;

	// convert cert to PEM
	let attCertPem = abToPem("CERTIFICATE", parsedAttCert);

	// verify signature
	const verify = tools().verifySignature(hashAlg, attCertPem, sig, appendBuffer(authenticatorData, clientDataHash));
	return verify;
}

async function validateCerts(parsedAttCert, aaguid, x5c, audit) {
	// make sure our root certs are loaded
	if (CertManager.getCerts().size === 0) {
		rootCertList.forEach((cert) => CertManager.addCert(cert));
	}

	// decode attestation cert
	let attCert = new Certificate(coerceToBase64(parsedAttCert, "parsedAttCert"));
	try {
		await attCert.verify();
	} catch (e) {
		let err = e;
		if (err.message === "Please provide issuer certificate as a parameter") {
			// err = new Error("Root attestation certificate for this token could not be found. Please contact your security key vendor.");
			audit.warning.set("attesation-not-validated", "could not validate attestation because the root attestation certification could not be found");
		} else {
			throw err;
		}
	}
	// TODO: validate chain?
	audit.journal.add("x5c");

	// cert MUST be x.509v3
	if (attCert.getVersion() !== 3) {
		throw new Error("expected packed attestation certificate to be x.509v3");
	}

	// save certificate warnings, info, and extensions in our audit information
	let exts = attCert.getExtensions();
	exts.forEach((v, k) => audit.info.set(k, v));
	attCert.info.forEach((v, k) => audit.info.set(k, v));
	attCert.warning.forEach((v, k) => audit.warning.set(k, v));
	audit.journal.add("attCert");
	// console.log("_cert", attCert._cert);
	// console.log("_cert.subject", attCert._cert.subject);

	// from: https://w3c.github.io/webauthn/#packed-attestation
	// Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
	if (attCert.getVersion() !== 3) {
		throw new Error("expected packed attestation certificate to be x.509v3");
	}

	// Subject field MUST be set to:
	// Subject-C ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
	// Subject-O Legal name of the Authenticator vendor (UTF8String)
	// Subject-OU Literal string “Authenticator Attestation” (UTF8String)
	// Subject-CN A UTF8String of the vendor’s choosing
	let subject = attCert.getSubject();
	if (typeof subject.get("country-name") !== "string") {
		throw new Error("packed attestation: attestation certificate missing 'country name'");
	}

	if (typeof subject.get("organization-name") !== "string") {
		throw new Error("packed attestation: attestation certificate missing 'organization name'");
	}

	if (subject.get("organizational-unit-name") !== "Authenticator Attestation") {
		throw new Error("packed attestation: attestation certificate 'organizational unit name' must be 'Authenticator Attestation'");
	}

	if (typeof subject.get("common-name") !== "string") {
		throw new Error("packed attestation: attestation certificate missing 'common name'");
	}

	// If the related attestation root certificate is used for multiple authenticator models, the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
	// XXX: no way to tell if AAGUID is required on the server side...

	// The Basic Constraints extension MUST have the CA component set to false.
	let basicConstraints = exts.get("basic-constraints");
	if (basicConstraints.cA !== false) {
		throw new Error("packed attestation: basic constraints 'cA' must be 'false'");
	}

	// An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through authenticator metadata services
	// TODO: no example of this is available to test against

	// If x5c contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
	let certAaguid = exts.get("fido-aaguid");
	if (certAaguid !== undefined && !abEqual(aaguid, certAaguid)) {
		throw new Error("packed attestation: authnrData AAGUID did not match AAGUID in attestation certificate");
	}
}

async function validateSelfSignature(rawClientData, authenticatorData, sig, hashAlg, publicKeyPem) {
	// create clientDataHash
	const clientDataHash = await tools().hashDigest(rawClientData);

	// verify signature
	const verify = tools().verifySignature(publicKeyPem,sig,appendBuffer(authenticatorData,clientDataHash));
	return verify;
}

function packedValidateSurrogate() {
	// see what algorithm we're working with
	let {
		algName,
		hashAlg,
	} = this.authnrData.get("alg");

	if (algName === undefined) {
		throw new Error("packed attestation: unknown algorithm " + algName);
	}

	// from: https://w3c.github.io/webauthn/#packed-attestation
	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.

	let res = validateSelfSignature(
		this.clientData.get("rawClientDataJson"),
		this.authnrData.get("rawAuthnrData"),
		this.authnrData.get("sig"),
		hashAlg,
		this.authnrData.get("credentialPublicKeyPem")
	);
	if (!res) {
		throw new Error("packed attestation signature verification failed");
	}
	this.audit.journal.add("sig");
	this.audit.journal.add("alg");
	this.audit.journal.add("x5c");

	// If successful, return attestation type Self and an empty trust path
	this.audit.info.set("attestation-type", "self");

	this.audit.journal.add("fmt");

	return true;
}

function packedValidateEcdaa() {
	throw new Error("packed attestation: ECDAA not implemented, please open a GitHub issue.");
}

const packedAttestation = {
	name: "packed",
	parseFn: packedParseFn,
	validateFn: packedValidateFn,
};

export { packedAttestation };