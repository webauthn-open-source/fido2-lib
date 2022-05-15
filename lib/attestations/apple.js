import { expect } from "chai";
import { Certificate } from "../certUtils.js";
import { Key } from "../keyUtils.js";
import { coerceToArrayBuffer, coerceToBase64, appendBuffer, tools, arrayBufferEquals } from "../utils.js";

// https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
// The syntax of an Apple attestation statement is defined as follows:
// appleStmtFormat = {
//    x5c: [ credCert: bytes, * (caCert: bytes) ]
// }
function appleParseFn(attStmt) {
	// Step 1: Verify that attStmt is valid CBOR conforming to the syntax
	// defined above and perform CBOR decoding on it to extract the contained fields.
	const ret = new Map();

	const x5c = attStmt.x5c;
	if (!Array.isArray(x5c)) {
		throw new TypeError(
			"expected apple attestation x5c field to be of type Array"
		);
	}

	const abX5c = [];
	for (let cert of x5c) {
		cert = coerceToArrayBuffer(cert, "apple x5c cert");
		abX5c.push(cert);
	}

	ret.set("credCert", abX5c.shift());

	return ret;
}

async function appleValidateFn() {
	const parsedCredCert = this.authnrData.get("credCert");

	// Step 2: Concatenate authenticatorData(rawAuthnrData) and clientDataHash(rawClientData) to form nonceToHash.
	const rawClientData = this.clientData.get("rawClientDataJson");
	const rawAuthnrData = this.authnrData.get("rawAuthnrData");

	const clientDataHash = await tools.hashDigest(rawClientData);

	const rawAuthnrDataBuf = new Uint8Array(rawAuthnrData);
	const clientDataHashBuf = new Uint8Array(clientDataHash);

	const nonceToHash = appendBuffer(rawAuthnrDataBuf, clientDataHashBuf);

	// Step 3: Perform SHA-256 hash of nonceToHash to produce nonce.
	const nonce = await tools.hashDigest(nonceToHash);

	// Step 4: Verify that nonce === value of extension with key OID 1.2.840.113635.100.8.2
	const credCert = new Certificate(
		coerceToBase64(parsedCredCert, "parsedCredCert")
	);
	const extensions = credCert.getExtensions();
	let attExtBytes;
	for (let ext of extensions) {
		if (Array.isArray(ext) && ext.length > 1) {
			if (ext[0] === "1.2.840.113635.100.8.2") {
				attExtBytes = ext[1];
			}
		}
	}
	if (!attExtBytes) {
		return false;
	}

	const asn1 = tools.fromBER(attExtBytes);
	if (asn1.offset === -1) {
		throw new Error("error parsing ASN.1 while validating 'apple' attestation");
	}
	const result = asn1.result;
	if (!asn1.result.valueBeforeDecodeView) {
		throw new Error("error parsing ASN.1 while validating 'apple' attestation, invalid schema (1)");
	}
	let expectedNonce;
	try {
		// Extract only nonce from valueHexView
		expectedNonce = new Uint8Array(asn1.result.valueBlock.value[0].valueBlock.value[0].valueBlock.valueHexView).buffer;
	} catch (e) {
		throw new Error("error parsing ASN.1 while validating 'apple' attestation, invalid schema (2)");
	}
	if (!arrayBufferEquals(expectedNonce,nonce)) {
		throw new Error("nonce did not match expectedNonce");
	}

	// Step 5: Verify that the credential public key equals the Subject Public Key of credCert.
	const credentialPublicKey = new Key();
	await credentialPublicKey.fromPem(this.authnrData.get("credentialPublicKeyPem"));
	const certificatePublicKey = new Key(await credCert.getPublicKey());
	const credentialPublicKeyReexportedPem = await credentialPublicKey.toPem(true);
	const certificatePublicKeyReexportedPem = await certificatePublicKey.toPem(true);

	if (credentialPublicKeyReexportedPem !== certificatePublicKeyReexportedPem) {
		throw new Error("certificatePublicKey did not match credentialPublicKey");
	}

	// ToDo: Verify certificate chain?

	// ToDo: Add required stuff to journal

	return true;
}

const appleAttestation = {
	name: "apple",
	parseFn: appleParseFn,
	validateFn: appleValidateFn,
};

export { appleAttestation };
