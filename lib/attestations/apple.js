import { Certificate } from "../certUtils.js";
import { PublicKey } from "../keyUtils.js";
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

	if (x5c.length < 1) {
		throw new TypeError(
			"expected apple attestation x5c field to contain at least 1 entry"
		);
	}

	const abX5c = [];
	for (let cert of x5c) {
		cert = coerceToArrayBuffer(cert, "apple x5c cert");
		abX5c.push(cert);
	}

	// The first certificate is credCert
	ret.set("credCert", abX5c.shift());

	// The rest of the certificates (if any) are the certificate trust chain
	ret.set("x5c", abX5c);

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
	this.audit.journal.add("credCert");
	const extensions = credCert.getExtensions();
	let expectedNonce;
	for (const ext of extensions) {
		if (Array.isArray(ext) && ext.length > 1) {
			if (ext[0] === "1.2.840.113635.100.8.2") {
				if (Array.isArray(ext[1]) && ext[1].length) {
					expectedNonce = ext[1][0];
				}
			}
		}
	}
	if (!expectedNonce) {
		throw new Error(
			"extension with key '1.2.840.113635.100.8.2' (apple) was not found"
		);
	}

	if (!arrayBufferEquals(expectedNonce, nonce)) {
		throw new Error("nonce did not match expectedNonce");
	}

	// Step 5: Verify that the credential public key equals the Subject Public Key of credCert.
	const credentialPublicKey = new PublicKey();
	await credentialPublicKey.fromPem(
		this.authnrData.get("credentialPublicKeyPem")
	);

	const certificatePublicKey = new PublicKey();
	certificatePublicKey.fromCryptoKey(await credCert.getPublicKey());
	const credentialPublicKeyReexportedPem = await credentialPublicKey.toPem(
		true
	);
	const certificatePublicKeyReexportedPem = await certificatePublicKey.toPem(
		true
	);
	this.audit.journal.add("credentialPublicKeyPem");

	if (credentialPublicKeyReexportedPem !== certificatePublicKeyReexportedPem) {
		throw new Error("certificatePublicKey did not match credentialPublicKey");
	}

	// Step 6: If successful, return implementation-specific values representing attestation type Anonymization CA and attestation trust path x5c.
	this.audit.journal.add("x5c");
	this.audit.info.set("attestation-type", "anonca");

	this.audit.journal.add("fmt");

	return true;
}

const appleAttestation = {
	name: "apple",
	parseFn: appleParseFn,
	validateFn: appleValidateFn,
};

export { appleAttestation };
