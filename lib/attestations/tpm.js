/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

"use strict";

const {
	printHex,
	coerceToArrayBuffer,
	coerceToBase64,
	abEqual,
	abToBuf,
	abToPem,
	abToInt,
} = require("../utils");

const {
	Certificate,
	CertManager,
} = require("../certUtils");

const crypto = require("crypto");

const coseToJwk = require("cose-to-jwk");

function tpmParseFn(attStmt) {
	var ret = new Map();

	if (attStmt.ecdaaKeyId !== undefined) {
		throw new Error("TPM ECDAA attesation is not currently supported.");
	}

	// x5c
	var x5c = attStmt.x5c;

	if (!Array.isArray(x5c)) {
		throw new TypeError("expected TPM attestation x5c field to be of type Array");
	}

	if (x5c.length < 1) {
		throw new TypeError("no certificates in TPM x5c field");
	}

	var newX5c = [];
	for (let cert of x5c) {
		cert = coerceToArrayBuffer(cert, "TPM x5c cert");
		newX5c.push(cert);
	}
	// first certificate MUST be the attestation cert
	ret.set("attCert", newX5c.shift());
	// the rest of the certificates (if any) are the certificate chain
	ret.set("x5c", newX5c);

	// ecdaa
	if (attStmt.ecdaaKeyId) ret.set("ecdaaKeyId", attStmt.ecdaaKeyId);

	// sig
	ret.set("sig", coerceToArrayBuffer(attStmt.sig, "tpm signature"));

	// sig
	ret.set("ver", attStmt.ver);

	// alg
	var alg = {
		algName: coseToJwk.algToStr(attStmt.alg),
		hashAlg: coseToJwk.algToHashStr(attStmt.alg),
	};
	ret.set("alg", alg);

	// certInfo
	var certInfo = parseCertInfo(coerceToArrayBuffer(attStmt.certInfo, "certInfo"));
	ret.set("certInfo", certInfo);

	// pubArea
	var pubArea = parsePubArea(coerceToArrayBuffer(attStmt.pubArea, "pubArea"));
	ret.set("pubArea", pubArea);

	return ret;
}

function parseCertInfo(certInfo) {
	if (!(certInfo instanceof ArrayBuffer)) {
		throw new Error("tpm attestation: expected certInfo to be ArrayBuffer");
	}

	var dv = new DataView(certInfo);
	var offset = 0;
	var ret;
	var ci = new Map();
	ci.set("rawCertInfo", certInfo);

	// TPM_GENERATED_VALUE magic number
	var magic = dv.getUint32(offset);
	// if this isn't the magic number, the rest of the parsing is going to fail
	if (magic !== 0xff544347) { // 0xFF + 'TCG'
		throw new Error("tpm attestation: certInfo had bad magic number: " + magic.toString(16));
	}
	ci.set("magic", magic);
	offset += 4;


	// TPMI_ST_ATTEST type
	var type = decodeStructureTag(dv.getUint16(offset));
	// if this isn't the right type, the rest of the parsing is going to fail
	if (type !== "TPM_ST_ATTEST_CERTIFY") {
		throw new Error("tpm attestation: got wrong type. expected 'TPM_ST_ATTEST_CERTIFY' got: " + type);
	}
	ci.set("type", type);
	offset += 2;

	// TPM2B_NAME qualifiedSigner
	ret = getTpm2bName(dv, offset);
	ci.set("qualifiedSignerHashType", ret.hashType);
	ci.set("qualifiedSigner", ret.nameHash);
	offset = ret.offset;

	// TPM2B_DATA extraData
	ret = getSizedElement(dv, offset);
	ci.set("extraData", ret.buf);
	offset = ret.offset;

	// TPMS_CLOCK_INFO clockInfo
	// UINT64 clock
	ci.set("clock", dv.buffer.slice(offset, offset + 8));
	offset += 8;
	// UINT32 resetCount
	ci.set("resetCount", dv.getUint32(offset));
	offset += 4;
	// UINT32 restartCount
	ci.set("restartCount", dv.getUint32(offset));
	offset += 4;
	// boolean safe
	ci.set("safe", !!dv.getUint8(offset));
	offset++;

	// UINT64 firmwareVersion
	ci.set("firmwareVersion", dv.buffer.slice(offset, offset + 8));
	offset += 8;

	// TPMU_ATTEST attested
	// TPM2B_NAME name
	ret = getTpm2bName(dv, offset);
	ci.set("nameHashType", ret.hashType);
	ci.set("name", ret.nameHash);
	offset = ret.offset;

	// TPM2B_NAME qualifiedName
	ret = getTpm2bName(dv, offset);
	ci.set("qualifiedNameHashType", ret.hashType);
	ci.set("qualifiedName", ret.nameHash);
	offset = ret.offset;

	if (offset !== certInfo.byteLength) {
		throw new Error("tpm attestation: left over bytes when parsing cert info");
	}

	return ci;
}

function parsePubArea(pubArea) {
	if (!(pubArea instanceof ArrayBuffer)) {
		throw new Error("tpm attestation: expected pubArea to be ArrayBuffer");
	}

	var dv = new DataView(pubArea);
	var offset = 0;
	var ret;
	var pa = new Map();
	pa.set("rawPubArea", pubArea);

	// TPMI_ALG_PUBLIC type
	var type = algIdToStr(dv.getUint16(offset));
	pa.set("type", type);
	offset += 2;

	// TPMI_ALG_HASH nameAlg
	pa.set("nameAlg", algIdToStr(dv.getUint16(offset)));
	offset += 2;

	// TPMA_OBJECT objectAttributes
	pa.set("objectAttributes", decodeObjectAttributes(dv.getUint32(offset)));
	offset += 4;

	// TPM2B_DIGEST authPolicy
	ret = getSizedElement(dv, offset);
	pa.set("authPolicy", ret.buf);
	offset = ret.offset;

	// TPMU_PUBLIC_PARMS parameters
	if (type !== "TPM_ALG_RSA") {
		throw new Error("tpm attestation: only TPM_ALG_RSA supported");
	}
	// TODO: support other types
	pa.set("symmetric", algIdToStr(dv.getUint16(offset)));
	offset += 2;
	pa.set("scheme", algIdToStr(dv.getUint16(offset)));
	offset += 2;
	pa.set("keyBits", dv.getUint16(offset));
	offset += 2;
	var exponent = dv.getUint32(offset);
	if (exponent === 0) exponent = 65537;
	pa.set("exponent", exponent);
	offset += 4;

	// TPMU_PUBLIC_ID unique
	ret = getSizedElement(dv, offset);
	pa.set("unique", ret.buf);
	offset = ret.offset;

	if (offset !== pubArea.byteLength) {
		throw new Error("tpm attestation: left over bytes when parsing public area");
	}

	return pa;
}

// eslint-disable complexity
function decodeStructureTag(t) {
	/* eslint complexity: ["off"] */
	switch (t) {
		case 0x00C4: return "TPM_ST_RSP_COMMAND";
		case 0x8000: return "TPM_ST_NULL";
		case 0x8001: return "TPM_ST_NO_SESSIONS";
		case 0x8002: return "TPM_ST_SESSIONS";
		case 0x8003: return "TPM_RESERVED_0x8003";
		case 0x8004: return "TPM_RESERVED_0x8004";
		case 0x8014: return "TPM_ST_ATTEST_NV";
		case 0x8015: return "TPM_ST_ATTEST_COMMAND_AUDIT";
		case 0x8016: return "TPM_ST_ATTEST_SESSION_AUDIT";
		case 0x8017: return "TPM_ST_ATTEST_CERTIFY";
		case 0x8018: return "TPM_ST_ATTEST_QUOTE";
		case 0x8019: return "TPM_ST_ATTEST_TIME";
		case 0x801A: return "TPM_ST_ATTEST_CREATION";
		case 0x801B: return "TPM_RESERVED_0x801B";
		case 0x8021: return "TPM_ST_CREATION";
		case 0x8022: return "TPM_ST_VERIFIED";
		case 0x8023: return "TPM_ST_AUTH_SECRET";
		case 0x8024: return "TPM_ST_HASHCHECK";
		case 0x8025: return "TPM_ST_AUTH_SIGNED";
		case 0x8029: return "TPM_ST_FU_MANIFEST";
		default:
			throw new Error("tpm attestation: unknown structure tag: " + t.toString(16));
	}
}

function decodeObjectAttributes(oa) {
	var attrList = [
		"RESERVED_0",
		"FIXED_TPM",
		"ST_CLEAR",
		"RESERVED_3",
		"FIXED_PARENT",
		"SENSITIVE_DATA_ORIGIN",
		"USER_WITH_AUTH",
		"ADMIN_WITH_POLICY",
		"RESERVED_8",
		"RESERVED_9",
		"NO_DA",
		"ENCRYPTED_DUPLICATION",
		"RESERVED_12",
		"RESERVED_13",
		"RESERVED_14",
		"RESERVED_15",
		"RESTRICTED",
		"DECRYPT",
		"SIGN_ENCRYPT",
		"RESERVED_19",
		"RESERVED_20",
		"RESERVED_21",
		"RESERVED_22",
		"RESERVED_23",
		"RESERVED_24",
		"RESERVED_25",
		"RESERVED_26",
		"RESERVED_27",
		"RESERVED_28",
		"RESERVED_29",
		"RESERVED_30",
		"RESERVED_31",
	];

	var ret = new Set();

	for (let i = 0; i < 32; i++) {
		let bit = 1 << i;
		if (oa & bit) {
			ret.add(attrList[i]);
		}
	}

	return ret;
}

function getSizedElement(dv, offset) {
	var size = dv.getUint16(offset);
	offset += 2;
	var buf = dv.buffer.slice(offset, offset + size);
	dv = new DataView(buf);
	offset += size;

	return {
		size,
		dv,
		buf,
		offset,
	};
}

function getTpm2bName(dvIn, oIn) {
	var {
		offset,
		dv,
	} = getSizedElement(dvIn, oIn);

	var hashType = algIdToStr(dv.getUint16(0));
	var nameHash = dv.buffer.slice(2);

	return {
		hashType,
		nameHash,
		offset,
	};
}

function algIdToStr(hashType) {
	var hashList = [
		"TPM_ALG_ERROR", // 0
		"TPM_ALG_RSA", // 1
		null,
		null,
		"TPM_ALG_SHA1", // 4
		"TPM_ALG_HMAC", // 5
		"TPM_ALG_AES", // 6
		"TPM_ALG_MGF1", // 7
		null,
		"TPM_ALG_KEYEDHASH", // 8
		"TPM_ALG_XOR", // A
		"TPM_ALG_SHA256", // B
		"TPM_ALG_SHA384", // C
		"TPM_ALG_SHA512", // D
		null,
		null,
		"TPM_ALG_NULL", // 10
		null,
		"TPM_ALG_SM3_256", // 12
		"TPM_ALG_SM4", // 13
		"TPM_ALG_RSASSA", // 14
		"TPM_ALG_RSAES", // 15
		"TPM_ALG_RSAPSS", // 16
		"TPM_ALG_OAEP", // 17
		"TPM_ALG_ECDSA", // 18
	];

	return hashList[hashType];
}

async function tpmValidateFn() {
	var parsedAttCert = this.authnrData.get("attCert");
	var certInfo = this.authnrData.get("certInfo");
	var pubArea = this.authnrData.get("pubArea");

	var ver = this.authnrData.get("ver");
	if (ver != "2.0") {
		throw new Error("tpm attestation: expected TPM version 2.0");
	}
	this.audit.journal.add("ver");

	// https://www.w3.org/TR/webauthn/#tpm-attestation
	// Verify that the public key specified by the parameters and unique fields of pubArea is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
	var pubAreaPkN = pubArea.get("unique");
	var pubAreaPkExp = pubArea.get("exponent");
	var credentialPublicKeyJwk = this.authnrData.get("credentialPublicKeyJwk");
	var credentialPublicKeyJwkN = coerceToArrayBuffer(credentialPublicKeyJwk.n, "credentialPublicKeyJwk.n");
	var credentialPublicKeyJwkExpBuf = coerceToArrayBuffer(credentialPublicKeyJwk.e, "credentialPublicKeyJwk.e");
	var credentialPublicKeyJwkExp = abToInt(credentialPublicKeyJwkExpBuf);

	if (credentialPublicKeyJwk.kty !== "RSA" ||
        pubArea.get("type") !== "TPM_ALG_RSA") {
		throw new Error("tpm attestation: only RSA keys are currently supported");
	}

	if (pubAreaPkExp !== credentialPublicKeyJwkExp) {
		throw new Error("tpm attestation: RSA exponents of WebAuthn credentialPublicKey and TPM publicArea did not match");
	}

	if (!abEqual(credentialPublicKeyJwkN, pubAreaPkN)) {
		throw new Error("tpm attestation: RSA 'n' of WebAuthn credentialPublicKey and TPM publicArea did not match");
	}

	// Validate that certInfo is valid:
	//     Verify that magic is set to TPM_GENERATED_VALUE.
	var magic = certInfo.get("magic");
	if (magic !== 0xff544347) { // 0xFF + 'TCG'
		throw new Error("tpm attestation: certInfo had bad magic number: " + magic.toString(16));
	}

	//     Verify that type is set to TPM_ST_ATTEST_CERTIFY.
	var type = certInfo.get("type");
	if (type !== "TPM_ST_ATTEST_CERTIFY") {
		throw new Error("tpm attestation: got wrong type. expected 'TPM_ST_ATTEST_CERTIFY' got: " + type);
	}

	//     Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
	var rawAuthnrData = this.authnrData.get("rawAuthnrData");
	var rawClientData = this.clientData.get("rawClientDataJson");
	const cdHash = crypto.createHash("sha256");
	cdHash.update(abToBuf(rawClientData));
	var clientDataHashBuf = cdHash.digest();

	var alg = this.authnrData.get("alg");
	if (alg.hashAlg === undefined) {
		throw new Error("tpm attestation: unknown algorithm: " + alg);
	}
	this.audit.journal.add("alg");

	const attHash = crypto.createHash(alg.hashAlg);
	attHash.update(abToBuf(rawAuthnrData));
	attHash.update(clientDataHashBuf);
	var extraDataHashBuf = attHash.digest();
	var generatedExtraDataHash = new Uint8Array(extraDataHashBuf).buffer;
	var extraData = certInfo.get("extraData");
	if (!abEqual(generatedExtraDataHash, extraData)) {
		throw new Error("extraData hash did not match authnrData + clientDataHash hashed");
	}

	//     Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3,
	//     [see parser]
	//     whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
	var pubAreaName = certInfo.get("name");
	var pubAreaNameHashAlg = tpmHashToNpmHash(certInfo.get("nameHashType"));
	const pubAreaNameHash = crypto.createHash(pubAreaNameHashAlg);
	pubAreaNameHash.update(abToBuf(pubArea.get("rawPubArea")));
	var pubAreaNameHashBuf = pubAreaNameHash.digest();
	var generatedPubAreaNameHash = new Uint8Array(pubAreaNameHashBuf).buffer;
	if (!abEqual(generatedPubAreaNameHash, pubAreaName)) {
		throw new Error("pubAreaName hash did not match hash of publicArea");
	}
	this.audit.journal.add("pubArea");

	//     Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored.
	//     These fields MAY be used as an input to risk engines.

	// If x5c is present, this indicates that the attestation type is not ECDAA. In this case:
	//     Verify the sig is a valid signature over certInfo using the attestation public key in x5c with the algorithm specified in alg.
	var sig = this.authnrData.get("sig");
	var rawCertInfo = certInfo.get("rawCertInfo");
	var attCertPem = abToPem("CERTIFICATE", parsedAttCert);
	const verifySig = crypto.createVerify(alg.hashAlg);
	verifySig.write(abToBuf(rawCertInfo));
	verifySig.end();
	var res = verifySig.verify(attCertPem, abToBuf(sig));
	if (!res) {
		throw new Error("TPM attestation signature verification failed");
	}
	this.audit.journal.add("sig");
	this.audit.journal.add("certInfo");

	//     Verify that x5c meets the requirements in §8.3.1 TPM attestation statement certificate requirements.
	// https://www.w3.org/TR/webauthn/#tpm-cert-requirements
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

	// Version MUST be set to 3.
	if (attCert.getVersion() !== 3) {
		throw new Error("expected TPM attestation certificate to be x.509v3");
	}

	// Subject field MUST be set to empty.
	var attCertSubject = attCert.getSubject();
	if (attCertSubject.size !== 0) {
		throw new Error("tpm attestation: attestation certificate MUST have empty subject");
	}

	// The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
	// [save certificate warnings, info, and extensions in our audit information]
	var attCertExt = attCert.getExtensions();
	attCertExt.forEach((v, k) => this.audit.info.set(k, v));
	attCert.info.forEach((v, k) => this.audit.info.set(k, v));
	attCert.warning.forEach((v, k) => this.audit.warning.set(k, v));

	var altName = attCertExt.get("subject-alt-name");
	if (altName === undefined ||
        !Array.isArray(altName) ||
        altName.length < 1) {
		throw new Error("tpm attestation: Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9");
	}

	// TCG EK Credential Profile For TPM Family 2.0; Level 0 Specification Version 2.0 Revision 14 4 November 2014
	// The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryNameform within the GeneralName structure.
	var directoryName;
	altName.forEach((name) => {
		if (name.directoryName !== undefined) {
			directoryName = name.directoryName;
		}
	});

	if (directoryName === undefined) {
		throw new Error("tpm attestation: subject alternative name did not contain directory name");
	}

	// The TPM manufacturer identifies the manufacturer of the TPM. This value MUST be the vendor ID defined in the TCG Vendor ID Registry
	if (!directoryName.has("tcg-at-tpm-manufacturer")) {
		throw new Error("tpm attestation: subject alternative name did not list manufacturer");
	}
	// TODO: lookup manufacturer in registry

	// The TPM part number is encoded as a string and is manufacturer-specific. A manufacturer MUST provide a way to the user to retrieve the part number physically or logically. This information could be e.g. provided as part of the vendor string in the command TPM2_GetCapability(property = TPM_PT_VENDOR_STRING_x; x=1…4).
	if (!directoryName.has("tcg-at-tpm-model")) {
		throw new Error("tpm attestation: subject alternative name did not list model number");
	}

	// The TPM firmware version is a manufacturer-specific implementation version of the TPM. This value SHOULD match the version reported by the command TPM2_GetCapability (property = TPM_PT_FIRMWARE_VERSION_1).
	if (!directoryName.has("tcg-at-tpm-version")) {
		throw new Error("tpm attestation: subject alternative name did not list firmware version");
	}

	// The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
	var extKeyUsage = attCertExt.get("ext-key-usage");
	if (!Array.isArray(extKeyUsage) || !extKeyUsage.includes("tcg-kp-aik-certificate")) {
		throw new Error("tpm attestation: the Extended Key Usage extension MUST contain 'tcg-kp-aik-certificate'");
	}

	// The Basic Constraints extension MUST have the CA component set to false.
	var basicConstraints = attCertExt.get("basic-constraints");
	if (typeof basicConstraints !== "object" || basicConstraints.cA !== false) {
		throw new Error("tpm attestation: the Basic Constraints extension MUST have the CA component set to false");
	}
	// An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280]
	// are both OPTIONAL as the status of many attestation certificates is available through metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].
	// [will use MDS]

	//     If x5c contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
	var certAaguid = attCertExt.get("fido-aaguid");
	var aaguid = this.authnrData.get("aaguid");
	if (certAaguid !== undefined && !abEqual(aaguid, certAaguid)) {
		throw new Error("tpm attestation: authnrData AAGUID did not match AAGUID in attestation certificate");
	}
	this.audit.journal.add("x5c");
	this.audit.journal.add("attCert");

	//     If successful, return attestation type AttCA and attestation trust path x5c.
	this.audit.info.set("attestation-type", "AttCA");

	this.audit.journal.add("fmt");

	return true;

	// If ecdaaKeyId is present, then the attestation type is ECDAA.
	//     Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo (see [FIDOEcdaaAlgorithm]).
	//     If successful, return attestation type ECDAA and the identifier of the ECDAA-Issuer public key ecdaaKeyId.
	// [not currently supported, error would have been thrown in parser]
}

function tpmHashToNpmHash(tpmHash) {
	switch (tpmHash) {
		case "TPM_ALG_SHA1": return "SHA1";
		case "TPM_ALG_SHA256": return "SHA256";
		case "TPM_ALG_SHA384": return "SHA384";
		case "TPM_ALG_SHA512": return "SHA512";
		default:
			throw new TypeError("Unsupported hash type: " + tpmHash);
	}
}

module.exports = {
	name: "tpm",
	parseFn: tpmParseFn,
	validateFn: tpmValidateFn,
};
