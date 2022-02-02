"use strict";

const {
	coerceToBase64Url,
	coerceToArrayBuffer,
	abToBuf,
	abToPem,
	printHex,
	abEqual,
	ab2str,
	b64ToJsObject,
	jsObjectToB64,
} = require("./utils");

const {
	CertManager,
} = require("./certUtils");

const crypto = require("crypto");

const jose = require("node-jose");

const fidoMdsRootCert =
	"-----BEGIN CERTIFICATE-----\n" +
	"MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\n" +
	"A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\n" +
	"Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\n" +
	"MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\n" +
	"A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n" +
	"hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\n" +
	"RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\n" +
	"gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\n" +
	"KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\n" +
	"QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\n" +
	"XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\n" +
	"DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\n" +
	"LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\n" +
	"RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\n" +
	"jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\n" +
	"6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\n" +
	"mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\n" +
	"Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\n" +
	"WD9f\n" +
	"-----END CERTIFICATE-----\n";

/**
 * Holds a single MDS entry that provides the metadata for an authenticator. Contains
 * both the TOC data (such as `statusReports` and `url`) as well as all the metadata
 * statment data. All the metadata has been converted from the integers found in the
 * [FIDORegistry](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html)
 * and [FIDO UAF Registry](https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-reg-v1.2-rd-20171128.html)
 * have been converted to more friendly values. The following values are converted:
 * * attachmentHint - converted to Array of Strings
 * * attestationTypes - converted to Array of Strings
 * * authenticationAlgorithm - converted to String
 * * keyProtection - converted to Array of Strings
 * * matcherProtection - converted to Array of Strings
 * * publicKeyAlgAndEncoding - converted to String
 * * tcDisplay - converted to Array of Strings
 * * userVerificationDetails - converted to Array of Array of {@link UserVerificationDesc}
 *
 * See the [FIDO Metadata Specification]{@link https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html}
 * for a description of each of the properties of this class.
 */
class MdsEntry {
	/**
     * Creates a new MDS entry. It is assumed that the entry has already been validated.
     * The typical way of creating new MdsEntry objects is via the {@link MdsCollection#addEntry} and {@link MdsCollection#validate}
     * methods, which will take care of parsing and validing the MDS entry for you.
     * @param  {Object} mdsEntry The parsed and validated metadata statement Object for this entry
     * @param  {Object} tocEntry The parsed and validated TOC information Object for this entry
     * @return {mdsEntry}          The properly formatted MDS entry
     */
	constructor(mdsEntry, tocEntry) {
		for (let key of Object.keys(tocEntry)) {
			this[key] = tocEntry[key];
		}

		for (let key of Object.keys(mdsEntry)) {
			this[key] = mdsEntry[key];
		}

		if (this.metadataStatement)
			delete this.metadataStatement;

		// make fields more useable:

		// attachmentHint
		this.attachmentHint = this.attachmentHint instanceof Array ? this.attachmentHint : attachmentHintToArr(this.attachmentHint);
		function attachmentHintToArr(hint) {
			var ret = [];
			if (hint & 0x0001) ret.push("internal");
			if (hint & 0x0002) ret.push("external");
			if (hint & 0x0004) ret.push("wired");
			if (hint & 0x0008) ret.push("wireless");
			if (hint & 0x0010) ret.push("nfc");
			if (hint & 0x0020) ret.push("bluetooth");
			if (hint & 0x0040) ret.push("network");
			if (hint & 0x0080) ret.push("ready");
			if (hint & 0xFF00) throw new Error("unknown attachment hint flags: " + hint & 0xFF00);
			return ret;
		}

		// attestationTypes
		if (!Array.isArray(this.attestationTypes)) throw new Error("expected attestationTypes to be Array, got: " + this.attestationTypes);
		this.attestationTypes = this.attestationTypes.map((att) => typeof(att) === "string" ? att : attestationTypeToStr(att));
		function attestationTypeToStr(att) {
			switch (att) {
				case 0x3E07: return "basic-full";
				case 0x3E08: return "basic-surrogate";
				case 0x3E09: return "ecdaa";
				default:
					throw new Error("uknown attestation type: " + att);
			}
		}

		// authenticationAlgorithm
		if (this.authenticationAlgorithms)
			this.authenticationAlgorithm = this.authenticationAlgorithms[0];

		this.authenticationAlgorithm = typeof(this.authenticationAlgorithm) === "string" ? this.authenticationAlgorithm : algToStr(this.authenticationAlgorithm);
		function algToStr(alg) {
			switch (alg) {
				case 0x0001: return "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW";
				case 0x0002: return "ALG_SIGN_SECP256R1_ECDSA_SHA256_DER";
				case 0x0003: return "ALG_SIGN_RSASSA_PSS_SHA256_RAW";
				case 0x0004: return "ALG_SIGN_RSASSA_PSS_SHA256_DER";
				case 0x0005: return "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW";
				case 0x0006: return "ALG_SIGN_SECP256K1_ECDSA_SHA256_DER";
				case 0x0007: return "ALG_SIGN_SM2_SM3_RAW";
				case 0x0008: return "ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW";
				case 0x0009: return "ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER";
				default:
					throw new Error("unknown authentication algorithm: " + alg);
			}
		}

		//certificates
		if (this.attestationRootCertificates)
			for (const certificate of this.attestationRootCertificates)
				CertManager.addCert(certificate);

		// icon: TODO

		// keyProtection
		this.keyProtection = this.keyProtection instanceof Array ? this.keyProtection : keyProtToArr(this.keyProtection);
		function keyProtToArr(kp) {
			var ret = [];
			if (kp & 0x0001) ret.push("software");
			if (kp & 0x0002) ret.push("hardware");
			if (kp & 0x0004) ret.push("tee");
			if (kp & 0x0008) ret.push("secure-element");
			if (kp & 0x0010) ret.push("remote-handle");
			if (kp & 0xFFE0) throw new Error("unknown key protection flags: " + kp & 0xFFE0);
			return ret;
		}

		// matcherProtection
		this.matcherProtection = this.matcherProtection instanceof Array ? this.matcherProtection : matcherProtToArr(this.matcherProtection);
		function matcherProtToArr(mp) {
			var ret = [];
			if (mp & 0x0001) ret.push("software");
			if (mp & 0x0002) ret.push("hardware");
			if (mp & 0x0004) ret.push("tee");
			if (mp & 0xFFF8) throw new Error("unknown key protection flags: " + mp & 0xFFF8);
			return ret;
		}

		// publicKeyAlgAndEncoding
		if (this.publicKeyAlgAndEncodings)
			this.publicKeyAlgAndEncoding = `ALG_KEY_${this.publicKeyAlgAndEncodings[0].toUpperCase()}`;

		this.publicKeyAlgAndEncoding = typeof(this.publicKeyAlgAndEncoding) === "string" ? this.publicKeyAlgAndEncoding : pkAlgAndEncodingToStr(this.publicKeyAlgAndEncoding);
		function pkAlgAndEncodingToStr(pkalg) {
			switch (pkalg) {
				case 0x0100: return "ALG_KEY_ECC_X962_RAW";
				case 0x0101: return "ALG_KEY_ECC_X962_DER";
				case 0x0102: return "ALG_KEY_RSA_2048_RAW";
				case 0x0103: return "ALG_KEY_RSA_2048_DER";
				case 0x0104: return "ALG_KEY_COSE";
				default:
					throw new Error("unknown public key algorithm and encoding: " + pkalg);
			}
		}

		// tcDisplay
		this.tcDisplay = this.tcDisplay instanceof Array ? this.tcDisplay : tcDisplayToArr(this.tcDisplay);
		function tcDisplayToArr(tcd) {
			var ret = [];
			if (tcd & 0x0001) ret.push("any");
			if (tcd & 0x0002) ret.push("priviledged-software");
			if (tcd & 0x0004) ret.push("tee");
			if (tcd & 0x0008) ret.push("hardware");
			if (tcd & 0x0010) ret.push("remote");
			if (tcd & 0xFFE0) throw new Error("unknown transaction confirmation display flags: " + tcd & 0xFFE0);
			return ret;
		}

		// userVerificationDetails
		this.userVerificationDetails = uvDetailsToSet(this.userVerificationDetails);
		function uvDetailsToSet(uvList) {
			var ret = [];
			if (!Array.isArray(uvList)) throw new Error("expected userVerificationDetails to be an Array, got: " + uvList);
			uvList.forEach((uv) => {
				if (!Array.isArray(uv)) throw new Error("expected userVerification to be Array, got " + uv);
				let d = uv.map((desc) => {
					/**
                     * @typedef {Object} UserVerificationDesc
                     * @description A description of a user verification method that an authenticator will peform.
                     * The properties are as described below, plus the contents of `caDesc`, `baDesc` or `paDesc`
                     * (depending on whether "code", "biometrics", or "pattern" are being described)
                     * as described in the [FIDO Metadata specification]{@link https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html}
                     * @property {String} type The type of user verification that the authenticator performs.
                     * Valid options are "code" (i.e. PIN), "biometric", or "pattern".
                     * @property {String} userVerification The specific type of user verification performed,
                     * such as "fingerprint", "presence", "passcode", etc.
					 * @property {String} userVerificationMethod The method of user verification performed,
					 * such as "passcode_internal", "presence_internal", etc.
                     */
					let newDesc = {};
					var descKey;

					if ("caDesc" in desc) {
						newDesc.type = "code";
						descKey = "caDesc";
					}

					if ("baDesc" in desc) {
						newDesc.type = "biometric";
						descKey = "baDesc";
					}

					if ("paDesc" in desc) {
						newDesc.type = "pattern";
						descKey = "paDesc";
					}

					newDesc.userVerification = uvToArr(desc.userVerification);

					if (desc.userVerificationMethod)
						newDesc.userVerification = (desc.userVerificationMethod.match(/(\w+)_internal/) || [ "none", "none" ])[1];

					if (descKey) for (let key of Object.keys(desc[descKey])) {
						newDesc[key] = desc[descKey][key];
					}

					return newDesc;
				});
				ret.push(d);
			});
			return ret;
		}

		function uvToArr(uv) {
			var ret = [];
			if (uv & 0x00000001) ret.push("presence");
			if (uv & 0x00000002) ret.push("fingerprint");
			if (uv & 0x00000004) ret.push("passcode");
			if (uv & 0x00000008) ret.push("voiceprint");
			if (uv & 0x00000010) ret.push("faceprint");
			if (uv & 0x00000020) ret.push("location");
			if (uv & 0x00000040) ret.push("eyeprint");
			if (uv & 0x00000080) ret.push("pattern");
			if (uv & 0x00000100) ret.push("handprint");
			if (uv & 0x00000200) ret.push("none");
			if (uv & 0x00000400) ret.push("all");
			return ret;
		}
		// userVerificationDetails
		if (this.protocolFamily === undefined) this.protocolFamily = "uaf";

		// fix boolean values, since NNL doesn't validate them very well
		realBoolean(this, "isSecondFactorOnly");
		realBoolean(this, "isKeyRestricted");
		realBoolean(this, "isFreshUserVerificationRequired");
		// TODO: read spec for other values
	}
}

/**
 * A class for managing, validating, and finding metadata that describes authenticators
 *
 * This class does not do any of the downloading of the TOC or any of the entries in the TOC,
 * but assumes that you can download the data and pass it to this class. This allows for cleverness
 * and flexibility in how, when, and what is downloaded -- while at the same time allowing this class
 * to take care of the not-so-fun parts of validating signatures, hashes, certificat chains, and certificate
 * revocation lists.
 *
 * Typically this will be created through {@link Fido2Lib#createMdsCollection} and then set as the global
 * MDS collection via {@link Fido2Lib#setMdsCollection}
 *
 * @example
 * var mc = Fido2Lib.createMdsCollection()
 * // download TOC from https://mds.fidoalliance.org ...
 * var tocObj = await mc.addToc(tocBase64);
 * tocObj.entries.forEach((entry) => {
 *     // download entry.url ...
 *     mc.addEntry(entryBase64);
 * });
 * Fido2Lib.setMdsCollection(mc); // performs validation
 * var entry = Fido2Lib.findEntry("4e4e#4005");
 */
class MdsCollection {
	/**
     * Creates a new MdsCollection
     * @return {MdsCollection} The MDS collection that was created. The freshly created MDS collection has
     * no Table of Contents (TOC) or entries, which must be added through {@link addToc} and {@link addEntry}, respectively.
     */
	constructor(collectionName) {
		if (typeof collectionName !== "string" ||
            collectionName.length < 1) {
			throw new Error("expected 'collectionName' to be non-empty string, got: " + collectionName);
		}

		this.toc = null;
		this.unvalidatedEntryList = new Map();
		this.entryList = new Map();
		this.validated = false;
		this.name = collectionName;
	}

	/**
     * Validates and stores the Table of Contents (TOC) for future reference. This method validates
     * the TOC JSON Web Token (JWT) signature, as well as the certificate chain. The certiciate chain
     * is validated using the `rootCert` and `crls` that are provided.
     * @param {String} tocStr   The base64url encoded Table of Contents, as described in the [FIDO Metadata Service specification]{@link https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-service-v2.0-id-20180227.html}
     * @param {Array.<String>|Array.<ArrayBuffer>|String|ArrayBuffer|undefined} rootCert One or more root certificates that serve as a trust anchor for the Metadata Service.
     * Certificate format is flexible, and can be a PEM string, a base64 encoded string, or an ArrayBuffer, provieded that each of those formats can be decoded to valid ASN.1
     * If the `rootCert` is `undefined`, then the default [FIDO MDS root certificate](https://mds.fidoalliance.org/Root.cer) will be used.
     * @param {Array.<String>|Array.<ArrayBuffer>} crls     An array of Certificate Revocation Lists (CRLs) that should be used when validating
     * the certificate chain. Like `rootCert` the format of the CRLs is flexible and can be PEM encoded, base64 encoded, or an ArrayBuffer
     * provied that the CRL contains valid ASN.1 encoding.
     * @returns {Promise.<Object>} Returns a Promise that resolves to a TOC object, or that rejects with an error.
     */
	async addToc(tocStr, rootCert, crls) {
		if (typeof tocStr !== "string" ||
            tocStr.length < 1) {
			throw new Error("expected MDS TOC to be non-empty string");
		}

		// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-service-v2.0-id-20180227.html#metadata-toc-object-processing-rules
		// The FIDO Server MUST follow these processing rules:
		//    The FIDO Server MUST be able to download the latest metadata TOC object from the well-known URL, when appropriate. The nextUpdate field of the Metadata TOC specifies a date when the download SHOULD occur at latest.
		//    If the x5u attribute is present in the JWT Header, then:
		//        The FIDO Server MUST verify that the URL specified by the x5u attribute has the same web-origin as the URL used to download the metadata TOC from. The FIDO Server SHOULD ignore the file if the web-origin differs (in order to prevent loading objects from arbitrary sites).
		//        The FIDO Server MUST download the certificate (chain) from the URL specified by the x5u attribute [JWS]. The certificate chain MUST be verified to properly chain to the metadata TOC signing trust anchor according to [RFC5280]. All certificates in the chain MUST be checked for revocation according to [RFC5280].
		//        The FIDO Server SHOULD ignore the file if the chain cannot be verified or if one of the chain certificates is revoked.
		//    If the x5u attribute is missing, the chain should be retrieved from the x5c attribute. If that attribute is missing as well, Metadata TOC signing trust anchor is considered the TOC signing certificate chain.
		//    Verify the signature of the Metadata TOC object using the TOC signing certificate chain (as determined by the steps above). The FIDO Server SHOULD ignore the file if the signature is invalid. It SHOULD also ignore the file if its number (no) is less or equal to the number of the last Metadata TOC object cached locally.
		//    Write the verified object to a local cache as required.

		// JWT verify
		var parsedJws;
		try {
			parsedJws = await jose.JWS.createVerify().verify(tocStr, { allowEmbeddedKey: true });
			this.toc = JSON.parse(ab2str(coerceToArrayBuffer(parsedJws.payload, "MDS TOC payload")));
		} catch (e) {
			e.message = "could not parse and validate MDS TOC: " + e.message;
			throw e;
		}

		// add rootCert
		if (rootCert === undefined) {
			if (parsedJws.kid === "Metadata TOC Signer 3" || parsedJws.key && parsedJws.key.kid === "Metadata TOC Signer 3") {
				rootCert = "-----BEGIN CERTIFICATE-----\n" +
				"MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG\n" +
				"A1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFk\n" +
				"YXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoX\n" +
				"DTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxs\n" +
				"aWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRS\n" +
				"b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+\n" +
				"AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4ims\n" +
				"rfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYw\n" +
				"DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYw\n" +
				"HwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAw\n" +
				"ZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciW\n" +
				"DcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XU\n" +
				"YjdBz56jSA==\n" +
				"-----END CERTIFICATE-----\n";
			} else {
				rootCert = fidoMdsRootCert;
			}
		}

		// verify cert chain
		var rootCerts;
		if (Array.isArray(rootCert)) rootCerts = rootCert;
		else rootCerts = [rootCert];
		var ret = await CertManager.verifyCertChain(parsedJws.header.x5c, rootCerts, crls);

		// save the raw TOC
		this.toc.raw = tocStr;
		
		// check for MDS v2
		if (this.toc.entries.some(entry => !entry.metadataStatement)) console.warn("[DEPRECATION WARNING] FIDO MDS v2 will be removed in October 2022. Please update to MDS v3!");

		return this.toc;
	}

	/**
     * Returns the parsed and validated Table of Contents object from {@link getToc}
     * @return {Object|null} Returns the TOC if one has been provided to {@link getToc}
     * or `null` if no TOC has been provided yet.
     */
	getToc() {
		return this.toc;
	}

	/**
     * Parses and adds a new MDS entry to the collection. The entry will not be available
     * through {@link findEntry} until {@link validate} has been called
     * @param {String} entryStr The base64url encoded entry, most likely downloaded from
     * the URL that was found in the Table of Contents (TOC)
     */
	addEntry(entryStr) {
		if (typeof entryStr !== "string" ||
            entryStr.length < 1) {
			throw new Error("expected MDS entry to be non-empty string");
		}

		var newEntry = b64ToJsObject(entryStr, "MDS entry");
		if (newEntry.metadataStatement) {
			newEntry = newEntry.metadataStatement;
			//Get the base64 string with all non-ASCII characters removed
			entryStr = jsObjectToB64(newEntry);
		}

		newEntry.raw = entryStr;
		var newEntryId = getMdsEntryId(newEntry);

		if (Array.isArray(newEntryId)) {
			// U2F array of IDs
			newEntryId.forEach((id) => {
				this.unvalidatedEntryList.set(id, newEntry);
			});
		} else {
			// UAF and FIDO2
			this.unvalidatedEntryList.set(newEntryId, newEntry);
		}
	}

	/**
     * Validates all entries that have been added. Note that {@link MdsCollection#findEntry}
     * will not find an {@link MdsEntry} until it has been validated.
     * @throws {Error} If a validation error occurs
     */
	validate() {
		// throw if no TOC
		if (typeof this.toc !== "object" || this.toc === null) {
			throw new Error("add MDS TOC before attempting to validate MDS collection");
		}

		// throw if no new entries
		if (this.unvalidatedEntryList.size < 1) {
			throw new Error("add MDS entries before attempting to validate MDS collection");
		}

		// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-service-v2.0-id-20180227.html#metadata-toc-object-processing-rules
		//    Iterate through the individual entries (of type MetadataTOCPayloadEntry). For each entry:
		//        Ignore the entry if the AAID, AAGUID or attestationCertificateKeyIdentifiers is not relevant to the relying party (e.g. not acceptable by any policy)
		//        Download the metadata statement from the URL specified by the field url. Some authenticator vendors might require authentication in order to provide access to the data. Conforming FIDO Servers SHOULD support the HTTP Basic, and HTTP Digest authentication schemes, as defined in [RFC2617].
		//        Check whether the status report of the authenticator model has changed compared to the cached entry by looking at the fields timeOfLastStatusChange and statusReport. Update the status of the cached entry. It is up to the relying party to specify behavior for authenticators with status reports that indicate a lack of certification, or known security issues. However, the status REVOKED indicates significant security issues related to such authenticators.
		//        Note
		//        Authenticators with an unacceptable status should be marked accordingly. This information is required for building registration and authentication policies included in the registration request and the authentication request [UAFProtocol].
		//        Compute the hash value of the (base64url encoding without padding of the UTF-8 encoded) metadata statement downloaded from the URL and verify the hash value to the hash specified in the field hash of the metadata TOC object. Ignore the downloaded metadata statement if the hash value doesn't match.
		//        Update the cached metadata statement according to the dowloaded one.

		this.unvalidatedEntryList.forEach((entry) => {
			// find matching TOC entry
			let entryId = getMdsEntryId(entry);
			let tocEntry = this.toc.entries.filter((te) => {
				let teId = getMdsEntryId(te);
				let eq = idEquals(teId, entryId);
				return eq;
			});

			if (tocEntry.length !== 1) {
				throw new Error(`found the wrong number of TOC entries for '${entryId}': ${tocEntry.length}`);
			}
			tocEntry = tocEntry[0];

			// validate hash
			const hash = crypto.createHash("sha256");
			// coerceToArrayBuffer(entry.raw, "MDS entry")
			hash.update(entry.raw);
			var entryHash = hash.digest();
			var tocEntryHash;

			if (tocEntry.hash) {
				tocEntryHash = tocEntry.hash;
			} else {
				const tocHash = crypto.createHash("sha256");
				//Get the base64 string with all non-ASCII characters removed, then update the hash with it
				tocHash.update(jsObjectToB64(tocEntry.metadataStatement));
				tocEntryHash = tocHash.digest();
			}

			tocEntryHash = coerceToArrayBuffer(tocEntryHash, "MDS TOC entry hash");
			if (!(abEqual(entryHash, tocEntryHash))) {
				throw new Error("MDS entry hash did not match corresponding hash in MDS TOC");
			}

			// validate status report
			// TODO: maybe setValidateEntryCallback(fn);

			// add new entry to collection entryList
			var newEntry = new MdsEntry(entry, tocEntry);
			newEntry.collection = this;

			if (Array.isArray(entryId)) {
				// U2F array of IDs
				entryId.forEach((id) => {
					this.entryList.set(tocEntry.metadataStatement ? id.replace(/-/g, "") : id, newEntry);
				});
			} else {
				// UAF and FIDO2
				this.entryList.set(tocEntry.metadataStatement ? entryId.replace(/-/g, "") : entryId, newEntry);
			}
		});
	}

	/**
     * Looks up an entry by AAID, AAGUID, or attestationCertificateKeyIdentifiers.
     * Only entries that have been validated will be found.
     * @param  {String|ArrayBuffer} id The AAID, AAGUID, or attestationCertificateKeyIdentifiers of the entry to find
     * @return {MdsEntry|null}    The MDS entry that was found, or null if no entry was found.
     */
	findEntry(id) {
		if (id instanceof ArrayBuffer) {
			id = coerceToBase64Url(id, "MDS entry id");
		}

		if (typeof id !== "string") {
			throw new Error("expected 'id' to be String, got: " + id);
		}

		return this.entryList.get(id.replace(/-/g, "")) || this.entryList.get(Buffer.from(id, "base64").toString("hex").replace(/-/g, "")) || null;
	}
}

function getMdsEntryId(obj) {
	if (typeof obj !== "object") {
		throw new Error("getMdsEntryId expected 'obj' to be object, got: " + obj);
	}

	if (typeof obj.aaid === "string") {
		return obj.aaid;
	}

	if (typeof obj.aaguid === "string") {
		return obj.aaguid;
	}

	if (Array.isArray(obj.attestationCertificateKeyIdentifiers)) {
		return obj.attestationCertificateKeyIdentifiers;
	}

	throw new Error("MDS entry didn't have a valid ID");
}

function idEquals(id1, id2) {
	if (id1 instanceof ArrayBuffer) {
		id1 = coerceToBase64Url(id1);
	}

	if (id2 instanceof ArrayBuffer) {
		id2 = coerceToBase64Url(id2);
	}

	// UAF, FIDO2
	if (typeof id1 === "string" && typeof id2 === "string") {
		return id1 === id2;
	}

	// U2F
	if (Array.isArray(id1) && Array.isArray(id2)) {
		if (id1.length !== id2.length) return false;
		var allSame = id1.reduce((acc, val) => acc && id2.includes(val), true);
		if (!allSame) return false;
		return true;
	}

	// no match
	return false;
}

function realBoolean(obj, prop) {
	if (obj[prop] === "true") obj[prop] = true;
	if (obj[prop] === "false") obj[prop] = false;
}

module.exports = {
	MdsEntry,
	MdsCollection,
};
