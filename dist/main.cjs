'use strict';

var tldts = require('tldts');
var punycode = require('punycode.js');
var jose = require('jose');
var pkijs$1 = require('pkijs');
var asn1js = require('asn1js');
var cborX = require('cbor-x');
var base64 = require('@hexagon/base64');
var platformCrypto = require('crypto');
var peculiarCrypto = require('@peculiar/webcrypto');

function _interopNamespaceDefault(e) {
	var n = Object.create(null);
	if (e) {
		Object.keys(e).forEach(function (k) {
			if (k !== 'default') {
				var d = Object.getOwnPropertyDescriptor(e, k);
				Object.defineProperty(n, k, d.get ? d : {
					enumerable: true,
					get: function () { return e[k]; }
				});
			}
		});
	}
	n.default = e;
	return Object.freeze(n);
}

var cborX__namespace = /*#__PURE__*/_interopNamespaceDefault(cborX);
var platformCrypto__namespace = /*#__PURE__*/_interopNamespaceDefault(platformCrypto);
var peculiarCrypto__namespace = /*#__PURE__*/_interopNamespaceDefault(peculiarCrypto);

class Certificate {
	constructor(cert) {
		let decoded;

		// Clean up base64 string
		if (typeof cert === "string" || cert instanceof String) {
			cert = cert.replace(/\r/g, "").trim();
			decoded = ab2str(coerceToArrayBuffer$1(cert, "certificate"));
		}

		if (isPem(cert)) {
			cert = pemToBase64(cert);
		} else if (decoded && isPem(decoded)) {
			cert = pemToBase64(decoded);
		}

		// Clean up certificate
		if (typeof cert === "string" || cert instanceof String) {
			cert = cert.replace(/\n/g, "");
		}

		cert = coerceToArrayBuffer$1(cert, "certificate");
		if (cert.byteLength === 0) {
			throw new Error("cert was empty (0 bytes)");
		}

		const asn1 = asn1js.fromBER(cert);
		if (asn1.offset === -1) {
			throw new Error("error parsing ASN.1");
		}

		this._cert = new pkijs.Certificate({ schema: asn1.result });
		this.warning = new Map();
		this.info = new Map();
	}

	getCommonName() {
		return this.searchForCommonName(this._cert.subject.typesAndValues);
	}

	searchForCommonName(attributes) {
		const X509_COMMON_NAME_KEY = "2.5.4.3";
		// Search the attributes for the common name of the certificate
		for (const attr of attributes) {
			if (attr.type === X509_COMMON_NAME_KEY) {
				return attr.value.valueBlock.value;
			}
		}
		// Return empty string if not found
		return "";
	}

	verify() {
		const issuerCommonName = this.getIssuer();
		const issuerCert = CertManager.getCertByCommonName(issuerCommonName);
		const _issuerCert = issuerCert ? issuerCert._cert : undefined;
		return this._cert.verify(_issuerCert)
			.catch((err) => {
				// who the hell throws a string?
				if (typeof err === "string") {
					err = new Error(err);
				}

				return Promise.reject(err);
			});
	}

	async getPublicKey() {
		const k = await this._cert.getPublicKey();
		return k;
	}

	async getPublicKeyJwk() {
		const publicKey = await this.getPublicKey();

		// Covert CryptoKey to JWK
		const publicKeyJwk = await webcrypto.subtle.exportKey("jwk", publicKey);

		return publicKeyJwk;
	}

	getIssuer() {
		return this.searchForCommonName(this._cert.issuer.typesAndValues);
	}

	getSerial(compatibility) {
		if (compatibility === undefined) {
			console.warn("[DEPRECATION WARNING] Please use getSerial(\"v2\").");
		} else if (compatibility === "v1") {
			console.warn("[DEPRECATION WARNING] Please migrate to getSerial(\"v2\") which will return just the serial number.");
		}

		return (compatibility === "v2") 
			? this._cert.serialNumber.valueBlock.toString()
			: this.getCommonName();
	}

	getVersion() {
		// x.509 versions:
		// 0 = v1
		// 1 = v2
		// 2 = v3
		return (this._cert.version + 1);
	}

	getSubject() {
		const ret = new Map();
		const subjectItems = this._cert.subject.typesAndValues;
		for (const subject of subjectItems) {
			const kv = resolveOid(subject.type,decodeValue(subject.value.valueBlock));
			ret.set(kv.id, kv.value);
		}

		return ret;
	}

	getExtensions() {
		const ret = new Map();

		if (this._cert.extensions === undefined) return ret;

		for (const ext of this._cert.extensions) {
			let kv;

			let v = ext.parsedValue || ext.extnValue;
			try {
				if (v.valueBlock) {
					v = decodeValue(v.valueBlock);
				}
				kv = resolveOid(ext.extnID, v);
			} catch (err) {
				if (ext.critical === false) {
					this.warning.set("x509-extension-error", ext.extnID + ": " + err.message);
					continue;
				} else {
					throw err;
				}
			}

			ret.set(kv.id, kv.value);
		}

		return ret;
	}
}

function resolveOid(id, value) {
	/* eslint complexity: ["off"] */
	const ret = {
		id,
		value,
	};

	if (value && value.valueHex) value = value.valueHex;

	let retMap;
	switch (id) {
		// FIDO
		case "1.3.6.1.4.1.45724.2.1.1":
			ret.id = "fido-u2f-transports";
			ret.value = decodeU2FTransportType(value);
			return ret;
		case "1.3.6.1.4.1.45724.1.1.4":
			ret.id = "fido-aaguid";
			return ret;
			// Subject
		case "2.5.4.6":
			ret.id = "country-name";
			return ret;
		case "2.5.4.10":
			ret.id = "organization-name";
			return ret;
		case "2.5.4.11":
			ret.id = "organizational-unit-name";
			return ret;
		case "2.5.4.3":
			ret.id = "common-name";
			return ret;

			// cert attributes

		case "2.5.29.14":
			ret.id = "subject-key-identifier";
			return ret;
		case "2.5.29.15":
			ret.id = "key-usage";
			ret.value = decodeKeyUsage(value);
			return ret;
		case "2.5.29.19":
			ret.id = "basic-constraints";
			return ret;
		case "2.5.29.35":
			retMap = new Map();
			ret.id = "authority-key-identifier";
			retMap.set("key-identifier", decodeValue(value.keyIdentifier));
			// TODO: other values
			ret.value = retMap;
			return ret;
		case "2.5.29.32":
			ret.id = "certificate-policies";
			ret.value = decodeCertificatePolicies(value);
			return ret;
		case "1.3.6.1.4.1.311.21.31":
			ret.id = "policy-qualifiers";
			ret.value = decodePolicyQualifiers(value);
			return ret;
		case "2.5.29.37":
			ret.id = "ext-key-usage";
			ret.value = decodeExtKeyUsage(value);
			return ret;
		case "2.5.29.17":
			ret.id = "subject-alt-name";
			ret.value = decodeAltNames(value);
			return ret;
		case "1.3.6.1.5.5.7.1.1":
			ret.id = "authority-info-access";
			ret.value = decodeAuthorityInfoAccess(value);
			return ret;
		case "1.3.6.1.5.5.7.48.2":
			ret.id = "cert-authority-issuers";
			if (typeof value !== "object") {
				throw new Error("expect cert-authority-issues to have Object as value");
			}
			ret.value = decodeGeneralName(value.type, value.value);
			return ret;
		case "1.3.6.1.5.5.7.2.2":
			ret.id = "policy-qualifier";
			ret.value = decodeValue(value.valueBlock);
			return ret;

			// TPM
		case "2.23.133.8.3":
			ret.id = "tcg-kp-aik-certificate";
			return ret;
		case "2.23.133.2.1":
			ret.id = "tcg-at-tpm-manufacturer";
			return ret;
		case "2.23.133.2.2":
			ret.id = "tcg-at-tpm-model";
			return ret;
		case "2.23.133.2.3":
			ret.id = "tcg-at-tpm-version";
			return ret;

			// Yubico
		case "1.3.6.1.4.1.41482.2":
			ret.id = "yubico-device-id";
			ret.value = resolveOid(ab2str(value)).id;
			return ret;
		case "1.3.6.1.4.1.41482.1.1":
			ret.id = "Security Key by Yubico";
			return ret;
		case "1.3.6.1.4.1.41482.1.2":
			ret.id = "YubiKey NEO/NEO-n";
			return ret;
		case "1.3.6.1.4.1.41482.1.3":
			ret.id = "YubiKey Plus";
			return ret;
		case "1.3.6.1.4.1.41482.1.4":
			ret.id = "YubiKey Edge";
			return ret;
		case "1.3.6.1.4.1.41482.1.5":
			ret.id = "YubiKey 4/YubiKey 4 Nano";
			return ret;

			// TODO
			// 1.3.6.1.4.1.45724.1.1.4 FIDO AAGUID
			// basic-constraints Yubico FIDO2, ST Micro
			// 2.5.29.35 ST Micro
			// subject-key-identifier ST Micro
			// 1.3.6.1.4.1.41482.3.3 Yubico Firmware version, encoded as 3 bytes, like: 040300 for 4.3.0
			// 1.3.6.1.4.1.41482.3.7 Yubico serial number of the YubiKey, encoded as an integer
			// 1.3.6.1.4.1.41482.3.8 Yubico two bytes, the first encoding pin policy and the second touch policy
			// Pin policy: 01 - never, 02 - once per session, 03 - always
			// Touch policy: 01 - never, 02 - always, 03 - cached for 15s

		default:
			return ret;
	}
}

function decodeValue(valueBlock) {
	const blockType = Object.getPrototypeOf(valueBlock).constructor.name;
	// console.log("blockType", blockType);
	// console.log("valueBlock", valueBlock);
	switch (blockType) {
		case "LocalIntegerValueBlock":
			return valueBlock.valueDec;
		case "LocalOctetStringValueBlock":
			return valueBlock.valueHex;
		case "LocalUtf8StringValueBlock":
			return valueBlock.value;
		case "LocalSimpleStringValueBlock":
			return valueBlock.value;
		case "OctetString":
			return valueBlock.valueBlock.valueHex;
		case "LocalBitStringValueBlock":
			return new Uint8Array(valueBlock.valueHex)[0];
		case "LocalBmpStringValueBlock":
			return valueBlock.value;
		case "LocalConstructedValueBlock":
			if (typeof valueBlock === "object" &&
                Array.isArray(valueBlock.value)) {
				return valueBlock.value.map((v) => decodeValue(v));
			}
			return valueBlock;
		case "Constructed":
			return decodeValue(valueBlock.valueBlock.value[0]);
		case "BmpString":
			return decodeValue(valueBlock.valueBlock);
		case "Utf8String":
			return valueBlock.valueBlock.value;
		default:
			throw new TypeError("unknown value type when decoding certificate: " + blockType);
	}
}

function decodeU2FTransportType(u2fRawTransports) {
	const bitLen = 3;
	const bitCount = 8 - bitLen - 1;
	let type = (u2fRawTransports >> bitLen);
	const ret = new Set();
	for (let i = bitCount; i >= 0; i--) {
		// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-authenticator-transports-extension-v1.2-ps-20170411.html
		if (type & 0x1) switch (i) {
			case 0:
				ret.add("bluetooth-classic");
				break;
			case 1:
				ret.add("bluetooth-low-energy");
				break;
			case 2:
				ret.add("usb");
				break;
			case 3:
				ret.add("nfc");
				break;
			case 4:
				ret.add("usb-internal");
				break;
			default:
				throw new Error("unknown U2F transport type: " + type);
		}
		type >>= 1;
	}
	return ret;
}

function decodeKeyUsage(value) {
	if (typeof value !== "number") {
		throw new Error("certificate: expected 'keyUsage' value to be number");
	}

	const retSet = new Set();

	if (value & 0x80) retSet.add("digitalSignature");
	if (value & 0x40) retSet.add("contentCommitment");
	if (value & 0x20) retSet.add("keyEncipherment");
	if (value & 0x10) retSet.add("dataEncipherment");
	if (value & 0x08) retSet.add("keyAgreement");
	if (value & 0x04) retSet.add("keyCertSign");
	if (value & 0x02) retSet.add("cRLSign");
	if (value & 0x01) retSet.add("encipherOnly");
	if (value & 0x01) retSet.add("decipherOnly");


	return retSet;
}

function decodeExtKeyUsage(value) {
	let keyPurposes = value.keyPurposes;
	if (typeof value !== "object" || !Array.isArray(keyPurposes)) {
		throw new Error("expected extended key purposes to be an Array");
	}

	keyPurposes = keyPurposes.map((oid) => resolveOid(oid).id);
	return keyPurposes;
}

function decodeCertificatePolicies(value) {
	if (value && Array.isArray(value.certificatePolicies)) {
		value = value.certificatePolicies.map((_policy) => resolveOid(value.certificatePolicies[0].policyIdentifier, value.certificatePolicies[0].policyQualifiers));
	}

	return value;
}

function decodePolicyQualifiers(value) {
	if (value && Array.isArray(value)) {
		value = value.map((qual) => resolveOid(qual.policyQualifierId, qual.qualifier));
	}

	return value;
}

function decodeAltNames(value) {
	if (typeof value !== "object" || !Array.isArray(value.altNames)) {
		throw new Error("expected alternate names to be an Array");
	}
	let altNames = value.altNames;
	altNames = altNames.map((name) => {
		if (typeof name !== "object") {
			throw new Error("expected alternate name to be an object");
		}

		if (name.type !== 4) {
			throw new Error("expected all alternate names to be of general type");
		}

		if (typeof name.value !== "object" || !Array.isArray(name.value.typesAndValues)) {
			throw new Error("malformatted alternate name");
		}

		return decodeGeneralName(name.type, name.value.typesAndValues);
	});

	return altNames;
}

function decodeAuthorityInfoAccess(v) {
	if (typeof v !== "object" || !Array.isArray(v.accessDescriptions)) {
		throw new Error("expected authority info access descriptions to be Array");
	}

	const retMap = new Map();
	v.accessDescriptions.forEach((desc) => {
		const { id, value } = resolveOid(desc.accessMethod, desc.accessLocation);
		retMap.set(id, value);
	});
	return retMap;
}

function decodeGeneralName(type, v) {
	if (typeof type !== "number") {
		throw new Error("malformed general name in x509 certificate");
	}

	let nameList;
	switch (type) {
		case 0: // other name
			throw new Error("general name 'other name' not supported");
		case 1: // rfc822Name
			throw new Error("general name 'rfc822Name' not supported");
		case 2: // dNSName
			throw new Error("general name 'dNSName' not supported");
		case 3: // x400Address
			throw new Error("general name 'x400Address' not supported");
		case 4: // directoryName
			if (!Array.isArray(v)) {
				throw new Error("expected general name 'directory name' to be Array");
			}

			nameList = new Map();
			v.forEach((val) => {
				const { id, value } = resolveOid(val.type, decodeValue(val.value));
				nameList.set(id, value);
			});
			return { directoryName: nameList };
		case 5: // ediPartyName
			throw new Error("general name 'ediPartyName' not supported");
		case 6: // uniformResourceIdentifier
			return { uniformResourceIdentifier: v };
		case 7: // iPAddress
			throw new Error("general name 'iPAddress' not supported");
		case 8: // registeredID
			throw new Error("general name 'registeredID' not supported");
		default:
			throw new Error("unknown general name type: " + type);
	}
}

class CRL {
	constructor(crl) {

		// Clean up base64 string
		if (typeof crl === "string" || crl instanceof String) {
			crl = crl.replace(/\r/g, "");
		}
		
		if (isPem(crl)) {
			crl = pemToBase64(crl);
		}
		
		crl = coerceToArrayBuffer$1(crl, "crl");
		const asn1 = asn1js.fromBER(crl);
		this._crl = new pkijs.CertificateRevocationList({
			schema: asn1.result,
		});
	}
}

const certMap = new Map();
class CertManager {
	static addCert(certBuf) {
		const cert = new Certificate(certBuf);
		const commonName = cert.getCommonName();
		certMap.set(commonName, cert);

		return true;
	}

	static getCerts() {
		return new Map([...certMap]);
	}

	static getCertBySerial(serial) {
		console.warn("[DEPRECATION WARNING] Please use CertManager.getCertByCommonName(commonName).");
		return certMap.get(serial);
	}

	static getCertByCommonName(commonName) {
		return certMap.get(commonName);
	}

	static removeAll() {
		certMap.clear();
	}

	static async verifyCertChain(certs, roots, crls) {
		if (!Array.isArray(certs) ||
            certs.length < 1) {
			throw new Error("expected 'certs' to be non-empty Array, got: " + certs);
		}

		certs = certs.map((cert) => {
			if (!(cert instanceof Certificate)) {
				// throw new Error("expected 'cert' to be an instance of Certificate");
				cert = new Certificate(cert);
			}

			return cert._cert;
		});

		if (!Array.isArray(roots) ||
            roots.length < 1) {
			throw new Error("expected 'roots' to be non-empty Array, got: " + roots);
		}

		roots = roots.map((r) => {
			if (!(r instanceof Certificate)) {
				// throw new Error("expected 'root' to be an instance of Certificate");
				r = new Certificate(r);
			}

			return r._cert;
		});

		crls = crls || [];
		if (!Array.isArray(crls)) {
			throw new Error("expected 'crls' to be undefined or Array, got: " + crls);
		}

		crls = crls.map((crl) => {
			if (!(crl instanceof CRL)) {
				// throw new Error("expected 'crl' to be an instance of Certificate");
				crl = new CRL(crl);
			}

			return crl._crl;
		});

		const chain = new pkijs.CertificateChainValidationEngine({
			trustedCerts: roots,
			certs,
			crls,
		});

		const res = await chain.verify();
		if (!res.result) {
			throw new Error(res.resultMessage);
		} else {
			return res;
		}
	}
}

const helpers = {
	resolveOid,
};

/**
 * Main COSE labels
 * defined here: https://tools.ietf.org/html/rfc8152#section-7.1
 * used by {@link fromCose}
 * 
 * @private
 */
const coseLabels = {
	1: {
		name: "kty",
		values: {
			1: "OKP",
			2: "EC",
			3: "RSA",
		},
	},
	2: {
		name: "kid",
		values: {},
	},
	3: {
		name: "alg",
		values: {
			"-7": "ECDSA_w_SHA256",
			/* "-8": "EdDSA", */
			"-35": "ECDSA_w_SHA384",
			"-36": "ECDSA_w_SHA512",
			/*"-37": "RSASSA-PSS_w_SHA-256",
			"-38": "RSASSA-PSS_w_SHA-384",
			"-39": "RSASSA-PSS_w_SHA-512",*/
			"-257": "RSASSA-PKCS1-v1_5_w_SHA256",
			"-258": "RSASSA-PKCS1-v1_5_w_SHA384",
			"-259": "RSASSA-PKCS1-v1_5_w_SHA512",
			"-65535": "RSASSA-PKCS1-v1_5_w_SHA1",
		},
	},
	4: {
		name: "key_ops",
		values: {},
	},
	5: {
		name: "base_iv",
		values: {},
	},
};

/**
 * Key specific COSE parameters
 * used by {@link fromCose}
 * 
 * @private
 */
const coseKeyParamList = {
	// ECDSA key parameters
	// defined here: https://tools.ietf.org/html/rfc8152#section-13.1.1
	EC: {
		"-1": {
			name: "crv",
			values: {
				1: "P-256",
				2: "P-384",
				3: "P-521",
			},
		},
		// value = Buffer
		"-2": { name: "x" },
		"-3": { name: "y" },
		"-4": { name: "d" },
	},
	// Octet Key Pair key parameters
	// defined here: https://datatracker.ietf.org/doc/html/rfc8152#section-13.2
	OKP: {
		"-1": {
			name: "crv",
			values: {
				4: "X25519",
				5: "X448",
				6: "Ed25519",
				7: "Ed448",
			},
		},
		// value = Buffer
		"-2": { name: "x" },
		"-4": { name: "d" },
	},
	// RSA key parameters
	// defined here: https://tools.ietf.org/html/rfc8230#section-4
	RSA: {
		// value = Buffer
		"-1": { name: "n" },
		"-2": { name: "e" },
		"-3": { name: "d" },
		"-4": { name: "p" },
		"-5": { name: "q" },
		"-6": { name: "dP" },
		"-7": { name: "dQ" },
		"-8": { name: "qInv" },
		"-9": { name: "other" },
		"-10": { name: "r_i" },
		"-11": { name: "d_i" },
		"-12": { name: "t_i" },
	},
};

/**
 * Maps COSE algorithm identifier to JWK alg
 * used by {@link fromCose}
 * 
 * @private
 */
const algToJWKAlg = {
	"RSASSA-PKCS1-v1_5_w_SHA256": "RS256",
	"RSASSA-PKCS1-v1_5_w_SHA384": "RS384",
	"RSASSA-PKCS1-v1_5_w_SHA512": "RS512",
	"RSASSA-PKCS1-v1_5_w_SHA1": "RS256",
	/*
	PS256-512 is untested 
	"RSASSA-PSS_w_SHA-256": "PS256",
	"RSASSA-PSS_w_SHA-384": "PS384",
	"RSASSA-PSS_w_SHA-512": "PS512",*/
	"ECDSA_w_SHA256": "ES256",
	"ECDSA_w_SHA384": "ES384",
	"ECDSA_w_SHA512": "ES512",
	/*
	EdDSA is untested and unfinished
	"EdDSA": "EdDSA" */
};

/**
 * Maps Cose algorithm identifier or JWK.alg to webcrypto algorithm identifier
 * used by {@link setAlgorithm}
 * 
 * @private
 */
const algorithmInputMap = {
	/* Cose Algorithm identifier to Webcrypto algorithm name */
	"RSASSA-PKCS1-v1_5_w_SHA256": "RSASSA-PKCS1-v1_5",
	"RSASSA-PKCS1-v1_5_w_SHA384": "RSASSA-PKCS1-v1_5",
	"RSASSA-PKCS1-v1_5_w_SHA512": "RSASSA-PKCS1-v1_5",
	"RSASSA-PKCS1-v1_5_w_SHA1": "RSASSA-PKCS1-v1_5",
	/*"RSASSA-PSS_w_SHA-256": "RSASSA-PSS",
	"RSASSA-PSS_w_SHA-384": "RSASSA-PSS",
	"RSASSA-PSS_w_SHA-512": "RSASSA-PSS",*/
	"ECDSA_w_SHA256": "ECDSA",
	"ECDSA_w_SHA384": "ECDSA",
	"ECDSA_w_SHA512": "ECDSA",
	/*"EdDSA": "EdDSA",*/

	/* JWK alg to Webcrypto algorithm name */
	"RS256": "RSASSA-PKCS1-v1_5",
	"RS384": "RSASSA-PKCS1-v1_5",
	"RS512": "RSASSA-PKCS1-v1_5",
	/*"PS256": "RSASSA-PSS",
	"PS384": "RSASSA-PSS",
	"PS512": "RSASSA-PSS",*/
	"ES384": "ECDSA",
	"ES256": "ECDSA",
	"ES512": "ECDSA",
	/*"EdDSA": "EdDSA",*/
};

/**
 * Maps Cose algorithm identifier webcrypto hash name
 * used by {@link setAlgorithm}
 * 
 * @private
 */
const inputHashMap = {
	/* Cose Algorithm identifier to Webcrypto hash name */
	"RSASSA-PKCS1-v1_5_w_SHA256": "SHA-256",
	"RSASSA-PKCS1-v1_5_w_SHA384": "SHA-384",
	"RSASSA-PKCS1-v1_5_w_SHA512": "SHA-512",
	"RSASSA-PKCS1-v1_5_w_SHA1": "SHA-1",
	/*"RSASSA-PSS_w_SHA256": "SHA-256",
	"RSASSA-PSS_w_SHA384": "SHA-384",
	"RSASSA-PSS_w_SHA512": "SHA-512",*/
	"ECDSA_w_SHA256": "SHA-256",
	"ECDSA_w_SHA384": "SHA-384",
	"ECDSA_w_SHA512": "SHA-512",
	/* "EdDSA": "EdDSA", */
};

/** 
 * Class representing a generic public key, 
 * with utility functions to convert between different formats
 * using Webcrypto
 * 
 * @package
 * 
 */
class PublicKey {

	/**
	 * Create a empty public key
	 * 
	 * @returns {CryptoKey}
	 */
	constructor() {
		/**
		 * Internal reference to imported PEM string
		 * @type {string}
		 * @private
		 */
		this._original_pem = undefined;

		/**
		 * Internal reference to imported JWK object
		 * @type {object}
		 * @private
		 */
		this._original_jwk = undefined;

		/**
		 * Internal reference to imported Cose data
		 * @type {object}
		 * @private
		 */
		this._original_cose = undefined;

		/**
		 * Internal reference to algorithm, should be of RsaHashedImportParams or EcKeyImportParams format
		 * @type {object}
		 * @private
		 */
		this._alg = undefined;

		/**
		 * Internal reference to a CryptoKey object
		 * @type {object}
		 * @private
		 */
		this._key = undefined;
	}

	/**
	 * Import a CryptoKey, makes basic checks and throws on failure
	 * 
	 * @public
	 * @param {CryptoKey} key - CryptoKey to import
	 * @param {object} [alg] - Algorithm override
	 * 
	 * @returns {CryptoKey} - Returns this for chaining
	 */
	fromCryptoKey(key, alg) {
		
		// Throw on missing key
		if (!key) {
			throw new TypeError("No key passed");
		}

		// Allow a CryptoKey to be passed through the constructor
		if (key && (!key.type || key.type !== "public")) {
			throw new TypeError("Invalid argument passed to fromCryptoKey, should be instance of CryptoKey with type public");
		}

		// Store key
		this._key = key;

		// Store internal representation of algorithm
		this.setAlgorithm(key.algorithm);

		// Update algorithm if passed
		if (alg) {
			this.setAlgorithm(alg);
		}

		return this;

	}

	/**
	 * Import public key from SPKI PEM. Throws on any type of failure.
	 *
	 * @async
	 * @public
	 * @param {string} pem - PEM formatted string
	 * @return {Promise<PublicKey>} - Returns itself for chaining
	 */
	async fromPem(pem, hashName) {

		// Convert PEM to Base64
		let base64ber,
			ber;

		// Clean up base64 string
		if (typeof pem === "string" || pem instanceof String) {
			pem = pem.replace(/\r/g, "");
		}

		if (isPem(pem)) {
			base64ber = pemToBase64(pem);
			ber = coerceToArrayBuffer$1(base64ber, "base64ber");
		} else {
			throw new Error("Supplied key is not in PEM format");
		}

		if (ber.byteLength === 0) {
			throw new Error("Supplied key ber was empty (0 bytes)");
		}

		// Extract x509 information
		const asn1 = asn1js.fromBER(ber);
		if (asn1.offset === -1) {
			throw new Error("error parsing ASN.1");
		}
		let keyInfo = new pkijs.PublicKeyInfo({ schema: asn1.result });
		const algorithm = {};

		// Extract algorithm from key info
		if (keyInfo.algorithm.algorithmId === "1.2.840.10045.2.1") {
			algorithm.name = "ECDSA";

			// Use parsedKey to extract namedCurve if present, else default to P-256
			const parsedKey = keyInfo.parsedKey;
			if (parsedKey && parsedKey.namedCurve === "1.2.840.10045.3.1.7") {  // NIST P-256, secp256r1
				algorithm.namedCurve = "P-256";
			} else if (parsedKey && parsedKey.namedCurve === "1.3.132.0.34") {  // NIST P-384, secp384r1
				algorithm.namedCurve = "P-384";
			} else if (parsedKey && parsedKey.namedCurve === "1.3.132.0.35") {  // NIST P-512, secp521r1
				algorithm.namedCurve = "P-512";
			} else {
				algorithm.namedCurve = "P-256";
			}

			// Handle RSA
		} else if (keyInfo.algorithm.algorithmId === "1.2.840.113549.1.1.1") {
			algorithm.name = "RSASSA-PKCS1-v1_5";

			// Default hash to SHA-256
			algorithm.hash = hashName || "SHA-256";
		}
		this.setAlgorithm(algorithm);

		// Import key using webcrypto
		let importSPKIResult;
		try {
			importSPKIResult = await webcrypto.subtle.importKey("spki", ber, algorithm, true, ["verify"]);
		} catch (_e1) {
			throw new Error("Unsupported key format", _e1);
		}

		// Store references
		this._original_pem = pem;
		this._key = importSPKIResult;
		
		return this;
	}

	
	/**
	 * Import public key from JWK. Throws on any type of failure.
	 *
	 * @async
	 * @public
	 * @param {object} jwk - JWK object
	 * @return {Promise<PublicKey>} - Returns itself for chaining
	 */
	async fromJWK(jwk, extractable) {

		// Copy JWK
		const jwkCopy = JSON.parse(JSON.stringify(jwk));
		// Force extractable flag if specified
		if (
			typeof extractable !== "undefined" &&
			typeof extractable === "boolean"
		) {
			jwkCopy.ext = extractable;
		}

		// Store alg
		this.setAlgorithm(jwkCopy);

		// Import jwk with Jose
		this._original_jwk = jwk;

		const generatedKey = await webcrypto.subtle.importKey(
			"jwk",
			jwkCopy,
			this.getAlgorithm(),
			true,
			["verify"]
		);
		this._key = generatedKey;
		return this;
	}

	/**
	 * Import public key from COSE data. Throws on any type of failure.
	 * 
	 * Internally this function converts COSE to a JWK, then calls .fromJwk() to import key to CryptoKey
	 *
	 * @async
	 * @public
	 * @param {object} cose - COSE data
	 * @return {Promise<PublicKey>} - Returns itself for chaining
	 */
	async fromCose(cose) {
		if (typeof cose !== "object") {
			throw new TypeError(
				"'cose' argument must be an object, probably an Buffer conatining valid COSE",
			);
		}

		this._cose = coerceToArrayBuffer$1(cose, "coseToJwk");

		let parsedCose;
		try {
			// In the current state, the "cose" parameter can contain not only the actual cose (= public key) but also extensions.
			// Both are CBOR encoded entries, so you can treat and evaluate the "cose" parameter accordingly.
			// "fromCose" is called from a context that contains an active AT flag (attestation), so the first CBOR entry is the actual cose.
			// "tools.cbor.decode" will fail when multiple entries are provided (e.g. cose + at least one extension), so "decodeMultiple" is the sollution.
			cborX__namespace.decodeMultiple(
				new Uint8Array(cose),
				cborObject => {
					parsedCose = cborObject;
					return false;
				}
			);
		} catch (err) {
			throw new Error(
				"couldn't parse authenticator.authData.attestationData CBOR: " +
					err,
			);
		}
		if (typeof parsedCose !== "object") {
			throw new Error(
				"invalid parsing of authenticator.authData.attestationData CBOR",
			);
		}
		const coseMap = new Map(Object.entries(parsedCose));
		const extraMap = new Map();
		const retKey = {};
		// parse main COSE labels
		for (const kv of coseMap) {
			const key = kv[0].toString();
			let value = kv[1].toString();

			if (!coseLabels[key]) {
				extraMap.set(kv[0], kv[1]);
				continue;
			}

			const name = coseLabels[key].name;
			if (coseLabels[key].values[value]) {
				value = coseLabels[key].values[value];
			}
			retKey[name] = value;
		}
		const keyParams = coseKeyParamList[retKey.kty];

		// parse key-specific parameters
		for (const kv of extraMap) {
			const key = kv[0].toString();
			let value = kv[1];

			if (!keyParams[key]) {
				throw new Error(
					"unknown COSE key label: " + retKey.kty + " " + key,
				);
			}
			const name = keyParams[key].name;

			if (keyParams[key].values) {
				value = keyParams[key].values[value.toString()];
			}
			value = coerceToBase64Url(value, "coseToJwk");

			retKey[name] = value;
		}

		// Store reference to original cose object
		this._original_cose = cose;

		// Set algorithm from cose JWK-like
		this.setAlgorithm(retKey);

		// Convert cose algorithm identifier to jwk algorithm name
		retKey.alg = algToJWKAlg[retKey.alg];

		await this.fromJWK(retKey, true);
		return this;
	}

	/**
	 * Exports public key to PEM. 
	 * - Reuses original PEM string if present.
	 * - Possible to force regeneration of PEM string by setting 'forcedExport' parameter to true
	 * - Throws on any kind of failure
	 *
	 * @async
	 * @public
	 * @param {boolean} [forcedExport] - Force regeneration of PEM string even if original PEM-string is available
	 * @return {Promise<string>} - Returns PEM string
	 */
	async toPem(forcedExport) {
		if (this._original_pem && !forcedExport) {
			return this._original_pem;
		} else if (this.getKey()) {
			let pemResult = abToPem("PUBLIC KEY",await webcrypto.subtle.exportKey("spki", this.getKey()));

			return pemResult;
		} else {
			throw new Error("No key information available");
		}
	}

	/**
	 * Exports public key to JWK. 
	 * - Only works if original jwk from 'fromJwk()' is available
	 * - Throws on any kind of failure
	 *
	 * @public
	 * @return {object} - Returns JWK object
	 */
	toJwk() {
		if (this._original_jwk) {
			return this._original_jwk;
		} else {
			throw new Error("No usable key information available");
		}
	}

	/**
	 * Exports public key to COSE data 
	 * - Only works if original cose data from 'fromCose()' is available
	 * - Throws on any kind of failure
	 *
	 * @public
	 * @return {object} - Returns COSE data object
	 */
	toCose() {
		if (this._original_cose) {
			return this._original_cose;
		} else {
			throw new Error("No usable key information available");
		}
	}

	/**
	 * Returns internal key in CryptoKey format
	 * - Mainly intended for internal use
	 * - Throws if internal CryptoKey does not exist
	 *
	 * @public
	 * @return {CryptoKey} - Internal CryptoKey instance, or undefined
	 */
	getKey() {
		if (this._key) {
			return this._key;
		} else {
			throw new Error("Key data not available");
		}
	}

	/**
	 * Returns internal algorithm, which should be of one of the following formats 
	 * - RsaHashedImportParams
	 * - EcKeyImportParams
	 * - undefined
	 *
	 * @public
	 * @return {object|undefined} - Internal algorithm representation, or undefined
	 */
	getAlgorithm() {
		return this._alg;
	}

	/**
	 * Sets internal algorithm identifier in format used by webcrypto, should be one of
	 * - Allows adding missing properties
	 * - Makes sure `alg.hash` is is `{ hash: { name: 'foo'} }` format
	 * - Syncs back updated algorithm to this._key
	 *
	 * @public
	 * @param {object} - RsaHashedImportParams, EcKeyImportParams, JWK or JWK-like
	 * @return {object|undefined} - Internal algorithm representation, or undefined
	 */
	setAlgorithm(algorithmInput) {

		let algorithmOutput = this._alg || {};

		// Check for name if not already present
		// From Algorithm object
		if (algorithmInput.name) {
			algorithmOutput.name = algorithmInput.name;
			// JWK or JWK-like
		} else if (algorithmInput.alg) {
			const algMapResult = algorithmInputMap[algorithmInput.alg];
			if (algMapResult) {
				algorithmOutput.name = algMapResult;	
			}
		}

		// Check for hash if not already present
		// From Algorithm object
		if (algorithmInput.hash) {
			if (algorithmInput.hash.name) {
				algorithmOutput.hash = algorithmInput.hash;
			} else {
				algorithmOutput.hash = { name: algorithmInput.hash };			}
			// Try to extract hash from JWK-like .alg
		} else if (algorithmInput.alg) {
			let hashMapResult = inputHashMap[algorithmInput.alg];
			if (hashMapResult) {
				algorithmOutput.hash = { name: hashMapResult };
			}

		}

		// Try to extract namedCurve if not already present
		if (algorithmInput.namedCurve) {
			algorithmOutput.namedCurve = algorithmInput.namedCurve;
		} else if (algorithmInput.crv) {
			algorithmOutput.namedCurve = algorithmInput.crv;
		}

		// Set this._alg if any algorithm properties existed, or were added
		if (Object.keys(algorithmOutput).length > 0) {
			this._alg = algorithmOutput;

			// Sync algorithm hash to CryptoKey
			if (this._alg.hash && this._key) {
				this._key.algorithm.hash = this._alg.hash;
			}
		}

	}

}

/** 
 * Utility function to convert a cose algorithm to string
 * 
 * @package
 * 
 * @param {string|number} - Cose algorithm
*/
function coseAlgToStr(alg) {
	if (typeof alg !== "number") {
		throw new TypeError("expected 'alg' to be a number, got: " + alg);
	}

	const algValues = coseLabels["3"].values;

	const mapResult = algValues[alg];
	if (!mapResult) {
		throw new Error("'alg' is not a valid COSE algorithm number");
	}

	return algValues[alg];
}


/** 
 * Utility function to convert a cose hashing algorithm to string
 * 
 * @package
 * 
 * @param {string|number} - Cose algorithm
 */
function coseAlgToHashStr(alg) {
	if (typeof alg === "number") alg = coseAlgToStr(alg);

	if (typeof alg !== "string") {
		throw new Error("'alg' is not a string or a valid COSE algorithm number");
	}

	const mapResult = inputHashMap[alg];
	if (!mapResult) {
		throw new Error("'alg' is not a valid COSE algorithm");
	}

	return inputHashMap[alg];
}

// External dependencies
let webcrypto;
if ((typeof self !== "undefined") && "crypto" in self) {
	// Always use crypto if available natively (browser / Deno)
	webcrypto = self.crypto;

} else {
	// Always use node webcrypto if available ( >= 16.0 )
	if(platformCrypto__namespace && platformCrypto__namespace.webcrypto) {
		webcrypto = platformCrypto__namespace.webcrypto;

	} else {
		// Fallback to @peculiar/webcrypto
		webcrypto = new peculiarCrypto__namespace.Crypto();
	}
}

// Set up pkijs
const pkijs = {
	setEngine: pkijs$1.setEngine,
	CryptoEngine: pkijs$1.CryptoEngine,
	Certificate: pkijs$1.Certificate,
	CertificateRevocationList: pkijs$1.CertificateRevocationList,
	CertificateChainValidationEngine: pkijs$1.CertificateChainValidationEngine,
	PublicKeyInfo: pkijs$1.PublicKeyInfo,
};
pkijs.setEngine(
	"newEngine",
	webcrypto,
	new pkijs.CryptoEngine({
		name: "",
		crypto: webcrypto,
		subtle: webcrypto.subtle,
	}),
);

function extractBigNum(fullArray, start, end, expectedLength) {
	let num = fullArray.slice(start, end);
	if (num.length !== expectedLength){
		num = Array(expectedLength).fill(0).concat(...num).slice(num.length);
	}
	return num;
}

/*
    Convert signature from DER to raw
    Expects Uint8Array
*/
function derToRaw(signature) {
	const rStart = 4;
	const rEnd = rStart + signature[3];
	const sStart = rEnd + 2;
	return new Uint8Array([
		...extractBigNum(signature, rStart, rEnd, 32),
		...extractBigNum(signature, sStart, signature.length, 32),
	]);
}
function isAndroidFacetId(str) {
	return str.startsWith("android:apk-key-hash:");
}

function isIOSFacetId(str) {
	return str.startsWith("ios:bundle-id:");
}


function checkOrigin(str) {
	if(!str)
		throw new Error("Empty Origin");

	if (isAndroidFacetId(str) || isIOSFacetId(str)) {
		return str;
	}

	const originUrl = new URL(str);
	const origin = originUrl.origin;

	if (origin !== str) {
		throw new Error("origin was malformatted");
	}

	const isLocalhost = (originUrl.hostname == "localhost" ||
		originUrl.hostname.endsWith(".localhost"));

	if (originUrl.protocol !== "https:" && !isLocalhost) {
		throw new Error("origin should be https");
	}

	if (
		(!validDomainName(originUrl.hostname) ||
			!validEtldPlusOne(originUrl.hostname)) && !isLocalhost
	) {
		throw new Error("origin is not a valid eTLD+1");
	}

	return origin;
}

function checkUrl(value, name, rules = {}) {
	if (!name) {
		throw new TypeError("name not specified in checkUrl");
	}

	if (typeof value !== "string") {
		throw new Error(`${name} must be a string`);
	}

	let urlValue = null;
	try {
		urlValue = new URL(value);
	} catch (_err) {
		throw new Error(`${name} is not a valid eTLD+1/url`);
	}

	if (!value.startsWith("http")) {
		throw new Error(`${name} must be http protocol`);
	}

	if (!rules.allowHttp && urlValue.protocol !== "https:") {
		throw new Error(`${name} should be https`);
	}

	// origin: base url without path including /
	if (
		!rules.allowPath && (value.endsWith("/") || urlValue.pathname !== "/")
	) { // urlValue adds / in path always
		throw new Error(`${name} should not include path in url`);
	}

	if (!rules.allowHash && urlValue.hash) {
		throw new Error(`${name} should not include hash in url`);
	}

	if (!rules.allowCred && (urlValue.username || urlValue.password)) {
		throw new Error(`${name} should not include credentials in url`);
	}

	if (!rules.allowQuery && urlValue.search) {
		throw new Error(`${name} should not include query string in url`);
	}

	return value;
}

function validEtldPlusOne(value) {
	// Parse domain name
	const result = tldts.parse(value, { allowPrivateDomains: true });

	// Require valid public suffix
	if (result.publicSuffix === null) {
		return false;
	}

	// Require valid hostname
	if (result.domainWithoutSuffix === null) {
		return false;
	}

	return true;
}

function validDomainName(value) {
	// Before we can validate we need to take care of IDNs with unicode chars.
	const ascii = punycode.toASCII(value);

	if (ascii.length < 1) {
		// return 'DOMAIN_TOO_SHORT';
		return false;
	}
	if (ascii.length > 255) {
		// return 'DOMAIN_TOO_LONG';
		return false;
	}

	// Check each part's length and allowed chars.
	const labels = ascii.split(".");
	let label;

	for (let i = 0; i < labels.length; ++i) {
		label = labels[i];
		if (!label.length) {
			// LABEL_TOO_SHORT
			return false;
		}
		if (label.length > 63) {
			// LABEL_TOO_LONG
			return false;
		}
		if (label.charAt(0) === "-") {
			// LABEL_STARTS_WITH_DASH
			return false;
		}
		/* if (label.charAt(label.length - 1) === '-') {
			// LABEL_ENDS_WITH_DASH
			return false;
		} */
		if (!/^[a-z0-9-]+$/.test(label)) {
			// LABEL_INVALID_CHARS
			return false;
		}
	}

	return true;
}

function checkDomainOrUrl(value, name, rules = {}) {
	if (!name) {
		throw new TypeError("name not specified in checkDomainOrUrl");
	}

	if (typeof value !== "string") {
		throw new Error(`${name} must be a string`);
	}

	if (validEtldPlusOne(value) && validDomainName(value)) {
		return value; // if valid domain no need for futher checks
	}

	return checkUrl(value, name, rules);
}

function checkRpId(rpId) {
	if (typeof rpId !== "string") {
		throw new Error("rpId must be a string");
	}

	const isLocalhost = (rpId === "localhost" || rpId.endsWith(".localhost"));

	if (isLocalhost) return rpId;

	return checkDomainOrUrl(rpId, "rpId");
}

async function verifySignature(publicKey, expectedSignature, data, hashName) {

	let publicKeyInst;
	if (publicKey instanceof PublicKey) {
		publicKeyInst = publicKey;

	// Check for Public CryptoKey
	} else if (publicKey && publicKey.type === "public") {
		publicKeyInst = new PublicKey();
		publicKeyInst.fromCryptoKey(publicKey);
	
	// Try importing from PEM
	} else {
		publicKeyInst = new PublicKey();
		await publicKeyInst.fromPem(publicKey);

	}
	
	// Check for valid algorithm
	const alg = publicKeyInst.getAlgorithm();
	if (typeof alg === "undefined") {
		throw new Error("verifySignature: Algoritm missing.");
	}

	// Use supplied hashName
	if (hashName) {
		alg.hash = {
			name: hashName,
		};
	}
	if (!alg.hash) {
		throw new Error("verifySignature: Hash name missing.");
	}

	// Sync (possible updated) algorithm back to key
	publicKeyInst.setAlgorithm(alg);

	try {
		let uSignature = new Uint8Array(expectedSignature);
		if (alg.name === "ECDSA") {
			uSignature = await derToRaw(uSignature);
		}
		return await webcrypto.subtle.verify(publicKeyInst.getAlgorithm(), publicKeyInst.getKey(), uSignature, new Uint8Array(data));
	} catch (_e) {
		console.error(_e);
	}
}

async function hashDigest(o, alg) {
	if (typeof o === "string") {
		o = new TextEncoder().encode(o);
	}
	const result = await webcrypto.subtle.digest(alg || "SHA-256", o);
	return result;
}

function randomValues(n) {
	const byteArray = new Uint8Array(n);
	webcrypto.getRandomValues(byteArray);
	return byteArray;
}

function getHostname(urlIn) {
	return new URL(urlIn).hostname;
}

async function getEmbeddedJwk(jwsHeader, alg) {
	let publicKeyJwk;

	// Use JWK from header
	if (jwsHeader.jwk) {
		publicKeyJwk = jwsHeader.jwk;

		// Extract JWK from first x509 certificate in header
	} else if (jwsHeader.x5c) {
		const x5c0 = jwsHeader.x5c[0];
		const cert = new Certificate(x5c0);
		publicKeyJwk = await cert.getPublicKeyJwk();

		// Use common name as kid if missing
		publicKeyJwk.kid = publicKeyJwk.kid || cert.getCommonName();
	}

	if (!publicKeyJwk) {
		throw new Error("getEmbeddedJwk: JWK not found in JWS.");
	}

	// Use alg from header if not present, use passed alg as default
	publicKeyJwk.alg = publicKeyJwk.alg || jwsHeader.alg || alg;

	return publicKeyJwk;
}

var toolbox = /*#__PURE__*/Object.freeze({
	__proto__: null,
	base64: base64,
	cbor: cborX__namespace,
	checkDomainOrUrl: checkDomainOrUrl,
	checkOrigin: checkOrigin,
	checkRpId: checkRpId,
	checkUrl: checkUrl,
	decodeProtectedHeader: jose.decodeProtectedHeader,
	fromBER: asn1js.fromBER,
	getEmbeddedJwk: getEmbeddedJwk,
	getHostname: getHostname,
	hashDigest: hashDigest,
	importJWK: jose.importJWK,
	jwtVerify: jose.jwtVerify,
	pkijs: pkijs,
	randomValues: randomValues,
	verifySignature: verifySignature,
	get webcrypto () { return webcrypto; }
});

function ab2str(buf) {
	let str = "";
	new Uint8Array(buf).forEach((ch) => {
		str += String.fromCharCode(ch);
	});
	return str;
}

function isBase64Url(str) {
	return !!str.match(/^[A-Za-z0-9\-_]+={0,2}$/);
}

function isPem(pem) {
	if (typeof pem !== "string") {
		return false;
	}

	const pemRegex = /^-----BEGIN .+-----$\n([A-Za-z0-9+/=]|\n)*^-----END .+-----$/m;
	return !!pem.match(pemRegex);
}

function isPositiveInteger(n) {
	return n >>> 0 === parseFloat(n);
}

function abToBuf$1(ab) {
	return new Uint8Array(ab).buffer;
}

function abToInt(ab) {
	if (!(ab instanceof ArrayBuffer)) {
		throw new Error("abToInt: expected ArrayBuffer");
	}

	const buf = new Uint8Array(ab);
	let cnt = ab.byteLength - 1;
	let ret = 0;
	buf.forEach((byte) => {
		ret |= byte << (cnt * 8);
		cnt--;
	});

	return ret;
}

function abToPem(type, ab) {
	if (typeof type !== "string") {
		throw new Error(
			"abToPem expected 'type' to be string like 'CERTIFICATE', got: " +
				type,
		);
	}

	const str = coerceToBase64(ab, "pem buffer");

	return [
		`-----BEGIN ${type}-----\n`,
		...str.match(/.{1,64}/g).map((s) => s + "\n"),
		`-----END ${type}-----\n`,
	].join("");
}

/**
 * Creates a new Uint8Array based on two different ArrayBuffers
 *
 * @private
 * @param {ArrayBuffers} buffer1 The first buffer.
 * @param {ArrayBuffers} buffer2 The second buffer.
 * @return {ArrayBuffers} The new ArrayBuffer created out of the two.
 */
const appendBuffer$1 = function(buffer1, buffer2) {
	const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
	tmp.set(new Uint8Array(buffer1), 0);
	tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
	return tmp.buffer;
};

function coerceToArrayBuffer$1(buf, name) {
	if (!name) {
		throw new TypeError("name not specified in coerceToArrayBuffer");
	}

	// Handle empty strings
	if (typeof buf === "string" && buf === "") {
		buf = new Uint8Array(0);

		// Handle base64url and base64 strings
	} else if (typeof buf === "string") {
		// base64 to base64url
		buf = buf.replace(/\+/g, "-").replace(/\//g, "_").replace("=", "");
		// base64 to Buffer
		buf = base64.toArrayBuffer(buf, true);
	}

	// Extract typed array from Array
	if (Array.isArray(buf)) {
		buf = new Uint8Array(buf);
	}

	// Extract ArrayBuffer from Node buffer
	if (typeof Buffer !== "undefined" && buf instanceof Buffer) {
		buf = new Uint8Array(buf);
		buf = buf.buffer;
	}

	// Extract arraybuffer from TypedArray
	if (buf instanceof Uint8Array) {
		buf = buf.slice(0, buf.byteLength, buf.buffer.byteOffset).buffer;
	}

	// error if none of the above worked
	if (!(buf instanceof ArrayBuffer)) {
		throw new TypeError(`could not coerce '${name}' to ArrayBuffer`);
	}

	return buf;
}

function coerceToBase64(thing, name) {
	if (!name) {
		throw new TypeError("name not specified in coerceToBase64");
	}

	if (typeof thing !== "string") {
		try {
			thing = base64.fromArrayBuffer(
				coerceToArrayBuffer$1(thing, name),
			);
		} catch (_err) {
			throw new Error(`could not coerce '${name}' to string`);
		}
	}

	return thing;
}

function str2ab(str) {
	const buf = new ArrayBuffer(str.length);
	const bufView = new Uint8Array(buf);
	for (let i = 0, strLen = str.length; i < strLen; i++) {
		bufView[i] = str.charCodeAt(i);
	}
	return buf;
}

function coerceToBase64Url(thing, name) {
	if (!name) {
		throw new TypeError("name not specified in coerceToBase64");
	}

	if (typeof thing === "string") {
		// Convert from base64 to base64url
		thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/={0,2}$/g, "");
	}

	if (typeof thing !== "string") {
		try {
			thing = base64.fromArrayBuffer(
				coerceToArrayBuffer$1(thing, name),
				true,
			);
		} catch (_err) {
			throw new Error(`could not coerce '${name}' to string`);
		}
	}

	return thing;
}

// Merged with previous arrayBufferEquals
function arrayBufferEquals(b1, b2) {
	if (
		!(b1 instanceof ArrayBuffer) ||
		!(b2 instanceof ArrayBuffer)
	) {
		return false;
	}

	if (b1.byteLength !== b2.byteLength) {
		return false;
	}
	b1 = new Uint8Array(b1);
	b2 = new Uint8Array(b2);
	for (let i = 0; i < b1.byteLength; i++) {
		if (b1[i] !== b2[i]) return false;
	}
	return true;
}

function abToHex(ab) {
	if (!(ab instanceof ArrayBuffer)) {
		throw new TypeError("Invalid argument passed to abToHex");
	}
	const result = Array.prototype.map.call(
		new Uint8Array(ab),
		(x) => ("00" + x.toString(16)).slice(-2),
	).join("");

	return result;
}

function b64ToJsObject(b64, desc) {
	return JSON.parse(ab2str(coerceToArrayBuffer$1(b64, desc)));
}

function jsObjectToB64(obj) {
	return base64.fromString(
		JSON.stringify(obj).replace(/[\u{0080}-\u{FFFF}]/gu, ""),
	);
}

function pemToBase64(pem) {
	
	// Clean up base64 string
	if (typeof pem === "string" || pem instanceof String) {
		pem = pem.replace(/\r/g, "");
	}
	
	if (!isPem(pem)) {
		throw new Error("expected PEM string as input");
	}

	// Remove trailing \n
	pem = pem.replace(/\n$/, "");

	// Split on \n
	let pemArr = pem.split("\n");

	// remove first and last lines
	pemArr = pemArr.slice(1, pemArr.length - 1);
	return pemArr.join("");
}

var utils = /*#__PURE__*/Object.freeze({
	__proto__: null,
	ab2str: ab2str,
	abToBuf: abToBuf$1,
	abToHex: abToHex,
	abToInt: abToInt,
	abToPem: abToPem,
	appendBuffer: appendBuffer$1,
	arrayBufferEquals: arrayBufferEquals,
	b64ToJsObject: b64ToJsObject,
	coerceToArrayBuffer: coerceToArrayBuffer$1,
	coerceToBase64: coerceToBase64,
	coerceToBase64Url: coerceToBase64Url,
	isBase64Url: isBase64Url,
	isPem: isPem,
	isPositiveInteger: isPositiveInteger,
	jsObjectToB64: jsObjectToB64,
	pemToBase64: pemToBase64,
	str2ab: str2ab,
	tools: toolbox
});

// deno-lint-ignore-file


async function validateExpectations() {
	/* eslint complexity: ["off"] */
	let req = this.requiredExpectations;
	let opt = this.optionalExpectations;
	let exp = this.expectations;

	if (!(exp instanceof Map)) {
		throw new Error("expectations should be of type Map");
	}

	if (Array.isArray(req)) {
		req = new Set([req]);
	}

	if (!(req instanceof Set)) {
		throw new Error("requiredExpectaions should be of type Set");
	}

	if (Array.isArray(opt)) {
		opt = new Set([opt]);
	}

	if (!(opt instanceof Set)) {
		throw new Error("optionalExpectations should be of type Set");
	}

	for (let field of req) {
		if (!exp.has(field)) {
			throw new Error(`expectation did not contain value for '${field}'`);
		}
	}

	let optCount = 0;
	for (const [field] of exp) {
		if (opt.has(field)) {
			optCount++;
		}
	}

	if (req.size !== exp.size - optCount) {
		throw new Error(
			`wrong number of expectations: should have ${req.size} but got ${exp.size - optCount}`,
		);
	}

	// origin - isValid
	if (req.has("origin")) {
		let expectedOrigin = exp.get("origin");

		checkOrigin(expectedOrigin);
	}

	// rpId - optional, isValid
	if (exp.has("rpId")) {
		let expectedRpId = exp.get("rpId");

		checkRpId(expectedRpId);
	}

	// challenge - is valid base64url string
	if (exp.has("challenge")) {
		let challenge = exp.get("challenge");
		if (typeof challenge !== "string") {
			throw new Error("expected challenge should be of type String, got: " + typeof challenge);
		}

		if (!isBase64Url(challenge)) {
			throw new Error("expected challenge should be properly encoded base64url String");
		}
	}

	// flags - is Array or Set
	if (req.has("flags")) {
		let validFlags = new Set(["UP", "UV", "UP-or-UV", "AT", "ED"]);
		let flags = exp.get("flags");

		for (let flag of flags) {
			if (!validFlags.has(flag)) {
				throw new Error(`expected flag unknown: ${flag}`);
			}
		}
	}

	// prevCounter
	if (req.has("prevCounter")) {
		let prevCounter = exp.get("prevCounter");

		if (!isPositiveInteger(prevCounter)) {
			throw new Error("expected counter to be positive integer");
		}
	}

	// publicKey
	if (req.has("publicKey")) {
		let publicKey = exp.get("publicKey");
		if (!isPem(publicKey)) {
			throw new Error("expected publicKey to be in PEM format");
		}
	}

	// userHandle
	if (req.has("userHandle")) {
		let userHandle = exp.get("userHandle");
		if (userHandle !== null &&
			typeof userHandle !== "string") {
			throw new Error("expected userHandle to be null or string");
		}
	}


	// allowCredentials
	if (exp.has("allowCredentials")) {
		let allowCredentials = exp.get("allowCredentials");
		if (allowCredentials != null) {
			if (!Array.isArray(allowCredentials)) {
				throw new Error("expected allowCredentials to be null or array");
			} else {
				allowCredentials.forEach((allowCredential, index) => {
					if (typeof allowCredential.id === "string") {
						allowCredential.id = coerceToArrayBuffer$1(allowCredential.id, "allowCredentials[" + index + "].id");
					}
					if (allowCredential.id == null || !(allowCredential.id instanceof ArrayBuffer)) {
						throw new Error("expected id of allowCredentials[" + index + "] to be ArrayBuffer");
					}
					if (allowCredential.type == null || allowCredential.type !== "public-key") {
						throw new Error("expected type of allowCredentials[" + index + "] to be string with value 'public-key'");
					}
					if (allowCredential.transports != null && !Array.isArray(allowCredential.transports)) {
						throw new Error("expected transports of allowCredentials[" + index + "] to be array or null");
					} else if (allowCredential.transports != null && !allowCredential.transports.every(el => ["usb", "nfc", "ble", "cable", "internal"].includes(el))) {
						throw new Error("expected transports of allowCredentials[" + index + "] to be string with value 'usb', 'nfc', 'ble', 'cable', 'internal' or null");
					}
				});
			}
		}

	}

	this.audit.validExpectations = true;

	return true;
}

function validateCreateRequest() {
	let req = this.request;

	if (typeof req !== "object") {
		throw new TypeError("expected request to be Object, got " + typeof req);
	}

	if (!(req.rawId instanceof ArrayBuffer) &&
		!(req.id instanceof ArrayBuffer)) {
		throw new TypeError("expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId " + typeof req.rawId + " and id " + typeof req.id);
	}

	if (typeof req.response !== "object") {
		throw new TypeError("expected 'response' field of request to be Object, got " + typeof req.response);
	}

	if (typeof req.response.attestationObject !== "string" &&
		!(req.response.attestationObject instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.attestationObject' to be base64 String or ArrayBuffer");
	}

	if (typeof req.response.clientDataJSON !== "string" &&
		!(req.response.clientDataJSON instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
	}

	this.audit.validRequest = true;

	return true;
}

function validateAssertionResponse() {
	let req = this.request;

	if (typeof req !== "object") {
		throw new TypeError("expected request to be Object, got " + typeof req);
	}

	if (!(req.rawId instanceof ArrayBuffer) &&
		!(req.id instanceof ArrayBuffer)) {
		throw new TypeError("expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId " + typeof req.rawId + " and id " + typeof req.id);
	}

	if (typeof req.response !== "object") {
		throw new TypeError("expected 'response' field of request to be Object, got " + typeof req.response);
	}

	if (typeof req.response.clientDataJSON !== "string" &&
		!(req.response.clientDataJSON instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
	}

	if (typeof req.response.authenticatorData !== "string" &&
		!(req.response.authenticatorData instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.authenticatorData' to be base64 String or ArrayBuffer");
	}

	if (typeof req.response.signature !== "string" &&
		!(req.response.signature instanceof ArrayBuffer)) {
		throw new TypeError("expected 'response.signature' to be base64 String or ArrayBuffer");
	}

	if (typeof req.response.userHandle !== "string" &&
		!(req.response.userHandle instanceof ArrayBuffer) &&
		req.response.userHandle !== undefined && req.response.userHandle !== null) {
		throw new TypeError("expected 'response.userHandle' to be base64 String, ArrayBuffer, or undefined");
	}

	this.audit.validRequest = true;

	return true;
}

async function validateRawClientDataJson() {
	// XXX: this isn't very useful, since this has already been parsed...
	let rawClientDataJson = this.clientData.get("rawClientDataJson");

	if (!(rawClientDataJson instanceof ArrayBuffer)) {
		throw new Error("clientData clientDataJson should be ArrayBuffer");
	}

	this.audit.journal.add("rawClientDataJson");

	return true;
}

async function validateTransports() {
	let transports = this.authnrData.get("transports");

	if (transports != null && !Array.isArray(transports)) {
		throw new Error("expected transports to be 'null' or 'array<string>'");
	}

	for (const index in transports) {
		if (typeof transports[index] !== "string") {
			throw new Error("expected transports[" + index + "] to be 'string'");
		}
	}

	this.audit.journal.add("transports");

	return true;
}

async function validateId() {
	let rawId = this.clientData.get("rawId");

	if (!(rawId instanceof ArrayBuffer)) {
		throw new Error("expected id to be of type ArrayBuffer");
	}

	let credId = this.authnrData.get("credId");
	if (credId !== undefined && !arrayBufferEquals(rawId, credId)) {
		throw new Error("id and credId were not the same");
	}

	let allowCredentials = this.expectations.get("allowCredentials");

	if (allowCredentials != undefined) {
		if (!allowCredentials.some((cred) => {
			let result = arrayBufferEquals(rawId, cred.id);
			return result;
		})) {
			throw new Error("Credential ID does not match any value in allowCredentials");
		}
	}

	this.audit.journal.add("rawId");

	return true;
}


async function validateOrigin() {
	let expectedOrigin = this.expectations.get("origin");
	let clientDataOrigin = this.clientData.get("origin");

	let origin = checkOrigin(clientDataOrigin);

	if (origin !== expectedOrigin) {
		throw new Error("clientData origin did not match expected origin");
	}

	this.audit.journal.add("origin");

	return true;
}

async function validateCreateType() {
	let type = this.clientData.get("type");

	if (type !== "webauthn.create") {
		throw new Error("clientData type should be 'webauthn.create', got: " + type);
	}

	this.audit.journal.add("type");

	return true;
}

async function validateGetType() {
	let type = this.clientData.get("type");

	if (type !== "webauthn.get") {
		throw new Error("clientData type should be 'webauthn.get'");
	}

	this.audit.journal.add("type");

	return true;
}

async function validateChallenge() {
	let expectedChallenge = this.expectations.get("challenge");
	let challenge = this.clientData.get("challenge");

	if (typeof challenge !== "string") {
		throw new Error("clientData challenge was not a string");
	}

	if (!isBase64Url(challenge)) {
		throw new TypeError("clientData challenge was not properly encoded base64url");
	}

	challenge = challenge.replace(/={1,2}$/, "");

	// console.log("challenge", challenge);
	// console.log("expectedChallenge", expectedChallenge);
	if (challenge !== expectedChallenge) {
		throw new Error("clientData challenge mismatch");
	}

	this.audit.journal.add("challenge");

	return true;
}

async function validateTokenBinding() {
	// TODO: node.js can't support token binding right now :(
	let tokenBinding = this.clientData.get("tokenBinding");

	if (typeof tokenBinding === "object") {
		if (tokenBinding.status !== "not-supported" &&
			tokenBinding.status !== "supported") {
			throw new Error("tokenBinding status should be 'not-supported' or 'supported', got: " + tokenBinding.status);
		}

		if (Object.keys(tokenBinding).length != 1) {
			throw new Error("tokenBinding had too many keys");
		}
	} else if (tokenBinding !== undefined) {
		throw new Error("Token binding field malformed: " + tokenBinding);
	}

	// TODO: add audit.info for token binding status so that it can be used for policies, risk, etc.
	this.audit.journal.add("tokenBinding");

	return true;
}

async function validateRawAuthnrData() {
	// XXX: this isn't very useful, since this has already been parsed...
	let rawAuthnrData = this.authnrData.get("rawAuthnrData");
	if (!(rawAuthnrData instanceof ArrayBuffer)) {
		throw new Error("authnrData rawAuthnrData should be ArrayBuffer");
	}

	this.audit.journal.add("rawAuthnrData");

	return true;
}


async function validateAttestation() {
	return Fido2Lib.validateAttestation.call(this);
}

async function validateAssertionSignature() {
	let expectedSignature = this.authnrData.get("sig");
	let publicKey = this.expectations.get("publicKey");
	let rawAuthnrData = this.authnrData.get("rawAuthnrData");
	let rawClientData = this.clientData.get("rawClientDataJson");

	// console.log("publicKey", publicKey);
	// printHex("expectedSignature", expectedSignature);
	// printHex("rawAuthnrData", rawAuthnrData);
	// printHex("rawClientData", rawClientData);


	let clientDataHashBuf = await hashDigest(rawClientData);
	let clientDataHash = new Uint8Array(clientDataHashBuf).buffer;

	let res = await verifySignature(
		publicKey,
		expectedSignature,
		appendBuffer$1(rawAuthnrData, clientDataHash),
		"SHA-256",
	);
	if (!res) {
		throw new Error("signature validation failed");
	}

	this.audit.journal.add("sig");

	return true;
}

async function validateRpIdHash() {
	let rpIdHash = this.authnrData.get("rpIdHash");

	if (typeof Buffer !== "undefined" && rpIdHash instanceof Buffer) {
		rpIdHash = new Uint8Array(rpIdHash).buffer;
	}

	if (!(rpIdHash instanceof ArrayBuffer)) {
		throw new Error("couldn't coerce clientData rpIdHash to ArrayBuffer");
	}

	let domain = this.expectations.has("rpId") ? this.expectations.get("rpId") : getHostname(this.expectations.get("origin"));

	let createdHash = new Uint8Array(await hashDigest(domain)).buffer;

	// wouldn't it be weird if two SHA256 hashes were different lengths...?
	if (rpIdHash.byteLength !== createdHash.byteLength) {
		throw new Error("authnrData rpIdHash length mismatch");
	}

	rpIdHash = new Uint8Array(rpIdHash);
	createdHash = new Uint8Array(createdHash);
	for (let i = 0; i < rpIdHash.byteLength; i++) {
		if (rpIdHash[i] !== createdHash[i]) {
			throw new TypeError("authnrData rpIdHash mismatch");
		}
	}

	this.audit.journal.add("rpIdHash");

	return true;
}

async function validateFlags() {
	let expectedFlags = this.expectations.get("flags");
	let flags = this.authnrData.get("flags");

	for (let expFlag of expectedFlags) {
		if (expFlag === "UP-or-UV") {
			if (flags.has("UV")) {
				if (flags.has("UP")) {
					continue;
				} else {
					throw new Error("expected User Presence (UP) flag to be set if User Verification (UV) is set");
				}
			} else if (flags.has("UP")) {
				continue;
			} else {
				throw new Error("expected User Presence (UP) or User Verification (UV) flag to be set and neither was");
			}
		}

		if (expFlag === "UV") {
			if (flags.has("UV")) {
				if (flags.has("UP")) {
					continue;
				} else {
					throw new Error("expected User Presence (UP) flag to be set if User Verification (UV) is set");
				}
			} else {
				throw new Error(`expected flag was not set: ${expFlag}`);
			}
		}

		if (!flags.has(expFlag)) {
			throw new Error(`expected flag was not set: ${expFlag}`);
		}
	}

	this.audit.journal.add("flags");

	return true;
}

async function validateInitialCounter() {
	let counter = this.authnrData.get("counter");

	// TODO: does counter need to be zero initially? probably not... I guess..
	if (typeof counter !== "number") {
		throw new Error("authnrData counter wasn't a number");
	}

	this.audit.journal.add("counter");

	return true;
}

async function validateAaguid() {
	let aaguid = this.authnrData.get("aaguid");

	if (!(aaguid instanceof ArrayBuffer)) {
		throw new Error("authnrData AAGUID is not ArrayBuffer");
	}

	if (aaguid.byteLength !== 16) {
		throw new Error("authnrData AAGUID was wrong length");
	}

	this.audit.journal.add("aaguid");

	return true;
}

async function validateCredId() {
	let credId = this.authnrData.get("credId");
	let credIdLen = this.authnrData.get("credIdLen");

	if (!(credId instanceof ArrayBuffer)) {
		throw new Error("authnrData credId should be ArrayBuffer");
	}

	if (typeof credIdLen !== "number") {
		throw new Error("authnrData credIdLen should be number, got " + typeof credIdLen);
	}

	if (credId.byteLength !== credIdLen) {
		throw new Error("authnrData credId was wrong length");
	}

	this.audit.journal.add("credId");
	this.audit.journal.add("credIdLen");

	return true;
}

async function validatePublicKey() {
	// XXX: the parser has already turned this into PEM at this point
	// if something were malformatted or wrong, we probably would have
	// thrown an error well before this.
	// Maybe we parse the ASN.1 and make sure attributes are correct?
	// Doesn't seem very worthwhile...

	let cbor = this.authnrData.get("credentialPublicKeyCose");
	let jwk = this.authnrData.get("credentialPublicKeyJwk");
	let pem = this.authnrData.get("credentialPublicKeyPem");

	// cbor
	if (!(cbor instanceof ArrayBuffer)) {
		throw new Error("authnrData credentialPublicKeyCose isn't of type ArrayBuffer");
	}
	this.audit.journal.add("credentialPublicKeyCose");

	// jwk
	if (typeof jwk !== "object") {
		throw new Error("authnrData credentialPublicKeyJwk isn't of type Object");
	}

	if (typeof jwk.kty !== "string") {
		throw new Error("authnrData credentialPublicKeyJwk.kty isn't of type String");
	}

	if (typeof jwk.alg !== "string") {
		throw new Error("authnrData credentialPublicKeyJwk.alg isn't of type String");
	}

	switch (jwk.kty) {
		case "EC":
			if (typeof jwk.crv !== "string") {
				throw new Error("authnrData credentialPublicKeyJwk.crv isn't of type String");
			}
			break;
		case "RSA":
			if (typeof jwk.n !== "string") {
				throw new Error("authnrData credentialPublicKeyJwk.n isn't of type String");

			}

			if (typeof jwk.e !== "string") {
				throw new Error("authnrData credentialPublicKeyJwk.e isn't of type String");
			}
			break;
		default:
			throw new Error("authnrData unknown JWK key type: " + jwk.kty);
	}

	this.audit.journal.add("credentialPublicKeyJwk");

	// pem
	if (typeof pem !== "string") {
		throw new Error("authnrData credentialPublicKeyPem isn't of type String");
	}

	if (!isPem(pem)) {
		throw new Error("authnrData credentialPublicKeyPem was malformatted");
	}
	this.audit.journal.add("credentialPublicKeyPem");

	return true;
}

function validateExtensions() {
	const extensions = this.authnrData.get("webAuthnExtensions");
	const shouldHaveExtensions = this.authnrData.get("flags").has("ED");

	if (shouldHaveExtensions) {
		if (Array.isArray(extensions) && 
			extensions.every(item => typeof item === "object")
		) {
			this.audit.journal.add("webAuthnExtensions");
		} else {
			throw new Error("webAuthnExtensions aren't valid");
		}
	} else {
		if (extensions !== undefined) {
			throw new Error("unexpected webAuthnExtensions found");
		}
	}

	return true;
}

async function validateUserHandle() {
	let userHandle = this.authnrData.get("userHandle");

	if (userHandle === undefined ||
		userHandle === null ||
		userHandle === "") {
		this.audit.journal.add("userHandle");
		return true;
	}

	userHandle = coerceToBase64Url(userHandle, "userHandle");
	let expUserHandle = this.expectations.get("userHandle");
	if (typeof userHandle === "string" &&
		userHandle === expUserHandle) {
		this.audit.journal.add("userHandle");
		return true;
	}

	throw new Error("unable to validate userHandle");
}

async function validateCounter() {
	let prevCounter = this.expectations.get("prevCounter");
	let counter = this.authnrData.get("counter");
	let counterSupported = !(counter === 0 && prevCounter === 0);

	if (counter <= prevCounter && counterSupported) {
		throw new Error("counter rollback detected");
	}

	this.audit.journal.add("counter");
	this.audit.info.set("counter-supported", "" + counterSupported);

	return true;
}

async function validateAudit() {
	let journal = this.audit.journal;
	let clientData = this.clientData;
	let authnrData = this.authnrData;

	for (let kv of clientData) {
		let val = kv[0];
		if (!journal.has(val)) {
			throw new Error(`internal audit failed: ${val} was not validated`);
		}
	}

	for (let kv of authnrData) {
		let val = kv[0];
		if (!journal.has(val)) {
			throw new Error(`internal audit failed: ${val} was not validated`);
		}
	}

	if (journal.size !== (clientData.size + authnrData.size)) {
		throw new Error(`internal audit failed: ${journal.size} fields checked; expected ${clientData.size + authnrData.size}`);
	}

	if (!this.audit.validExpectations) {
		throw new Error("internal audit failed: expectations not validated");
	}

	if (!this.audit.validRequest) {
		throw new Error("internal audit failed: request not validated");
	}

	this.audit.complete = true;

	return true;
}

function attach(o) {
	let mixins = {
		validateExpectations,
		validateCreateRequest,
		// clientData validators
		validateRawClientDataJson,
		validateOrigin,
		validateId,
		validateCreateType,
		validateGetType,
		validateChallenge,
		validateTokenBinding,
		validateTransports,
		// authnrData validators
		validateRawAuthnrData,
		validateAttestation,
		validateAssertionSignature,
		validateRpIdHash,
		validateAaguid,
		validateCredId,
		validatePublicKey,
		validateExtensions,
		validateFlags,
		validateUserHandle,
		validateCounter,
		validateInitialCounter,
		validateAssertionResponse,
		// audit structures
		audit: {
			validExpectations: false,
			validRequest: false,
			complete: false,
			journal: new Set(),
			warning: new Map(),
			info: new Map(),
		},
		validateAudit,
	};

	for (let key of Object.keys(mixins)) {
		o[key] = mixins[key];
	}
}

// NOTE: throws if origin is https and has port 443
// use `new URL(originstr).origin` to create a properly formatted origin
function parseExpectations(exp) {
	if (typeof exp !== "object") {
		throw new TypeError(
			"expected 'expectations' to be of type object, got " + typeof exp,
		);
	}

	const ret = new Map();

	// origin
	if (exp.origin) {
		if (typeof exp.origin !== "string") {
			throw new TypeError(
				"expected 'origin' should be string, got " + typeof exp.origin,
			);
		}

		const origin = checkOrigin(exp.origin);
		ret.set("origin", origin);
	}

	// rpId
	if (exp.rpId) {
		if (typeof exp.rpId !== "string") {
			throw new TypeError(
				"expected 'rpId' should be string, got " + typeof exp.rpId,
			);
		}

		const rpId = checkRpId(exp.rpId);
		ret.set("rpId", rpId);
	}

	// challenge
	if (exp.challenge) {
		let challenge = exp.challenge;
		challenge = coerceToBase64Url(challenge, "expected challenge");
		ret.set("challenge", challenge);
	}

	// flags
	if (exp.flags) {
		let flags = exp.flags;

		if (Array.isArray(flags)) {
			flags = new Set(flags);
		}

		if (!(flags instanceof Set)) {
			throw new TypeError(
				"expected flags to be an Array or a Set, got: " + typeof flags,
			);
		}

		ret.set("flags", flags);
	}

	// counter
	if (exp.prevCounter !== undefined) {
		if (typeof exp.prevCounter !== "number") {
			throw new TypeError(
				"expected 'prevCounter' should be Number, got " +
					typeof exp.prevCounter,
			);
		}

		ret.set("prevCounter", exp.prevCounter);
	}

	// publicKey
	if (exp.publicKey) {
		if (typeof exp.publicKey !== "string") {
			throw new TypeError(
				"expected 'publicKey' should be String, got " +
					typeof exp.publicKey,
			);
		}

		ret.set("publicKey", exp.publicKey);
	}

	// userHandle
	if (exp.userHandle !== undefined) {
		let userHandle = exp.userHandle;
		if (userHandle !== null && userHandle !== "") {
			userHandle = coerceToBase64Url(userHandle, "userHandle");
		}
		ret.set("userHandle", userHandle);
	}

	// allowCredentials
	if (exp.allowCredentials !== undefined) {
		const allowCredentials = exp.allowCredentials;

		if (allowCredentials !== null && !Array.isArray(allowCredentials)) {
			throw new TypeError(
				"expected 'allowCredentials' to be null or array, got " +
					typeof allowCredentials,
			);
		}

		for (const index in allowCredentials) {
			if (allowCredentials[index].id != null) {
				allowCredentials[index].id = coerceToArrayBuffer$1(
					allowCredentials[index].id,
					"allowCredentials[" + index + "].id",
				);
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
	const rawId = coerceToArrayBuffer$1(msg.rawId, "rawId");

	if (typeof msg.response !== "object") {
		throw new TypeError("expected response to be Object");
	}

	const clientDataJSON = coerceToArrayBuffer$1(
		msg.response.clientDataJSON,
		"clientDataJSON",
	);
	if (!(clientDataJSON instanceof ArrayBuffer)) {
		throw new TypeError("expected 'clientDataJSON' to be ArrayBuffer");
	}

	// convert to string
	const clientDataJson = ab2str(clientDataJSON);

	// parse JSON string
	let parsed;
	try {
		parsed = JSON.parse(clientDataJson);
	} catch (err) {
		throw new Error("couldn't parse clientDataJson: " + err);
	}

	const ret = new Map([
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
async function parseAttestationObject(attestationObject) {
	// update docs to say ArrayBuffer-ish object
	attestationObject = coerceToArrayBuffer$1(
		attestationObject,
		"attestationObject",
	);

	// parse attestation
	let parsed;
	try {
		parsed = cborX__namespace.decode(new Uint8Array(attestationObject));
	} catch (_err) {
		throw new TypeError("couldn't parse attestationObject CBOR");
	}

	if (typeof parsed !== "object") {
		throw new TypeError("invalid parsing of attestationObject cbor");
	}

	if (typeof parsed.fmt !== "string") {
		throw new Error("expected attestation CBOR to contain a 'fmt' string");
	}

	if (typeof parsed.attStmt !== "object") {
		throw new Error(
			"expected attestation CBOR to contain a 'attStmt' object",
		);
	}

	if (!(parsed.authData instanceof Uint8Array)) {
		throw new Error(
			"expected attestation CBOR to contain a 'authData' byte sequence",
		);
	}

	const ret = new Map([
		...Fido2Lib.parseAttestation(parsed.fmt, parsed.attStmt),
		// return raw buffer for future signature verification
		["rawAuthnrData", coerceToArrayBuffer$1(parsed.authData, "authData")],
		// Added for compatibility with parseAuthnrAttestationResponse
		["transports", undefined],
		// parse authData
		...await parseAuthenticatorData(parsed.authData),
	]);

	return ret;
}

async function parseAuthnrAttestationResponse(msg) {
	if (typeof msg !== "object") {
		throw new TypeError("expected msg to be Object");
	}

	if (typeof msg.response !== "object") {
		throw new TypeError("expected response to be Object");
	}

	let attestationObject = msg.response.attestationObject;

	// update docs to say ArrayBuffer-ish object
	attestationObject = coerceToArrayBuffer$1(
		attestationObject,
		"attestationObject",
	);

	let parsed;
	try {
		parsed = cborX__namespace.decode(new Uint8Array(attestationObject));
	} catch (_err) {
		throw new TypeError("couldn't parse attestationObject CBOR");
	}

	if (typeof parsed !== "object") {
		throw new TypeError("invalid parsing of attestationObject CBOR");
	}

	if (typeof parsed.fmt !== "string") {
		throw new Error("expected attestation CBOR to contain a 'fmt' string");
	}

	if (typeof parsed.attStmt !== "object") {
		throw new Error("expected attestation CBOR to contain a 'attStmt' object");
	}

	if (!(parsed.authData instanceof Uint8Array)) {
		throw new Error("expected attestation CBOR to contain a 'authData' byte sequence");
	}

	if (msg.transports != undefined && !Array.isArray(msg.transports)) {
		throw new Error("expected transports to be 'null' or 'array<string>'");
	}

	// have to require here to prevent circular dependency
	const ret = new Map([
		...Fido2Lib.parseAttestation(parsed.fmt, parsed.attStmt),
		// return raw buffer for future signature verification
		["rawAuthnrData", coerceToArrayBuffer$1(parsed.authData, "authData")],
		["transports", msg.transports],
		// parse authData
		...await parseAuthenticatorData(parsed.authData),
	]);

	return ret;
}

async function parseAuthenticatorData(authnrDataArrayBuffer) {
	// convert to ArrayBuffer
	authnrDataArrayBuffer = coerceToArrayBuffer$1(authnrDataArrayBuffer, "authnrDataArrayBuffer");

	const ret = new Map();

	// console.log("authnrDataArrayBuffer", authnrDataArrayBuffer);
	// console.log("typeof authnrDataArrayBuffer", typeof authnrDataArrayBuffer);
	// printHex("authnrDataArrayBuffer", authnrDataArrayBuffer);

	const authnrDataBuf = new DataView(authnrDataArrayBuffer);
	let offset = 0;
	ret.set("rpIdHash", authnrDataBuf.buffer.slice(offset, offset + 32));
	offset += 32;
	const flags = authnrDataBuf.getUint8(offset);
	const flagsSet = new Set();
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
	const attestation = flagsSet.has("AT");
	const extensions = flagsSet.has("ED");

	if (attestation) {
		ret.set("aaguid", authnrDataBuf.buffer.slice(offset, offset + 16));
		offset += 16;
		const credIdLen = authnrDataBuf.getUint16(offset, false);
		ret.set("credIdLen", credIdLen);
		offset += 2;
		ret.set(
			"credId",
			authnrDataBuf.buffer.slice(offset, offset + credIdLen),
		);
		offset += credIdLen;

		// Import public key
		const publicKey = new PublicKey();
		await publicKey.fromCose(
			authnrDataBuf.buffer.slice(offset, authnrDataBuf.buffer.byteLength),
		);

		// TODO: does not only contain the COSE if the buffer contains extensions
		ret.set("credentialPublicKeyCose", await publicKey.toCose());
		ret.set("credentialPublicKeyJwk", await publicKey.toJwk());
		ret.set("credentialPublicKeyPem", await publicKey.toPem());
	}

	if (extensions) {
		const cborObjects = cborX__namespace.decodeMultiple(new Uint8Array(authnrDataBuf.buffer.slice(offset, authnrDataBuf.buffer.byteLength)));

		// skip publicKey if present
		if (attestation) {
			cborObjects.shift();
		}

		if (cborObjects.length === 0) {
			throw new Error("extensions missing");
		}

		ret.set("webAuthnExtensions", cborObjects);
	}

	return ret;
}

async function parseAuthnrAssertionResponse(msg) {
	if (typeof msg !== "object") {
		throw new TypeError("expected msg to be Object");
	}

	if (typeof msg.response !== "object") {
		throw new TypeError("expected response to be Object");
	}

	let userHandle;
	if (msg.response.userHandle !== undefined && msg.response.userHandle !== null) {
		userHandle = coerceToArrayBuffer$1(msg.response.userHandle, "response.userHandle");
		if (userHandle.byteLength === 0) {
			userHandle = undefined;
		}
	}

	const sigAb = coerceToArrayBuffer$1(msg.response.signature, "response.signature");
	const ret = new Map([
		["sig", sigAb],
		["userHandle", userHandle],
		["rawAuthnrData", coerceToArrayBuffer$1(msg.response.authenticatorData, "response.authenticatorData")],
		...await parseAuthenticatorData(msg.response.authenticatorData),
	]);

	return ret;
}

const lockSym = Symbol();

/**
 * The base class of {@link Fido2AttestationResult} and {@link Fido2AssertionResult}
 * @property {Map} authnrData Authenticator data that was parsed and validated
 * @property {Map} clientData Client data that was parsed and validated
 * @property {Map} expectations The expectations that were used to validate the result
 * @property {Object} request The request that was validated
 * @property {Map} audit A collection of audit information, such as useful warnings and information. May be useful for risk engines or for debugging.
 * @property {Boolean} audit.validExpectations Whether the expectations that were provided were complete and valid
 * @property {Boolean} audit.validRequest Whether the request message was complete and valid
 * @property {Boolean} audit.complete Whether all fields in the result have been validated
 * @property {Set} audit.journal A list of the fields that were validated
 * @property {Map} audit.warning A set of warnings that were generated while validating the result
 * @property {Map} audit.info A set of informational fields that were generated while validating the result. Includes any x509 extensions of the attestation certificate during registration, and whether the key supports a rollback counter during authentication.
 */
class Fido2Result {
	constructor(sym) {
		if (sym !== lockSym) {
			throw new Error("Do not create with 'new' operator. Call 'Fido2AttestationResult.create()' or 'Fido2AssertionResult.create()' instead.");
		}

		attach(this);
	}

	parse() {
		// TODO: id
		this.clientData = parseClientResponse(this.request);
	}

	async validate() {
		// clientData, except type
		await this.validateRawClientDataJson();
		await this.validateOrigin();
		await this.validateChallenge();
		await this.validateTokenBinding();
		await this.validateId();

		// authenticatorData, minus attestation
		await this.validateRawAuthnrData();
		await this.validateRpIdHash();
		await this.validateFlags();
		await this.validateExtensions();
	}

	async create(req, exp) {
		if (typeof req !== "object") {
			throw new TypeError("expected 'request' to be object, got: " + typeof req);
		}

		if (typeof exp !== "object") {
			throw new TypeError("expected 'expectations' to be object, got: " + typeof exp);
		}

		this.expectations = parseExpectations(exp);
		this.request = req;

		// validate that input expectations and request are complete and in the right format
		await this.validateExpectations();

		// parse and validate all the request fields (CBOR, etc.)
		await this.parse();
		await this.validate();

		// ensure the parsing and validation went well
		await this.validateAudit();

		return this;
	}
}

/**
 * A validated attesetation result
 * @extends {Fido2Result}
 */
class Fido2AttestationResult extends Fido2Result {
	constructor(sym) {
		super(sym);

		this.requiredExpectations = new Set([
			"origin",
			"challenge",
			"flags",
		]);
		this.optionalExpectations = new Set([
			"rpId",
		]);
	}

	async parse() {
		this.validateCreateRequest();
		await super.parse();
		this.authnrData = await parseAuthnrAttestationResponse(this.request);
	}

	async validate() {
		await this.validateCreateType();
		await this.validateAaguid();
		await this.validatePublicKey();
		await super.validate();
		await this.validateAttestation();
		await this.validateInitialCounter();
		await this.validateCredId();
		await this.validateTransports();
	}

	static async create(req, exp) {
		return await (new Fido2AttestationResult(lockSym)).create(req, exp);
	}
}

/**
 * A validated assertion result
 * @extends {Fido2Result}
 */
class Fido2AssertionResult extends Fido2Result {
	constructor(sym) {
		super(sym);
		this.requiredExpectations = new Set([
			"origin",
			"challenge",
			"flags",
			"prevCounter",
			"publicKey",
			"userHandle",
		]);
		this.optionalExpectations = new Set([
			"rpId",
			"allowCredentials",
		]);
	}

	async parse() {
		this.validateAssertionResponse();
		await super.parse();
		this.authnrData = await parseAuthnrAssertionResponse(this.request);
	}

	async validate() {
		await this.validateGetType();
		await super.validate();
		await this.validateAssertionSignature();
		await this.validateUserHandle();
		await this.validateCounter();
	}

	static create(req, exp) {
		return new Fido2AssertionResult(lockSym).create(req, exp);
	}
}

const fidoMdsRootCert = "-----BEGIN CERTIFICATE-----\n" +
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
		for (const key of Object.keys(tocEntry)) {
			this[key] = tocEntry[key];
		}

		for (const key of Object.keys(mdsEntry)) {
			this[key] = mdsEntry[key];
		}

		if (this.metadataStatement) {
			delete this.metadataStatement;
		}

		// make fields more useable:

		// attachmentHint
		this.attachmentHint = this.attachmentHint instanceof Array ? this.attachmentHint : attachmentHintToArr(this.attachmentHint);
		function attachmentHintToArr(hint) {
			const ret = [];
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
		if (this.authenticationAlgorithms) {
			this.authenticationAlgorithm = this.authenticationAlgorithms[0];
		}

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
		if (this.attestationRootCertificates) {
			for (const certificate of this.attestationRootCertificates) {
				CertManager.addCert(certificate);
			}
		}

		// icon: TODO

		// keyProtection
		this.keyProtection = this.keyProtection instanceof Array ? this.keyProtection : keyProtToArr(this.keyProtection);
		function keyProtToArr(kp) {
			const ret = [];
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
			const ret = [];
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
			const ret = [];
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
			const ret = [];
			if (!Array.isArray(uvList)) throw new Error("expected userVerificationDetails to be an Array, got: " + uvList);
			uvList.forEach((uv) => {
				if (!Array.isArray(uv)) throw new Error("expected userVerification to be Array, got " + uv);
				const d = uv.map((desc) => {
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
					const newDesc = {};
					let descKey;

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

					if (descKey) for (const key of Object.keys(desc[descKey])) {
						newDesc[key] = desc[descKey][key];
					}

					return newDesc;
				});
				ret.push(d);
			});
			return ret;
		}

		function uvToArr(uv) {
			const ret = [];
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
		let parsedJws;
		try {
			// Read protected header
			const protectedHeader = await jose.decodeProtectedHeader(tocStr);
			const publicKey = await getEmbeddedJwk(protectedHeader);
			// Verify
			parsedJws = await jose.jwtVerify(
				tocStr,
				await jose.importJWK(publicKey),
			);

			// Store verified header and key
			parsedJws.header = protectedHeader;
			parsedJws.key = publicKey;

			this.toc = parsedJws.payload;
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
		let rootCerts;
		if (Array.isArray(rootCert)) rootCerts = rootCert;
		else rootCerts = [rootCert];

		// Extract cert chain from header
		const certHeader = parsedJws.header ? parsedJws.header : parsedJws.protectedHeader;

		await CertManager.verifyCertChain(certHeader.x5c, rootCerts, crls);

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

		let newEntry = b64ToJsObject(entryStr, "MDS entry");
		if (newEntry.metadataStatement) {
			newEntry = newEntry.metadataStatement;
			//Get the base64 string with all non-ASCII characters removed
			entryStr = jsObjectToB64(newEntry);
		}

		newEntry.raw = entryStr;
		const newEntryId = getMdsEntryId(newEntry);

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
	 * @returns {Promise} Returns a Promise
	 */
	async validate() {
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

		let mapEntry;
		for (mapEntry of this.unvalidatedEntryList) {
			const entry = mapEntry[1];
			// find matching TOC entry
			const entryId = getMdsEntryId(entry);
			let tocEntry = this.toc.entries.filter((te) => {
				const teId = getMdsEntryId(te);
				const eq = idEquals(teId, entryId);
				return eq;
			});

			if (tocEntry.length !== 1) {
				throw new Error(`found the wrong number of TOC entries for '${entryId}': ${tocEntry.length}`);
			}
			tocEntry = tocEntry[0];

			// validate hash
			const entryHash = await hashDigest(entry.raw);
			let tocEntryHash;
			if (tocEntry.hash) {
				tocEntryHash = tocEntry.hash;
			} else {
				tocEntryHash = await hashDigest(
					jsObjectToB64(tocEntry.metadataStatement),
				);
			}

			tocEntryHash = coerceToArrayBuffer$1(tocEntryHash, "MDS TOC entry hash");
			if (!(arrayBufferEquals(entryHash, tocEntryHash))) {
				throw new Error("MDS entry hash did not match corresponding hash in MDS TOC");
			}

			// validate status report
			// TODO: maybe setValidateEntryCallback(fn);

			// add new entry to collection entryList
			const newEntry = new MdsEntry(entry, tocEntry);
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
		}
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

		return this.entryList.get(id.replace(/-/g, "")) ||
			this.entryList.get(
				abToHex(base64.toArrayBuffer(id, true)).replace(/-/g, ""),
			) || null;
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
		const allSame = id1.reduce((acc, val) => acc && id2.includes(val), true);
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

/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

function noneParseFn(attStmt) {
	if (Object.keys(attStmt).length !== 0) {
		throw new Error("'none' attestation format: attStmt had fields");
	}

	return new Map();
}

function noneValidateFn() {
	this.audit.journal.add("fmt");

	return true;
}

const noneAttestation = {
	name: "none",
	parseFn: noneParseFn,
	validateFn: noneValidateFn,
};

const u2fRootCerts = [
	// Yubico Root Cert
	// https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
	"MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ\n" +
	"dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw\n" +
	"MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290\n" +
	"IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
	"AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk\n" +
	"5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep\n" +
	"8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw\n" +
	"nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT\n" +
	"9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw\n" +
	"LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ\n" +
	"hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN\n" +
	"BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4\n" +
	"MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt\n" +
	"hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k\n" +
	"LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U\n" +
	"sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc\n" +
	"U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==",
];

const algMap = new Map([
	[-7, {
		algName: "ECDSA_w_SHA256",
		hashAlg: "SHA-256",
	}],
	// [-8, {
	//     name: "EdDSA",
	//     hash: undefined
	// }],
	[-35, {
		algName: "ECDSA_w_SHA384",
		hashAlg: "SHA-384",
	}],
	[-36, {
		algName: "ECDSA_w_SHA512",
		hashAlg: "SHA-512",
	}],
	[-257, {
		algName: "RSASSA-PKCS1-v1_5_w_SHA256",
		hashAlg: "SHA-256",
	}],
]);

function packedParseFn(attStmt) {
	const ret = new Map();

	// alg
	const algEntry = algMap.get(attStmt.alg);
	if (algEntry === undefined) {
		throw new Error("packed attestation: unknown algorithm: " + attStmt.alg);
	}
	ret.set("alg", algEntry);

	// x5c
	const x5c = attStmt.x5c;
	const newX5c = [];
	if (Array.isArray(x5c)) {
		for (let cert of x5c) {
			cert = coerceToArrayBuffer$1(cert, "packed x5c cert");
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
		ecdaaKeyId = coerceToArrayBuffer$1(ecdaaKeyId, "ecdaaKeyId");
		ret.set("ecdaaKeyId", ecdaaKeyId);
	}

	// sig
	let sig = attStmt.sig;
	sig = coerceToArrayBuffer$1(sig, "packed signature");
	ret.set("sig", sig);

	return ret;
}

async function packedValidateFn() {
	const x5c = this.authnrData.get("x5c");
	const ecdaaKeyId = this.authnrData.get("ecdaaKeyId");

	if (x5c !== undefined && ecdaaKeyId !== undefined) {
		throw new Error("packed attestation: should be 'basic' or 'ecdaa', got both");
	}

	if (x5c) return await packedValidateBasic.call(this);
	if (ecdaaKeyId) return await packedValidateEcdaa.call(this);
	return await packedValidateSurrogate.call(this);
}

async function packedValidateBasic() {
	// see what algorithm we're working with
	const {
		algName,
		hashAlg,
	} = this.authnrData.get("alg");

	if (algName === undefined) {
		throw new Error("packed attestation: unknown algorithm " + algName);
	}

	// from: https://w3c.github.io/webauthn/#packed-attestation
	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in x5c with the algorithm specified in alg.
	const res = await validateSignature(
		this.clientData.get("rawClientDataJson"),
		this.authnrData.get("rawAuthnrData"),
		this.authnrData.get("sig"),
		hashAlg,
		this.authnrData.get("attCert"),
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

async function validateSignature(
	rawClientData,
	authenticatorData,
	sig,
	hashAlg,
	parsedAttCert,
) {
	// create clientDataHash
	const hash = await hashDigest(rawClientData);
	const clientDataHash = new Uint8Array(hash).buffer;

	// convert cert to PEM
	const attCertPem = abToPem("CERTIFICATE", parsedAttCert);

	// Get public key from cert
	const cert = new Certificate(attCertPem);
	const publicKey = await cert.getPublicKey();

	// verify signature
	const verify = await verifySignature(
		publicKey,
		sig,
		appendBuffer$1(authenticatorData, clientDataHash),
		hashAlg,
	);
	return verify;
}

async function validateCerts(parsedAttCert, aaguid, _x5c, audit) {
	// ToDo: Do something with x5c! Prefixed with _ to avoid linting errors for now

	// make sure our root certs are loaded
	if (CertManager.getCerts().size === 0) {
		u2fRootCerts.forEach((cert) => CertManager.addCert(cert));
	}

	// decode attestation cert
	const attCert = new Certificate(coerceToBase64(parsedAttCert, "parsedAttCert"));
	try {
		await attCert.verify();
	} catch (e) {
		const err = e;
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
	const exts = attCert.getExtensions();
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
	const subject = attCert.getSubject();
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
	const basicConstraints = exts.get("basic-constraints");
	if (basicConstraints.cA !== false) {
		throw new Error("packed attestation: basic constraints 'cA' must be 'false'");
	}

	// An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through authenticator metadata services
	// TODO: no example of this is available to test against

	// If x5c contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
	const certAaguid = exts.get("fido-aaguid");
	if (certAaguid !== undefined && !arrayBufferEquals(aaguid, certAaguid)) {
		throw new Error("packed attestation: authnrData AAGUID did not match AAGUID in attestation certificate");
	}
}

async function validateSelfSignature(rawClientData, authenticatorData, sig, hashAlg, publicKeyPem) {
	// create clientDataHash
	const clientDataHash = await hashDigest(rawClientData, hashAlg);

	// verify signature
	const verify = await verifySignature(
		publicKeyPem,
		sig,
		appendBuffer$1(authenticatorData, clientDataHash),
		hashAlg,
	);
	return verify;
}

async function packedValidateSurrogate() {
	// see what algorithm we're working with
	const {
		algName,
		hashAlg,
	} = this.authnrData.get("alg");

	if (algName === undefined) {
		throw new Error("packed attestation: unknown algorithm " + algName);
	}

	// from: https://w3c.github.io/webauthn/#packed-attestation
	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.

	const res = await validateSelfSignature(
		this.clientData.get("rawClientDataJson"),
		this.authnrData.get("rawAuthnrData"),
		this.authnrData.get("sig"),
		hashAlg,
		this.authnrData.get("credentialPublicKeyPem"),
	);
	if (!res || typeof res !== "boolean") {
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

function fidoU2fParseFn(attStmt) {
	const ret = new Map();
	const x5c = attStmt.x5c;
	let sig = attStmt.sig;

	if (!Array.isArray(x5c)) {
		throw new TypeError("expected U2F attestation x5c field to be of type Array");
	}

	if (x5c.length < 1) {
		throw new TypeError("no certificates in U2F x5c field");
	}

	const newX5c = [];
	for (let cert of x5c) {
		cert = coerceToArrayBuffer$1(cert, "U2F x5c cert");
		newX5c.push(cert);
	}
	// first certificate MUST be the attestation cert
	ret.set("attCert", newX5c.shift());
	// the rest of the certificates (if any) are the certificate chain
	ret.set("x5c", newX5c);

	sig = coerceToArrayBuffer$1(sig, "U2F signature");
	ret.set("sig", sig);

	return ret;
}

async function fidoU2fValidateFn() {
	const x5c = this.authnrData.get("x5c");
	const parsedAttCert = this.authnrData.get("attCert");

	// validate cert chain
	if (x5c.length > 0) {
		throw new Error("cert chain not validated");
	}
	this.audit.journal.add("x5c");

	// make sure our root certs are loaded
	if (CertManager.getCerts().size === 0) {
		u2fRootCerts.forEach((cert) => CertManager.addCert(cert));
	}

	// decode attestation cert
	const attCert = new Certificate(coerceToBase64(parsedAttCert, "parsedAttCert"));
	try {
		await attCert.verify();
	} catch (err) {
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
	const jwk = this.authnrData.get("credentialPublicKeyJwk");
	if (jwk.kty !== "EC" ||
        jwk.crv !== "P-256") {
		throw new Error("bad U2F key type");
	}

	// rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData.attestedCredentialData
	const rpIdHash = this.authnrData.get("rpIdHash");
	const credId = this.authnrData.get("credId");

	// create clientDataHash
	const rawClientData = this.clientData.get("rawClientDataJson");
	const clientDataHash = abToBuf$1(await hashDigest(abToBuf$1(rawClientData)));

	// Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to CTAP1/U2F public Key format [FIDO-CTAP]
	//      Let publicKeyU2F represent the result of the conversion operation and set its first byte to 0x04. Note: This signifies uncompressed ECC key format.
	//      Extract the value corresponding to the "-2" key (representing x coordinate) from credentialPublicKey, confirm its size to be of 32 bytes and concatenate it with publicKeyU2F. If size differs or "-2" key is not found, terminate this algorithm and return an appropriate error.
	const x = coerceToArrayBuffer$1(jwk.x, "U2F public key x component");
	if (x.byteLength !== 32) {
		throw new Error("U2F public key x component was wrong size");
	}

	//      Extract the value corresponding to the "-3" key (representing y coordinate) from credentialPublicKey, confirm its size to be of 32 bytes and concatenate it with publicKeyU2F. If size differs or "-3" key is not found, terminate this algorithm and return an appropriate error.
	const y = coerceToArrayBuffer$1(jwk.y, "U2F public key y component");
	if (y.byteLength !== 32) {
		throw new Error("U2F public key y component was wrong size");
	}

	// Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
	const verificationData = new Uint8Array([
		0x00,
		...new Uint8Array(rpIdHash),
		...new Uint8Array(clientDataHash),
		...new Uint8Array(credId),
		0x04,
		...new Uint8Array(x),
		...new Uint8Array(y),
	]);

	// Verify the sig using verificationData and certificate public key per [SEC1].
	const sig = this.authnrData.get("sig");
	const attCertPem = abToPem("CERTIFICATE", parsedAttCert);

	// Get public key from cert
	const cert = new Certificate(attCertPem);
	const publicKey = await cert.getPublicKey();

	const res = await verifySignature(
		publicKey,
		abToBuf$1(sig),
		abToBuf$1(verificationData),
		"SHA-256",
	);
	if (!res) {
		throw new Error("U2F attestation signature verification failed");
	}
	this.audit.journal.add("sig");

	// If successful, return attestation type Basic with the attestation trust path set to x5c.
	this.audit.info.set("attestation-type", "basic");

	this.audit.journal.add("fmt");
	return true;
}

const fidoU2fAttestation = {
	name: "fido-u2f",
	parseFn: fidoU2fParseFn,
	validateFn: fidoU2fValidateFn,
};

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
	const protectedHeader = await jose.decodeProtectedHeader(response);
	const publicKey = await getEmbeddedJwk(protectedHeader);
	const parsedJws = await jose.jwtVerify(
		response,
		await jose.importJWK(publicKey),
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
	const clientDataHash = await hashDigest(rawClientData);

	// concatenate buffers
	const rawAuthnrDataBuf = new Uint8Array(rawAuthnrData);
	const clientDataHashBuf = new Uint8Array(clientDataHash);

	const concatenated = appendBuffer$1(rawAuthnrDataBuf, clientDataHashBuf);

	// create hash of the concatenation
	const hash = await hashDigest(concatenated);

	const nonce = base64.fromArrayBuffer(hash);

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
	const attCert = new Certificate(coerceToBase64(parsedJws.header.x5c.shift(), "parsedAttCert"));
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

function tpmParseFn(attStmt) {
	const ret = new Map();

	if (attStmt.ecdaaKeyId !== undefined) {
		throw new Error("TPM ECDAA attesation is not currently supported.");
	}

	// x5c
	const x5c = attStmt.x5c;

	if (!Array.isArray(x5c)) {
		throw new TypeError("expected TPM attestation x5c field to be of type Array");
	}

	if (x5c.length < 1) {
		throw new TypeError("no certificates in TPM x5c field");
	}

	const newX5c = [];
	for (let cert of x5c) {
		cert = coerceToArrayBuffer$1(cert, "TPM x5c cert");
		newX5c.push(cert);
	}
	// first certificate MUST be the attestation cert
	ret.set("attCert", newX5c.shift());
	// the rest of the certificates (if any) are the certificate chain
	ret.set("x5c", newX5c);

	// ecdaa
	if (attStmt.ecdaaKeyId) ret.set("ecdaaKeyId", attStmt.ecdaaKeyId);

	// sig
	ret.set("sig", coerceToArrayBuffer$1(attStmt.sig, "tpm signature"));

	// sig
	ret.set("ver", attStmt.ver);

	// alg
	const alg = {
		algName: coseAlgToStr(attStmt.alg),
		hashAlg: coseAlgToHashStr(attStmt.alg),
	};
	ret.set("alg", alg);

	// certInfo
	const certInfo = parseCertInfo(coerceToArrayBuffer$1(attStmt.certInfo, "certInfo"));
	ret.set("certInfo", certInfo);

	// pubArea
	const pubArea = parsePubArea(coerceToArrayBuffer$1(attStmt.pubArea, "pubArea"));
	ret.set("pubArea", pubArea);

	return ret;
}

function parseCertInfo(certInfo) {
	if (!(certInfo instanceof ArrayBuffer)) {
		throw new Error("tpm attestation: expected certInfo to be ArrayBuffer");
	}

	const dv = new DataView(certInfo);
	let offset = 0;
	let ret;
	const ci = new Map();
	ci.set("rawCertInfo", certInfo);

	// TPM_GENERATED_VALUE magic number
	const magic = dv.getUint32(offset);
	// if this isn't the magic number, the rest of the parsing is going to fail
	if (magic !== 0xff544347) { // 0xFF + 'TCG'
		throw new Error("tpm attestation: certInfo had bad magic number: " + magic.toString(16));
	}
	ci.set("magic", magic);
	offset += 4;

	// TPMI_ST_ATTEST type
	const type = decodeStructureTag(dv.getUint16(offset));
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

	const dv = new DataView(pubArea);
	let offset = 0;
	let ret;
	const pa = new Map();
	pa.set("rawPubArea", pubArea);

	// TPMI_ALG_PUBLIC type
	const type = algIdToStr(dv.getUint16(offset));
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
	let exponent = dv.getUint32(offset);
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
	const attrList = [
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

	const ret = new Set();

	for (let i = 0; i < 32; i++) {
		const bit = 1 << i;
		if (oa & bit) {
			ret.add(attrList[i]);
		}
	}

	return ret;
}

function getSizedElement(dv, offset) {
	const size = dv.getUint16(offset);
	offset += 2;
	const buf = dv.buffer.slice(offset, offset + size);
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
	const {
		offset,
		dv,
	} = getSizedElement(dvIn, oIn);

	const hashType = algIdToStr(dv.getUint16(0));
	const nameHash = dv.buffer.slice(2);

	return {
		hashType,
		nameHash,
		offset,
	};
}

function algIdToStr(hashType) {
	const hashList = [
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
	const parsedAttCert = this.authnrData.get("attCert");
	const certInfo = this.authnrData.get("certInfo");
	const pubArea = this.authnrData.get("pubArea");

	const ver = this.authnrData.get("ver");
	if (ver != "2.0") {
		throw new Error("tpm attestation: expected TPM version 2.0");
	}
	this.audit.journal.add("ver");

	// https://www.w3.org/TR/webauthn/#tpm-attestation
	// Verify that the public key specified by the parameters and unique fields of pubArea is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
	const pubAreaPkN = pubArea.get("unique");
	const pubAreaPkExp = pubArea.get("exponent");
	const credentialPublicKeyJwk = this.authnrData.get("credentialPublicKeyJwk");
	const credentialPublicKeyJwkN = coerceToArrayBuffer$1(credentialPublicKeyJwk.n,"credentialPublicKeyJwk.n");
	const credentialPublicKeyJwkExpBuf = coerceToArrayBuffer$1(credentialPublicKeyJwk.e,"credentialPublicKeyJwk.e");
	const credentialPublicKeyJwkExp = abToInt(credentialPublicKeyJwkExpBuf);

	if (credentialPublicKeyJwk.kty !== "RSA" ||
        pubArea.get("type") !== "TPM_ALG_RSA") {
		throw new Error("tpm attestation: only RSA keys are currently supported");
	}

	if (pubAreaPkExp !== credentialPublicKeyJwkExp) {
		throw new Error("tpm attestation: RSA exponents of WebAuthn credentialPublicKey and TPM publicArea did not match");
	}

	if (!arrayBufferEquals(credentialPublicKeyJwkN, pubAreaPkN)) {
		throw new Error("tpm attestation: RSA 'n' of WebAuthn credentialPublicKey and TPM publicArea did not match");
	}
	// Validate that certInfo is valid:
	//     Verify that magic is set to TPM_GENERATED_VALUE.
	const magic = certInfo.get("magic");
	if (magic !== 0xff544347) { // 0xFF + 'TCG'
		throw new Error("tpm attestation: certInfo had bad magic number: " + magic.toString(16));
	}

	//     Verify that type is set to TPM_ST_ATTEST_CERTIFY.
	const type = certInfo.get("type");
	if (type !== "TPM_ST_ATTEST_CERTIFY") {
		throw new Error("tpm attestation: got wrong type. expected 'TPM_ST_ATTEST_CERTIFY' got: " + type);
	}

	//     Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
	const rawAuthnrData = this.authnrData.get("rawAuthnrData");
	const rawClientData = this.clientData.get("rawClientDataJson");
	const clientDataHashBuf = await hashDigest(abToBuf$1(rawClientData));

	const alg = this.authnrData.get("alg");
	if (alg.hashAlg === undefined) {
		throw new Error("tpm attestation: unknown algorithm: " + alg);
	}
	this.audit.journal.add("alg");

	const extraDataHashBuf = await hashDigest(
		appendBuffer$1(abToBuf$1(rawAuthnrData), clientDataHashBuf),
		alg.hashAlg,
	);
	const generatedExtraDataHash = new Uint8Array(extraDataHashBuf).buffer;
	const extraData = certInfo.get("extraData");
	if (!arrayBufferEquals(generatedExtraDataHash, extraData)) {
		throw new Error("extraData hash did not match authnrData + clientDataHash hashed");
	}

	//     Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3,
	//     [see parser]
	//     whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
	const pubAreaName = certInfo.get("name");
	const pubAreaNameHashAlg = tpmHashToNpmHash(certInfo.get("nameHashType"));
	const pubAreaNameHashBuf = await hashDigest(
		abToBuf$1(pubArea.get("rawPubArea")),
		pubAreaNameHashAlg,
	);
	const generatedPubAreaNameHash = new Uint8Array(pubAreaNameHashBuf).buffer;
	if (!arrayBufferEquals(generatedPubAreaNameHash, pubAreaName)) {
		throw new Error("pubAreaName hash did not match hash of publicArea");
	}
	this.audit.journal.add("pubArea");

	//     Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored.
	//     These fields MAY be used as an input to risk engines.

	// If x5c is present, this indicates that the attestation type is not ECDAA. In this case:
	//     Verify the sig is a valid signature over certInfo using the attestation public key in x5c with the algorithm specified in alg.
	const sig = this.authnrData.get("sig");
	const rawCertInfo = certInfo.get("rawCertInfo");
	const attCertPem = abToPem("CERTIFICATE", parsedAttCert);

	// Get public key from cert
	const cert = new Certificate(attCertPem);
	const publicKey = await cert.getPublicKey();

	const res = await verifySignature(
		publicKey,
		sig,
		abToBuf$1(rawCertInfo),
		alg.hashAlg,
	);
	if (!res) {
		throw new Error("TPM attestation signature verification failed");
	}
	this.audit.journal.add("sig");
	this.audit.journal.add("certInfo");

	//     Verify that x5c meets the requirements in §8.3.1 TPM attestation statement certificate requirements.
	// https://www.w3.org/TR/webauthn/#tpm-cert-requirements
	// decode attestation cert
	const attCert = new Certificate(coerceToBase64(parsedAttCert, "parsedAttCert"));
	try {
		await attCert.verify();
	} catch (e) {
		const err = e;
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
	const attCertSubject = attCert.getSubject();
	if (attCertSubject.size !== 0) {
		throw new Error("tpm attestation: attestation certificate MUST have empty subject");
	}

	// The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
	// [save certificate warnings, info, and extensions in our audit information]
	const attCertExt = attCert.getExtensions();
	attCertExt.forEach((v, k) => this.audit.info.set(k, v));
	attCert.info.forEach((v, k) => this.audit.info.set(k, v));
	attCert.warning.forEach((v, k) => this.audit.warning.set(k, v));

	const altName = attCertExt.get("subject-alt-name");
	if (altName === undefined ||
        !Array.isArray(altName) ||
        altName.length < 1) {
		throw new Error("tpm attestation: Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9");
	}

	// TCG EK Credential Profile For TPM Family 2.0; Level 0 Specification Version 2.0 Revision 14 4 November 2014
	// The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryNameform within the GeneralName structure.
	let directoryName;
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
	const extKeyUsage = attCertExt.get("ext-key-usage");
	if (!Array.isArray(extKeyUsage) || !extKeyUsage.includes("tcg-kp-aik-certificate")) {
		throw new Error("tpm attestation: the Extended Key Usage extension MUST contain 'tcg-kp-aik-certificate'");
	}


	// The Basic Constraints extension MUST have the CA component set to false.
	const basicConstraints = attCertExt.get("basic-constraints");
	if (typeof basicConstraints !== "object" || basicConstraints.cA !== false) {
		throw new Error("tpm attestation: the Basic Constraints extension MUST have the CA component set to false");
	}
	// An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280]
	// are both OPTIONAL as the status of many attestation certificates is available through metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].
	// [will use MDS]

	//     If x5c contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
	const certAaguid = attCertExt.get("fido-aaguid");
	const aaguid = this.authnrData.get("aaguid");
	if (certAaguid !== undefined && !arrayBufferEquals(aaguid, certAaguid)) {
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
		case "TPM_ALG_SHA1": return "SHA-1";
		case "TPM_ALG_SHA256": return "SHA-256";
		case "TPM_ALG_SHA384": return "SHA-384";
		case "TPM_ALG_SHA512": return "SHA-512";
		default:
			throw new TypeError("Unsupported hash type: " + tpmHash);
	}
}

const tpmAttestation = {
	name: "tpm",
	parseFn: tpmParseFn,
	validateFn: tpmValidateFn,
};

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
		cert = coerceToArrayBuffer$1(cert, "apple x5c cert");
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

	const clientDataHash = await hashDigest(rawClientData);

	const rawAuthnrDataBuf = new Uint8Array(rawAuthnrData);
	const clientDataHashBuf = new Uint8Array(clientDataHash);

	const nonceToHash = appendBuffer$1(rawAuthnrDataBuf, clientDataHashBuf);

	// Step 3: Perform SHA-256 hash of nonceToHash to produce nonce.
	const nonce = await hashDigest(nonceToHash);

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

const {
	coerceToArrayBuffer,
	abToBuf,
	tools,
	appendBuffer,
} = utils;

const globalAttestationMap = new Map();
const globalExtensionMap = new Map();
const globalMdsCollection = new Map();

class Fido2Lib {
	/**
	 * Creates a FIDO2 server class
	 * @param {Object} opts Options for the server
	 * @param {Number} [opts.timeout=60000] The amount of time to wait, in milliseconds, before a call has timed out
	 * @param {String} [opts.rpId="localhost"] The name of the server
	 * @param {String} [opts.rpName="Anonymous Service"] The name of the server
	 * @param {String} [opts.rpIcon] A URL for the service's icon. Can be a [RFC 2397]{@link https://tools.ietf.org/html/rfc2397} data URL.
	 * @param {Number} [opts.challengeSize=64] The number of bytes to use for the challenge
	 * @param {Object} [opts.authenticatorSelection] An object describing what types of authenticators are allowed to register with the service.
	 * See [AuthenticatorSelectionCriteria]{@link https://w3.org/TR/webauthn/#authenticatorSelection} in the WebAuthn spec for details.
	 * @param {String} [opts.authenticatorAttachment] Indicates whether authenticators should be part of the OS ("platform"), or can be roaming authenticators ("cross-platform")
	 * @param {Boolean} [opts.authenticatorRequireResidentKey] Indicates whether authenticators must store the key internally (true) or if they can use a KDF to generate keys
	 * @param {String} [opts.authenticatorUserVerification] Indicates whether user verification should be performed. Options are "required", "preferred", or "discouraged".
	 * @param {String} [opts.attestation="direct"] The preferred attestation type to be used.
	 * See [AttestationConveyancePreference]{https://w3.org/TR/webauthn/#enumdef-attestationconveyancepreference} in the WebAuthn spec
	 * @param {Array<Number>} [opts.cryptoParams] A list of COSE algorithm identifiers (e.g. -7)
	 * ordered by the preference in which the authenticator should use them.
	 */
	constructor(opts) {
		/* eslint complexity: ["off"] */
		opts = opts || {};

		// set defaults
		this.config = {};

		// timeout
		this.config.timeout = (opts.timeout === undefined) ? 60000 : opts.timeout; // 1 minute
		checkOptType(this.config, "timeout", "number");
		if (!(this.config.timeout >>> 0 === parseFloat(this.config.timeout))) {
			throw new RangeError("timeout should be zero or positive integer");
		}

		// challengeSize
		this.config.challengeSize = opts.challengeSize || 64;
		checkOptType(this.config, "challengeSize", "number");
		if (this.config.challengeSize < 32) {
			throw new RangeError(
				"challenge size too small, must be 32 or greater",
			);
		}

		// rpId
		this.config.rpId = opts.rpId;
		checkOptType(this.config, "rpId", "string");

		// rpName
		this.config.rpName = opts.rpName || "Anonymous Service";
		checkOptType(this.config, "rpName", "string");

		// rpIcon
		this.config.rpIcon = opts.rpIcon;
		checkOptType(this.config, "rpIcon", "string");

		// authenticatorRequireResidentKey
		this.config.authenticatorRequireResidentKey = opts.authenticatorRequireResidentKey;
		checkOptType(this.config, "authenticatorRequireResidentKey", "boolean");

		// authenticatorAttachment
		this.config.authenticatorAttachment = opts.authenticatorAttachment;
		if (
			this.config.authenticatorAttachment !== undefined &&
			(this.config.authenticatorAttachment !== "platform" &&
				this.config.authenticatorAttachment !== "cross-platform")
		) {
			throw new TypeError(
				"expected authenticatorAttachment to be 'platform', or 'cross-platform', got: " +
					this.config.authenticatorAttachment,
			);
		}

		// authenticatorUserVerification
		this.config.authenticatorUserVerification = opts.authenticatorUserVerification;
		if (
			this.config.authenticatorUserVerification !== undefined &&
			(this.config.authenticatorUserVerification !== "required" &&
				this.config.authenticatorUserVerification !== "preferred" &&
				this.config.authenticatorUserVerification !== "discouraged")
		) {
			throw new TypeError(
				"expected authenticatorUserVerification to be 'required', 'preferred', or 'discouraged', got: " +
					this.config.authenticatorUserVerification,
			);
		}

		// attestation
		this.config.attestation = opts.attestation || "direct";
		if (
			this.config.attestation !== "direct" &&
			this.config.attestation !== "indirect" &&
			this.config.attestation !== "none"
		) {
			throw new TypeError(
				"expected attestation to be 'direct', 'indirect', or 'none', got: " +
					this.config.attestation,
			);
		}

		// cryptoParams
		this.config.cryptoParams = opts.cryptoParams || [-7, -257];
		checkOptType(this.config, "cryptoParams", Array);
		if (this.config.cryptoParams.length < 1) {
			throw new TypeError("cryptoParams must have at least one element");
		}
		this.config.cryptoParams.forEach((param) => {
			checkOptType({ cryptoParam: param }, "cryptoParam", "number");
		});

		this.attestationMap = globalAttestationMap;
		this.extSet = new Set(); // enabled extensions (all disabled by default)
		this.extOptMap = new Map(); // default options for extensions

		// TODO: convert icon file to data-URL icon
		// TODO: userVerification
	}

	/**
	 * Creates a new {@link MdsCollection}
	 * @param {String} collectionName The name of the collection to create.
	 * Used to identify the source of a {@link MdsEntry} when {@link Fido2Lib#findMdsEntry}
	 * finds multiple matching entries from different sources (e.g. FIDO MDS 1 & FIDO MDS 2)
	 * @return {MdsCollection} The MdsCollection that was created
	 * @see  MdsCollection
	 */
	static createMdsCollection(collectionName) {
		return new MdsCollection(collectionName);
	}

	/**
	 * Adds a new {@link MdsCollection} to the global MDS collection list that will be used for {@link findMdsEntry}
	 * @param {MdsCollection} mdsCollection The MDS collection that will be used
	 * @see  MdsCollection
	 */
	static async addMdsCollection(mdsCollection) {
		if (!(mdsCollection instanceof MdsCollection)) {
			throw new Error(
				"expected 'mdsCollection' to be instance of MdsCollection, got: " +
					mdsCollection,
			);
		}
		await mdsCollection.validate();
		globalMdsCollection.set(mdsCollection.name, mdsCollection);
	}

	/**
	 * Removes all entries from the global MDS collections list. Mostly used for testing.
	 */
	static clearMdsCollections() {
		globalMdsCollection.clear();
	}

	/**
	 * Returns {@link MdsEntry} objects that match the requested id. The
	 * lookup is done by calling {@link MdsCollection#findEntry} on the current global
	 * MDS collection. If no global MDS collection has been specified using
	 * {@link setMdsCollection}, an `Error` will be thrown.
	 * @param  {String|ArrayBuffer} id The authenticator id to look up metadata for
	 * @return {Array.<MdsEntry>}    Returns an Array of {@link MdsEntry} for the specified id.
	 * If no entry was found, the Array will be empty.
	 * @see  MdsCollection
	 */
	static findMdsEntry(id) {
		if (globalMdsCollection.size < 1) {
			throw new Error(
				"must set MDS collection before attempting to find an MDS entry",
			);
		}

		const ret = [];
		for (const collection of globalMdsCollection.values()) {
			const entry = collection.findEntry(id);
			if (entry) ret.push(entry);
		}

		return ret;
	}

	/**
	 * Adds a new global extension that will be available to all instantiations of
	 * {@link Fido2Lib}. Note that the extension must still be enabled by calling
	 * {@link enableExtension} for each instantiation of a Fido2Lib.
	 * @param {String} extName     The name of the extension to add. (e.g. - "appid")
	 * @param {Function} optionGeneratorFn Extensions are included in
	 * @param {Function} resultParserFn    [description]
	 * @param {Function} resultValidatorFn [description]
	 */
	static addExtension(
		extName,
		optionGeneratorFn,
		resultParserFn,
		resultValidatorFn,
	) {
		if (typeof extName !== "string") {
			throw new Error("expected 'extName' to be String, got: " + extName);
		}

		if (globalExtensionMap.has(extName)) {
			throw new Error(
				`the extension '${extName}' has already been added`,
			);
		}

		if (typeof optionGeneratorFn !== "function") {
			throw new Error(
				"expected 'optionGeneratorFn' to be a Function, got: " +
					optionGeneratorFn,
			);
		}

		if (typeof resultParserFn !== "function") {
			throw new Error(
				"expected 'resultParserFn' to be a Function, got: " +
					resultParserFn,
			);
		}

		if (typeof resultValidatorFn !== "function") {
			throw new Error(
				"expected 'resultValidatorFn' to be a Function, got: " +
					resultValidatorFn,
			);
		}

		globalExtensionMap.set(extName, {
			optionGeneratorFn,
			resultParserFn,
			resultValidatorFn,
		});
	}

	/**
	 * Removes all extensions from the global extension registry. Mostly used for testing.
	 */
	static deleteAllExtensions() {
		globalExtensionMap.clear();
	}

	/**
	 * Generates the options to send to the client for the specified extension
	 * @private
	 * @param  {String} extName The name of the extension to generate options for. Must be a valid extension that has been registered through {@link Fido2Lib#addExtension}
	 * @param  {String} type    The type of options that are being generated. Valid options are "attestation" or "assertion".
	 * @param  {Any} [options] Optional parameters to pass to the generator function
	 * @return {Any}         The extension value that will be sent to the client. If `undefined`, this extension won't be included in the
	 * options sent to the client.
	 */
	generateExtensionOptions(extName, type, options) {
		if (typeof extName !== "string") {
			throw new Error("expected 'extName' to be String, got: " + extName);
		}

		if (type !== "attestation" && type !== "assertion") {
			throw new Error(
				"expected 'type' to be 'attestation' or 'assertion', got: " +
					type,
			);
		}

		const ext = globalExtensionMap.get(extName);
		if (
			typeof ext !== "object" ||
			typeof ext.optionGeneratorFn !== "function"
		) {
			throw new Error(`valid extension for '${extName}' not found`);
		}
		const ret = ext.optionGeneratorFn(extName, type, options);

		return ret;
	}

	static parseExtensionResult(extName, clientThing, authnrThing) {
		if (typeof extName !== "string") {
			throw new Error("expected 'extName' to be String, got: " + extName);
		}

		const ext = globalExtensionMap.get(extName);
		if (
			typeof ext !== "object" ||
			typeof ext.parseFn !== "function"
		) {
			throw new Error(`valid extension for '${extName}' not found`);
		}
		const ret = ext.parseFn(extName, clientThing, authnrThing);

		return ret;
	}

	static validateExtensionResult(extName) {
		const ext = globalExtensionMap.get(extName);
		if (
			typeof ext !== "object" ||
			typeof ext.validateFn !== "function"
		) {
			throw new Error(`valid extension for '${extName}' not found`);
		}
		const ret = ext.validateFn.call(this);

		return ret;
	}

	/**
	 * Enables the specified extension.
	 * @param  {String} extName The name of the extension to enable. Must be a valid extension that has been registered through {@link Fido2Lib#addExtension}
	 */
	enableExtension(extName) {
		if (typeof extName !== "string") {
			throw new Error("expected 'extName' to be String, got: " + extName);
		}

		if (!globalExtensionMap.has(extName)) {
			throw new Error(`valid extension for '${extName}' not found`);
		}

		this.extSet.add(extName);
	}

	/**
	 * Disables the specified extension.
	 * @param  {String} extName The name of the extension to enable. Must be a valid extension that has been registered through {@link Fido2Lib#addExtension}
	 */
	disableExtension(extName) {
		if (typeof extName !== "string") {
			throw new Error("expected 'extName' to be String, got: " + extName);
		}

		if (!globalExtensionMap.has(extName)) {
			throw new Error(`valid extension for '${extName}' not found`);
		}

		this.extSet.delete(extName);
	}

	/**
	 * Specifies the options to be used for the extension
	 * @param  {String} extName The name of the extension to set the options for (e.g. - "appid". Must be a valid extension that has been registered through {@link Fido2Lib#addExtension}
	 * @param {Any} options The parameter that will be passed to the option generator function (e.g. - "https://webauthn.org")
	 */
	setExtensionOptions(extName, options) {
		if (typeof extName !== "string") {
			throw new Error("expected 'extName' to be String, got: " + extName);
		}

		if (!globalExtensionMap.has(extName)) {
			throw new Error(`valid extension for '${extName}' not found`);
		}

		this.extOptMap.set(extName, options);
	}

	/**
	 * Validates an attestation response. Will be called within the context (`this`) of a {@link Fido2AttestationResult}
	 * @private
	 */
	static async validateAttestation() {
		const fmt = this.authnrData.get("fmt");

		// validate input
		if (typeof fmt !== "string") {
			throw new TypeError(
				"expected 'fmt' to be string, got: " + typeof fmt,
			);
		}

		// get from attestationMap
		const fmtObj = globalAttestationMap.get(fmt);
		if (
			typeof fmtObj !== "object" ||
			typeof fmtObj.parseFn !== "function" ||
			typeof fmtObj.validateFn !== "function"
		) {
			throw new Error(`no support for attestation format: ${fmt}`);
		}

		// call fn
		const ret = await fmtObj.validateFn.call(this);

		// validate return
		if (ret !== true) {
			throw new Error(`${fmt} validateFn did not return 'true'`);
		}

		// return result
		return ret;
	}

	/**
	 * Adds a new attestation format that will automatically be recognized and parsed
	 * for any future {@link Fido2CreateRequest} messages
	 * @param {String} fmt The name of the attestation format, as it appears in the
	 * ARIN registry and / or as it will appear in the {@link Fido2CreateRequest}
	 * message that is received
	 * @param {Function} parseFn The function that will be called to parse the
	 * attestation format. It will receive the `attStmt` as a parameter and will be
	 * called from the context (`this`) of the `Fido2CreateRequest`
	 * @param {Function} validateFn The function that will be called to validate the
	 * attestation format. It will receive no arguments, as all the necessary
	 * information for validating the attestation statement will be contained in the
	 * calling context (`this`).
	 */
	static addAttestationFormat(fmt, parseFn, validateFn) {
		// validate input
		if (typeof fmt !== "string") {
			throw new TypeError(
				"expected 'fmt' to be string, got: " + typeof fmt,
			);
		}

		if (typeof parseFn !== "function") {
			throw new TypeError(
				"expected 'parseFn' to be string, got: " + typeof parseFn,
			);
		}

		if (typeof validateFn !== "function") {
			throw new TypeError(
				"expected 'validateFn' to be string, got: " + typeof validateFn,
			);
		}

		if (globalAttestationMap.has(fmt)) {
			throw new Error(`can't add format: '${fmt}' already exists`);
		}

		// add to attestationMap
		globalAttestationMap.set(fmt, {
			parseFn,
			validateFn,
		});

		return true;
	}

	/**
	 * Deletes all currently registered attestation formats.
	 */
	static deleteAllAttestationFormats() {
		globalAttestationMap.clear();
	}

	/**
	 * Parses an attestation statememnt of the format specified
	 * @private
	 * @param {String} fmt The name of the format to be parsed, as specified in the
	 * ARIN registry of attestation formats.
	 * @param {Object} attStmt The attestation object to be parsed.
	 * @return {Map} A Map of all the attestation fields that were parsed.
	 * At this point the fields have not yet been verified.
	 * @throws {Error} when a field cannot be parsed or verified.
	 * @throws {TypeError} when supplied parameters `fmt` or `attStmt` are of the
	 * wrong type
	 */
	static parseAttestation(fmt, attStmt) {
		// validate input
		if (typeof fmt !== "string") {
			throw new TypeError(
				"expected 'fmt' to be string, got: " + typeof fmt,
			);
		}

		if (typeof attStmt !== "object") {
			throw new TypeError(
				"expected 'attStmt' to be object, got: " + typeof attStmt,
			);
		}

		// get from attestationMap
		const fmtObj = globalAttestationMap.get(fmt);
		if (
			typeof fmtObj !== "object" ||
			typeof fmtObj.parseFn !== "function" ||
			typeof fmtObj.validateFn !== "function"
		) {
			throw new Error(`no support for attestation format: ${fmt}`);
		}

		// call fn
		const ret = fmtObj.parseFn.call(this, attStmt);

		// validate return
		if (!(ret instanceof Map)) {
			throw new Error(`${fmt} parseFn did not return a Map`);
		}

		// return result
		return new Map([
			["fmt", fmt],
			...ret,
		]);
	}

	/**
	 * Parses and validates an attestation response from the client
	 * @param {Object} res The assertion result that was generated by the client.
	 * See {@link https://w3.org/TR/webauthn/#authenticatorattestationresponse AuthenticatorAttestationResponse} in the WebAuthn spec.
	 * @param {String} [res.id] The base64url encoded id returned by the client
	 * @param {String} [res.rawId] The base64url encoded rawId returned by the client. If `res.rawId` is missing, `res.id` will be used instead. If both are missing an error will be thrown.
	 * @param {String} res.response.clientDataJSON The base64url encoded clientDataJSON returned by the client
	 * @param {String} res.response.authenticatorData The base64url encoded authenticatorData returned by the client
	 * @param {Object} expected The expected parameters for the assertion response.
	 * If these parameters don't match the recieved values, validation will fail and an error will be thrown.
	 * @param {String} expected.challenge The base64url encoded challenge that was sent to the client, as generated by [assertionOptions]{@link Fido2Lib#assertionOptions}
	 * @param {String} expected.origin The expected origin that the authenticator has signed over. For example, "https://localhost:8443" or "https://webauthn.org"
	 * @param {String} expected.factor Which factor is expected for the assertion. Valid values are "first", "second", or "either".
	 * If "first", this requires that the authenticator performed user verification (e.g. - biometric authentication, PIN authentication, etc.).
	 * If "second", this requires that the authenticator performed user presence (e.g. - user pressed a button).
	 * If "either", then either "first" or "second" is acceptable
	 * @return {Promise<Fido2AttestationResult>} Returns a Promise that resolves to a {@link Fido2AttestationResult}
	 * @throws {Error} If parsing or validation fails
	 */
	async attestationResult(res, expected) {
		expected.flags = factorToFlags(expected.factor, ["AT"]);
		delete expected.factor;
		return await Fido2AttestationResult.create(res, expected);
	}

	/**
	 * Parses and validates an assertion response from the client
	 * @param {Object} res The assertion result that was generated by the client.
	 * See {@link https://w3.org/TR/webauthn/#authenticatorassertionresponse AuthenticatorAssertionResponse} in the WebAuthn spec.
	 * @param {String} [res.id] The base64url encoded id returned by the client
	 * @param {String} [res.rawId] The base64url encoded rawId returned by the client. If `res.rawId` is missing, `res.id` will be used instead. If both are missing an error will be thrown.
	 * @param {String} res.response.clientDataJSON The base64url encoded clientDataJSON returned by the client
	 * @param {String} res.response.attestationObject The base64url encoded authenticatorData returned by the client
	 * @param {String} res.response.signature The base64url encoded signature returned by the client
	 * @param {String|null} [res.response.userHandle] The base64url encoded userHandle returned by the client. May be null or an empty string.
	 * @param {Object} expected The expected parameters for the assertion response.
	 * If these parameters don't match the recieved values, validation will fail and an error will be thrown.
	 * @param {String} expected.challenge The base64url encoded challenge that was sent to the client, as generated by [assertionOptions]{@link Fido2Lib#assertionOptions}
	 * @param {String} expected.origin The expected origin that the authenticator has signed over. For example, "https://localhost:8443" or "https://webauthn.org"
	 * @param {String} expected.factor Which factor is expected for the assertion. Valid values are "first", "second", or "either".
	 * If "first", this requires that the authenticator performed user verification (e.g. - biometric authentication, PIN authentication, etc.).
	 * If "second", this requires that the authenticator performed user presence (e.g. - user pressed a button).
	 * If "either", then either "first" or "second" is acceptable
	 * @param {String} expected.publicKey A PEM encoded public key that will be used to validate the assertion response signature.
	 * This is the public key that was returned for this user during [attestationResult]{@link Fido2Lib#attestationResult}
	 * @param {Number} expected.prevCounter The previous value of the signature counter for this authenticator.
	 * @param {String|null} expected.userHandle The expected userHandle, which was the user.id during registration
	 * @return {Promise<Fido2AssertionResult>} Returns a Promise that resolves to a {@link Fido2AssertionResult}
	 * @throws {Error} If parsing or validation fails
	 */
	// deno-lint-ignore require-await
	async assertionResult(res, expected) {
		expected.flags = factorToFlags(expected.factor, []);
		delete expected.factor;
		return Fido2AssertionResult.create(res, expected);
	}

	/**
	 * Gets a challenge and any other parameters for the `navigator.credentials.create()` call
	 * The `challenge` property is an `ArrayBuffer` and will need to be encoded to be transmitted to the client.
	 * @param {Object} [opts] An object containing various options for the option creation
	 * @param {Object} [opts.extensionOptions] An object that contains the extensions to enable, and the options to use for each of them.
	 * The keys of this object are the names of the extensions (e.g. - "appid"), and the value of each key is the option that will
	 * be passed to that extension when it is generating the value to send to the client. This object overrides the extensions that
	 * have been set with {@link enableExtension} and the options that have been set with {@link setExtensionOptions}. If an extension
	 * was enabled with {@link enableExtension} but it isn't included in this object, the extension won't be sent to the client. Likewise,
	 * if an extension was disabled with {@link disableExtension} but it is included in this object, it will be sent to the client.
	 * @param {String} [extraData] Extra data to be signed by the authenticator during attestation. The challenge will be a hash:
	 * SHA256(rawChallenge + extraData) and the `rawChallenge` will be returned as part of PublicKeyCredentialCreationOptions.
	 * @returns {Promise<PublicKeyCredentialCreationOptions>} The options for creating calling `navigator.credentials.create()`
	 */
	async attestationOptions(opts) {
		opts = opts || {};

		// The object being returned is described here:
		// https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
		let challenge = tools.randomValues(this.config.challengeSize);
		challenge = coerceToArrayBuffer(challenge, "challenge");
		const pubKeyCredParams = [];
		this.config.cryptoParams.forEach((coseId) => {
			pubKeyCredParams.push({
				type: "public-key",
				alg: coseId,
			});
		});

		// mix extraData into challenge
		let rawChallenge;
		if (opts.extraData) {
			rawChallenge = challenge;
			const extraData = coerceToArrayBuffer(opts.extraData, "extraData");
			const hash = await tools.hashDigest(
				appendBuffer(challenge, extraData),
			);
			challenge = new Uint8Array(hash).buffer;
		}

		const options = {
			rp: {},
			user: {},
		};

		const extensions = createExtensions.call(
			this,
			"attestation",
			opts.extensionOptions,
		);

		/**
		 * @typedef {Object} PublicKeyCredentialCreationOptions
		 * @description This object is returned by {@link attestationOptions} and is basially the same as
		 * the [PublicKeyCredentialCreationOptions]{@link https://w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions}
		 * object that is required to be passed to `navigator.credentials.create()`. With the exception of the `challenge` property,
		 * all other properties are optional and only set if they were specified in the configuration paramater
		 * that was passed to the constructor.
		 * @property {Object} rp Relying party information (a.k.a. - server / service information)
		 * @property {String} [rp.name] Relying party name (e.g. - "ACME"). This is only set if `rpName` was specified during the `new` call.
		 * @property {String} [rp.id] Relying party ID, a domain name (e.g. - "example.com"). This is only set if `rpId` was specified during the `new` call.
		 * @property {Object} user User information. This will be an empty object
		 * @property {ArrayBuffer} challenge An ArrayBuffer filled with random bytes. This will be verified in {@link attestationResult}
		 * @property {Array} [pubKeyCredParams] A list of PublicKeyCredentialParameters objects, based on the `cryptoParams` that was passed to the constructor.
		 * @property {Number} [timeout] The amount of time that the call should take before returning an error
		 * @property {String} [attestation] Whether the client should request attestation from the authenticator or not
		 * @property {Object} [authenticatorSelection] A object describing which authenticators are preferred for registration
		 * @property {String} [authenticatorSelection.attachment] What type of attachement is acceptable for new authenticators.
		 * Allowed values are "platform", meaning that the authenticator is embedded in the operating system, or
		 * "cross-platform", meaning that the authenticator is removeable (e.g. USB, NFC, or BLE).
		 * @property {Boolean} [authenticatorSelection.requireResidentKey] Indicates whether authenticators must store the keys internally, or if they can
		 * store them externally (using a KDF or key wrapping)
		 * @property {String} [authenticatorSelection.userVerification] Indicates whether user verification is required for authenticators. User verification
		 * means that an authenticator will validate a use through their biometrics (e.g. fingerprint) or knowledge (e.g. PIN). Allowed
		 * values for `userVerification` are "required", meaning that registration will fail if no authenticator provides user verification;
		 * "preferred", meaning that if multiple authenticators are available, the one(s) that provide user verification should be used; or
		 * "discouraged", which means that authenticators that don't provide user verification are preferred.
		 * @property {ArrayBuffer} [rawChallenge] If `extraData` was passed to {@link attestationOptions}, this
		 * will be the original challenge used, and `challenge` will be a hash:
		 * SHA256(rawChallenge + extraData)
		 * @property {Object} [extensions] The values of any enabled extensions.
		 */
		setOpt(options.rp, "name", this.config.rpName);
		setOpt(options.rp, "id", this.config.rpId);
		setOpt(options.rp, "icon", this.config.rpIcon);
		setOpt(options, "challenge", challenge);
		setOpt(options, "pubKeyCredParams", pubKeyCredParams);
		setOpt(options, "timeout", this.config.timeout);
		setOpt(options, "attestation", this.config.attestation);
		if (
			this.config.authenticatorAttachment !== undefined ||
			this.config.authenticatorRequireResidentKey !== undefined ||
			this.config.authenticatorUserVerification !== undefined
		) {
			options.authenticatorSelection = {};
			setOpt(
				options.authenticatorSelection,
				"authenticatorAttachment",
				this.config.authenticatorAttachment,
			);
			setOpt(
				options.authenticatorSelection,
				"requireResidentKey",
				this.config.authenticatorRequireResidentKey,
			);
			setOpt(
				options.authenticatorSelection,
				"userVerification",
				this.config.authenticatorUserVerification,
			);
		}
		setOpt(options, "rawChallenge", rawChallenge);

		if (Object.keys(extensions).length > 0) {
			options.extensions = extensions;
		}

		return options;
	}

	/**
	 * Creates an assertion challenge and any other parameters for the `navigator.credentials.get()` call.
	 * The `challenge` property is an `ArrayBuffer` and will need to be encoded to be transmitted to the client.
	 * @param {Object} [opts] An object containing various options for the option creation
	 * @param {Object} [opts.extensionOptions] An object that contains the extensions to enable, and the options to use for each of them.
	 * The keys of this object are the names of the extensions (e.g. - "appid"), and the value of each key is the option that will
	 * be passed to that extension when it is generating the value to send to the client. This object overrides the extensions that
	 * have been set with {@link enableExtension} and the options that have been set with {@link setExtensionOptions}. If an extension
	 * was enabled with {@link enableExtension} but it isn't included in this object, the extension won't be sent to the client. Likewise,
	 * if an extension was disabled with {@link disableExtension} but it is included in this object, it will be sent to the client.
	 * @param {String} [extraData] Extra data to be signed by the authenticator during attestation. The challenge will be a hash:
	 * SHA256(rawChallenge + extraData) and the `rawChallenge` will be returned as part of PublicKeyCredentialCreationOptions.
	 * @returns {Promise<PublicKeyCredentialRequestOptions>} The options to be passed to `navigator.credentials.get()`
	 */
	async assertionOptions(opts) {
		opts = opts || {};

		// https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
		let challenge = tools.randomValues(this.config.challengeSize);
		challenge = coerceToArrayBuffer(challenge, "challenge");
		const options = {};

		// mix extraData into challenge
		let rawChallenge;
		if (opts.extraData) {
			rawChallenge = challenge;
			const extraData = coerceToArrayBuffer(opts.extraData, "extraData");
			challenge = abToBuf(
				await tools.hashDigest(appendBuffer(challenge, extraData)),
			);
		}

		const extensions = createExtensions.call(
			this,
			"assertion",
			opts.extensionOptions,
		);

		/**
		 * @typedef {Object} PublicKeyCredentialRequestOptions
		 * @description This object is returned by {@link assertionOptions} and is basially the same as
		 * the [PublicKeyCredentialRequestOptions]{@link https://w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions}
		 * object that is required to be passed to `navigator.credentials.get()`. With the exception of the `challenge` property,
		 * all other properties are optional and only set if they were specified in the configuration paramater
		 * that was passed to the constructor.
		 * @property {ArrayBuffer} challenge An ArrayBuffer filled with random bytes. This will be verified in {@link attestationResult}
		 * @property {Number} [timeout] The amount of time that the call should take before returning an error
		 * @property {String} [rpId] Relying party ID, a domain name (e.g. - "example.com"). This is only set if `rpId` was specified during the `new` call.
		 * @property {String} [attestation] Whether the client should request attestation from the authenticator or not
		 * @property {String} [userVerification] Indicates whether user verification is required for authenticators. User verification
		 * means that an authenticator will validate a use through their biometrics (e.g. fingerprint) or knowledge (e.g. PIN). Allowed
		 * values for `userVerification` are "required", meaning that authentication will fail if no authenticator provides user verification;
		 * "preferred", meaning that if multiple authenticators are available, the one(s) that provide user verification should be used; or
		 * "discouraged", which means that authenticators that don't provide user verification are preferred.
		 * @property {ArrayBuffer} [rawChallenge] If `extraData` was passed to {@link attestationOptions}, this
		 * will be the original challenge used, and `challenge` will be a hash:
		 * SHA256(rawChallenge + extraData)
		 * @property {Object} [extensions] The values of any enabled extensions.
		 */
		setOpt(options, "challenge", challenge);
		setOpt(options, "timeout", this.config.timeout);
		setOpt(options, "rpId", this.config.rpId);
		setOpt(
			options,
			"userVerification",
			this.config.authenticatorUserVerification,
		);

		setOpt(options, "rawChallenge", rawChallenge);

		if (Object.keys(extensions).length > 0) {
			options.extensions = extensions;
		}

		return options;
	}
}

function checkOptType(opts, prop, type) {
	if (typeof opts !== "object") return;

	// undefined
	if (opts[prop] === undefined) return;

	// native type
	if (typeof type === "string") {
		// deno-lint-ignore valid-typeof
		if (typeof opts[prop] !== type) {
			throw new TypeError(
				`expected ${prop} to be ${type}, got: ${opts[prop]}`,
			);
		}
	}

	// class type
	if (typeof type === "function") {
		if (!(opts[prop] instanceof type)) {
			throw new TypeError(
				`expected ${prop} to be ${type.name}, got: ${opts[prop]}`,
			);
		}
	}
}

function setOpt(obj, prop, val) {
	if (val !== undefined) {
		obj[prop] = val;
	}
}

function factorToFlags(expectedFactor, flags) {
	// var flags = ["AT"];
	flags = flags || [];

	switch (expectedFactor) {
		case "first":
			flags.push("UP");
			flags.push("UV");
			break;
		case "second":
			flags.push("UP");
			break;
		case "either":
			flags.push("UP-or-UV");
			break;
		default:
			throw new TypeError(
				"expectedFactor should be 'first', 'second' or 'either'",
			);
	}

	return flags;
}

function createExtensions(type, extObj) {
	/* eslint-disable no-invalid-this */
	const extensions = {};

	// default extensions
	let enabledExtensions = this.extSet;
	let extensionsOptions = this.extOptMap;

	// passed in extensions
	if (typeof extObj === "object") {
		enabledExtensions = new Set(Object.keys(extObj));
		extensionsOptions = new Map();
		for (const key of Object.keys(extObj)) {
			extensionsOptions.set(key, extObj[key]);
		}
	}

	// generate extension values
	for (const extension of enabledExtensions) {
		const extVal = this.generateExtensionOptions(
			extension,
			type,
			extensionsOptions.get(extension),
		);
		if (extVal !== undefined) extensions[extension] = extVal;
	}

	return extensions;
}
Fido2Lib.addAttestationFormat(
	noneAttestation.name,
	noneAttestation.parseFn,
	noneAttestation.validateFn,
);
Fido2Lib.addAttestationFormat(
	packedAttestation.name,
	packedAttestation.parseFn,
	packedAttestation.validateFn,
);
Fido2Lib.addAttestationFormat(
	fidoU2fAttestation.name,
	fidoU2fAttestation.parseFn,
	fidoU2fAttestation.validateFn,
);
Fido2Lib.addAttestationFormat(
	androidSafetyNetAttestation.name,
	androidSafetyNetAttestation.parseFn,
	androidSafetyNetAttestation.validateFn,
);
Fido2Lib.addAttestationFormat(
	tpmAttestation.name,
	tpmAttestation.parseFn,
	tpmAttestation.validateFn,
);
Fido2Lib.addAttestationFormat(
	appleAttestation.name,
	appleAttestation.parseFn,
	appleAttestation.validateFn
);

exports.CRL = CRL;
exports.CertManager = CertManager;
exports.Certificate = Certificate;
exports.Fido2AssertionResult = Fido2AssertionResult;
exports.Fido2AttestationResult = Fido2AttestationResult;
exports.Fido2Lib = Fido2Lib;
exports.Fido2Result = Fido2Result;
exports.MdsCollection = MdsCollection;
exports.MdsEntry = MdsEntry;
exports.PublicKey = PublicKey;
exports.abToBuf = abToBuf$1;
exports.abToHex = abToHex;
exports.androidSafetyNetAttestation = androidSafetyNetAttestation;
exports.appendBuffer = appendBuffer$1;
exports.appleAttestation = appleAttestation;
exports.arrayBufferEquals = arrayBufferEquals;
exports.attach = attach;
exports.coerceToArrayBuffer = coerceToArrayBuffer$1;
exports.coerceToBase64 = coerceToBase64;
exports.coerceToBase64Url = coerceToBase64Url;
exports.coseAlgToHashStr = coseAlgToHashStr;
exports.coseAlgToStr = coseAlgToStr;
exports.fidoU2fAttestation = fidoU2fAttestation;
exports.helpers = helpers;
exports.isBase64Url = isBase64Url;
exports.isPem = isPem;
exports.jsObjectToB64 = jsObjectToB64;
exports.noneAttestation = noneAttestation;
exports.packedAttestation = packedAttestation;
exports.parseAttestationObject = parseAttestationObject;
exports.parseAuthenticatorData = parseAuthenticatorData;
exports.parseAuthnrAssertionResponse = parseAuthnrAssertionResponse;
exports.parseAuthnrAttestationResponse = parseAuthnrAttestationResponse;
exports.parseClientResponse = parseClientResponse;
exports.parseExpectations = parseExpectations;
exports.pemToBase64 = pemToBase64;
exports.str2ab = str2ab;
exports.tools = toolbox;
exports.tpmAttestation = tpmAttestation;
