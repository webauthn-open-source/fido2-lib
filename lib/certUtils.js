import { ab2str, coerceToArrayBuffer, isPem, pemToBase64, tools } from "./utils.js";

class Certificate {
	constructor(cert) {
		let decoded;

		// Clean up base64 string
		if (typeof cert === "string" || cert instanceof String) {
			cert = cert.replace(/\r/g, "").trim();
			decoded = ab2str(coerceToArrayBuffer(cert, "certificate"));
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

		cert = coerceToArrayBuffer(cert, "certificate");
		if (cert.byteLength === 0) {
			throw new Error("cert was empty (0 bytes)");
		}

		const asn1 = tools.fromBER(cert);
		if (asn1.offset === -1) {
			throw new Error("error parsing ASN.1");
		}

		this._cert = new tools.pkijs.Certificate({ schema: asn1.result });
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
		const publicKeyJwk = await tools.webcrypto.subtle.exportKey("jwk", publicKey);

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
		
		crl = coerceToArrayBuffer(crl, "crl");
		const asn1 = tools.fromBER(crl);
		this._crl = new tools.pkijs.CertificateRevocationList({
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

		const chain = new tools.pkijs.CertificateChainValidationEngine({
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

export { Certificate, CertManager, CRL, helpers };
