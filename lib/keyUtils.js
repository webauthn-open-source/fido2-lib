import { coerceToArrayBuffer, coerceToBase64Url, isPem, pemToBase64, tools } from "./utils.js";

function getKeyInfo(ber) {
	const asn1 = tools.fromBER(ber);
	if (asn1.offset === -1) {
		throw new Error("error parsing ASN.1");
	}
	return new tools.pkijs.PublicKeyInfo({ schema: asn1.result });
}

// main COSE labels
// defined here: https://tools.ietf.org/html/rfc8152#section-7.1
const coseLabels = {
	1: {
		name: "kty",
		values: {
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
			"-8": "EdDSA",
			"-35": "ECDSA_w_SHA384",
			"-36": "ECDSA_w_SHA512",
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

// Extract hash from Cose Alg
const algHashes = {
	ECDSA_w_SHA256: "SHA-256",
	// EdDSA: ""
	ECDSA_w_SHA384: "SHA-384",
	ECDSA_w_SHA512: "SHA-512",
	"RSASSA-PKCS1-v1_5_w_SHA256": "SHA-256",
	"RSASSA-PKCS1-v1_5_w_SHA384": "SHA-384",
	"RSASSA-PKCS1-v1_5_w_SHA512": "SHA-512",
	"RSASSA-PKCS1-v1_5_w_SHA1": "SHA-1",
};

const algMap = {
	"RSASSA-PKCS1-v1_5_w_SHA256": "RS256",
	"ECDSA_w_SHA256": "ES256",
	"ECDSA_w_SHA384": "ES256",
	"ECDSA_w_SHA512": "ES256",
};

function algToStr(alg) {
	if (typeof alg !== "number") {
		throw new TypeError("expected 'alg' to be a number, got: " + alg);
	}

	const algValues = coseLabels["3"].values;
	return algValues[alg];
}

function algToHashStr(alg) {
	if (typeof alg === "number") alg = algToStr(alg);

	if (typeof alg !== "string") {
		throw new Error(
			"'alg' is not a string or a valid COSE algorithm number",
		);
	}

	return algHashes[alg];
}

// key-specific parameters
const keyParamList = {
	// ECDSA key parameters
	// defined here: https://tools.ietf.org/html/rfc8152#section-13.1.1
	EC: {
		"-1": {
			name: "crv",
			values: {
				1: "P-256",
				2: "P-384",
				3: "P-521",
				4: "X25519",
				5: "X448",
				6: "Ed25519",
				7: "Ed448",
			},
		},
		"-2": {
			name: "x",
			// value = Buffer
		},
		"-3": {
			name: "y",
			// value = Buffer
		},
		"-4": {
			name: "d",
			// value = Buffer
		},
	},
	// RSA key parameters
	// defined here: https://tools.ietf.org/html/rfc8230#section-4
	RSA: {
		"-1": {
			name: "n",
			// value = Buffer
		},
		"-2": {
			name: "e",
			// value = Buffer
		},
		"-3": {
			name: "d",
			// value = Buffer
		},
		"-4": {
			name: "p",
			// value = Buffer
		},
		"-5": {
			name: "q",
			// value = Buffer
		},
		"-6": {
			name: "dP",
			// value = Buffer
		},
		"-7": {
			name: "dQ",
			// value = Buffer
		},
		"-8": {
			name: "qInv",
			// value = Buffer
		},
		"-9": {
			name: "other",
			// value = Array
		},
		"-10": {
			name: "r_i",
			// value = Buffer
		},
		"-11": {
			name: "d_i",
			// value = Buffer
		},
		"-12": {
			name: "t_i",
			// value = Buffer
		},
	},
};

function jwkToAlgorithm(jwk) {
	const alg = {};
	if (algMap[jwk.alg]) {
		alg.name = algMap[jwk.alg];
	}
	if (algHashes[jwk.alg]) {
		alg.hash = algHashes[jwk.alg];
	}
	if (jwk.crv) {
		alg.namedCurve = jwk.crv;
	}
	return alg;
}

class Key {
	constructor(key, alg) {
		// Stored on import
		this._original_pem = undefined;
		this._original_jwk = undefined;
		this._original_cose = undefined;

		// Allow a CryptoKey to be passed through the constructor
		if (key && (!key.type || key.type !== "public")) {
			throw new TypeError("Invalid argument passed to Key constructor, should be instance of CryptoKey with type public");
		}

		if (key && !alg) {
			if (key.algorithm) {
				alg = key.algorithm;
			} else {
				throw new TypeError("Key cannot be supplied without algorithm");
			}
		}
		this._key = key;
		this._alg = alg;
		this._keyinfo = undefined;
	}

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
			ber = coerceToArrayBuffer(base64ber, "base64ber");
		} else {
			throw new Error("Supplied key is not in PEM format");
		}

		if (ber.byteLength === 0) {
			throw new Error("Supplied key ber was empty (0 bytes)");
		}

		// Extract x509 information
		// ToDo: Extract algorithm from key info, and pass on
		this._keyInfo = getKeyInfo(ber);
		const algorithm = {};

		// ToDo: Support for more formats?
		// Handle ECDSA
		if (this._keyInfo.algorithm.algorithmId === "1.2.840.10045.2.1") {
			algorithm.name = "ECDSA";

			// Use parsedKey to extract namedCurve if present, else default to P-256
			const parsedKey = this._keyInfo.parsedKey;
			if (parsedKey && parsedKey.namedCurve === "1.2.840.10045.3.1.7") {
				algorithm.namedCurve = "P-256";
			} else {
				algorithm.namedCurve = "P-256";
			}

			// Handle RSA
		} else if (this._keyInfo.algorithm.algorithmId === "1.2.840.113549.1.1.1") {
			algorithm.name = "RSASSA-PKCS1-v1_5";

			// Default hash to SHA-256
			algorithm.hash = hashName || "SHA-256";
		}

		let importSPKIResult;
		try {
			importSPKIResult = await tools.webcrypto.subtle.importKey("spki", ber, algorithm, true, ["verify"]);
		} catch (_e1) {
			throw new Error("Unsupported key format", _e1, _e2);
		}
		this._original_pem = pem;
		this._key = importSPKIResult;
		this._alg = algorithm;
		return this._key;
	}

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
		this._alg = jwkToAlgorithm(jwkCopy);

		// Import jwk with Jose
		this._original_jwk = jwk;
		const generatedKey = await tools.importJWK(
			jwkCopy,
			algMap[jwkCopy.alg] || jwkCopy.alg,
		);
		this._key = generatedKey;
		return this._key;
	}

	async fromCose(cose) {
		if (typeof cose !== "object") {
			throw new TypeError(
				"'cose' argument must be an object, probably an Buffer conatining valid COSE",
			);
		}

		this._cose = coerceToArrayBuffer(cose, "coseToJwk");

		let parsedCose;
		try {
			parsedCose = tools.cbor.decode(new Uint8Array(cose));
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

		const keyParams = keyParamList[retKey.kty];

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

		// Import key from jwk
		this._original_cose = cose;

		await this.fromJWK(retKey, true);
		return this._key;
	}

	async toPem(forcedExport) {
		if (this._original_pem && !forcedExport) {
			return this._original_pem;
		} else if (this.getKey()) {
			let pemResult = await tools.exportSPKI(this.getKey());

			// Add trailing \n if missing (Deno only)
			if (pemResult[pemResult.length - 1] !== "\n") {
				pemResult += "\n";
			}

			return pemResult;
		} else {
			throw new Error("No key information available");
		}
	}

	toJwk() {
		if (this._original_jwk) {
			return this._original_jwk;
		} else {
			throw new Error("No usable key information available");
		}
	}

	toCose() {
		if (this._original_cose) {
			return this._original_cose;
		} else {
			throw new Error("No usable key information available");
		}
	}

	getKey() {
		if (this._key) {
			return this._key;
		} else {
			throw new Error("Key data not available");
		}
	}

	getAlgorithm() {
		return this._alg;
	}
}

export { algToHashStr, algToStr, Key };
