import { coerceToArrayBuffer, coerceToBase64Url, isPem, pemToBase64, abToPem, tools } from "./utils.js";

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
			ber = coerceToArrayBuffer(base64ber, "base64ber");
		} else {
			throw new Error("Supplied key is not in PEM format");
		}

		if (ber.byteLength === 0) {
			throw new Error("Supplied key ber was empty (0 bytes)");
		}

		// Extract x509 information
		const asn1 = tools.fromBER(ber);
		if (asn1.offset === -1) {
			throw new Error("error parsing ASN.1");
		}
		let keyInfo = new tools.pkijs.PublicKeyInfo({ schema: asn1.result });
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
			importSPKIResult = await tools.webcrypto.subtle.importKey("spki", ber, algorithm, true, ["verify"]);
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

		const generatedKey = await tools.webcrypto.subtle.importKey(
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

		this._cose = coerceToArrayBuffer(cose, "coseToJwk");

		let parsedCose;
		try {
			// In the current state, the "cose" parameter can contain not only the actual cose (= public key) but also extensions.
			// Both are CBOR encoded entries, so you can treat and evaluate the "cose" parameter accordingly.
			// "fromCose" is called from a context that contains an active AT flag (attestation), so the first CBOR entry is the actual cose.
			// "tools.cbor.decode" will fail when multiple entries are provided (e.g. cose + at least one extension), so "decodeMultiple" is the sollution.
			tools.cbor.decodeMultiple(
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
			let pemResult = abToPem("PUBLIC KEY",await tools.webcrypto.subtle.exportKey("spki", this.getKey()));

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
				algorithmOutput.hash = { name: algorithmInput.hash };;
			}
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


export { PublicKey, coseAlgToStr, coseAlgToHashStr };
