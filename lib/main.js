"use strict";

const crypto = require("crypto");
const {
	Fido2AttestationResult,
	Fido2AssertionResult,
} = require("./response");
const {
	coerceToArrayBuffer,
	abToBuf,
	printHex,
} = require("./utils");
const {
	MdsCollection,
} = require("./mds");

var globalAttestationMap = new Map();
var globalExtensionMap = new Map();
var globalMdsCollection = new Map();

/**
 * The main FIDO2 server class
 */
class Fido2Lib {
	/**
    * Creates a FIDO2 server class
    * @param {Object} opts Options for the server
    * @param {Number} [opts.timeout=60000] The amount of time to wait, in milliseconds, before a call has timed out
    * @param {String} [opts.rpId="localhost"] The name of the server
    * @param {String} [opts.rpName="Anonymous Service"] The name of the server
    * @param {String} [opts.rpIcon] A URL for the service's icon. Can be a [RFC 2397]{@link https://tools.ietf.org/html/rfc2397} data URL.
    * @param {Number} [opts.challengeSize=64] The number of bytes to use for the challenge
    * @param {Object} [opts.authenticatorSelectionCriteria] An object describing what types of authenticators are allowed to register with the service.
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
			throw new RangeError("challenge size too small, must be 32 or greater");
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
		if (this.config.authenticatorAttachment !== undefined &&
            (this.config.authenticatorAttachment !== "platform" &&
            this.config.authenticatorAttachment !== "cross-platform")) {
			throw new TypeError("expected authenticatorAttachment to be 'platform', or 'cross-platform', got: " + this.config.authenticatorAttachment);
		}

		// authenticatorUserVerification
		this.config.authenticatorUserVerification = opts.authenticatorUserVerification;
		if (this.config.authenticatorUserVerification !== undefined &&
            (this.config.authenticatorUserVerification !== "required" &&
            this.config.authenticatorUserVerification !== "preferred" &&
            this.config.authenticatorUserVerification !== "discouraged")) {
			throw new TypeError("expected authenticatorUserVerification to be 'required', 'preferred', or 'discouraged', got: " + this.config.authenticatorUserVerification);
		}

		// attestation
		this.config.attestation = opts.attestation || "direct";
		if (this.config.attestation !== "direct" &&
            this.config.attestation !== "indirect" &&
            this.config.attestation !== "none") {
			throw new TypeError("expected attestation to be 'direct', 'indirect', or 'none', got: " + this.config.attestation);
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
		var challenge = crypto.randomBytes(this.config.challengeSize);
		challenge = coerceToArrayBuffer(challenge, "challenge");
		var pubKeyCredParams = [];
		this.config.cryptoParams.forEach((coseId) => {
			pubKeyCredParams.push({
				type: "public-key",
				alg: coseId });
		});

		// mix extraData into challenge
		let rawChallenge;
		if (opts.extraData) {
			rawChallenge = challenge;
			let extraData = coerceToArrayBuffer(opts.extraData, "extraData");
			let hash = crypto.createHash("sha256");
			hash.update(abToBuf(challenge));
			hash.update(abToBuf(extraData));
			challenge = new Uint8Array(hash.digest()).buffer;
		}

		var options = {
			rp: {},
			user: {},
		};

		var extensions = createExtensions.call(this, "attestation", opts.extensionOptions);

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
         * @property {Object} [authenticatorSelectionCriteria] A object describing which authenticators are preferred for registration
         * @property {String} [authenticatorSelectionCriteria.attachment] What type of attachement is acceptable for new authenticators.
         * Allowed values are "platform", meaning that the authenticator is embedded in the operating system, or
         * "cross-platform", meaning that the authenticator is removeable (e.g. USB, NFC, or BLE).
         * @property {Boolean} [authenticatorSelectionCriteria.requireResidentKey] Indicates whether authenticators must store the keys internally, or if they can
         * store them externally (using a KDF or key wrapping)
         * @property {String} [authenticatorSelectionCriteria.userVerification] Indicates whether user verification is required for authenticators. User verification
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
		if (this.config.authenticatorAttachment !== undefined ||
            this.config.authenticatorRequireResidentKey !== undefined ||
            this.config.authenticatorUserVerification !== undefined) {
			options.authenticatorSelection = {};
			setOpt(options.authenticatorSelection, "authenticatorAttachment", this.config.authenticatorAttachment);
			setOpt(options.authenticatorSelection, "requireResidentKey", this.config.authenticatorRequireResidentKey);
			setOpt(options.authenticatorSelection, "userVerification", this.config.authenticatorUserVerification);
		}
		setOpt(options, "rawChallenge", rawChallenge);

		if (Object.keys(extensions).length > 0) {
			options.extensions = extensions;
		}

		return options;
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
		return Fido2AttestationResult.create(res, expected);
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
		var challenge = crypto.randomBytes(this.config.challengeSize);
		challenge = coerceToArrayBuffer(challenge, "challenge");
		var options = {};

		// mix extraData into challenge
		let rawChallenge;
		if (opts.extraData) {
			rawChallenge = challenge;
			let extraData = coerceToArrayBuffer(opts.extraData, "extraData");
			let hash = crypto.createHash("sha256");
			hash.update(abToBuf(challenge));
			hash.update(abToBuf(extraData));
			challenge = new Uint8Array(hash.digest()).buffer;
		}

		var extensions = createExtensions.call(this, "assertion", opts.extensionOptions);

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
		setOpt(options, "userVerification", this.config.authenticatorUserVerification);

		setOpt(options, "rawChallenge", rawChallenge);

		if (Object.keys(extensions).length > 0) {
			options.extensions = extensions;
		}

		return options;
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
	async assertionResult(res, expected) {
		expected.flags = factorToFlags(expected.factor, []);
		delete expected.factor;
		return Fido2AssertionResult.create(res, expected);
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
			throw new TypeError("expected 'fmt' to be string, got: " + typeof fmt);
		}

		if (typeof parseFn !== "function") {
			throw new TypeError("expected 'parseFn' to be string, got: " + typeof parseFn);
		}

		if (typeof validateFn !== "function") {
			throw new TypeError("expected 'validateFn' to be string, got: " + typeof validateFn);
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
			throw new TypeError("expected 'fmt' to be string, got: " + typeof fmt);
		}

		if (typeof attStmt !== "object") {
			throw new TypeError("expected 'attStmt' to be object, got: " + typeof attStmt);
		}

		// get from attestationMap
		var fmtObj = globalAttestationMap.get(fmt);
		if (typeof fmtObj !== "object" ||
            typeof fmtObj.parseFn !== "function" ||
            typeof fmtObj.validateFn !== "function") {
			throw new Error(`no support for attestation format: ${fmt}`);
		}

		// call fn
		var ret = fmtObj.parseFn.call(this, attStmt);

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
     * Validates an attestation response. Will be called within the context (`this`) of a {@link Fido2AttestationResult}
     * @private
     */
	static async validateAttestation() {
		var fmt = this.authnrData.get("fmt");

		// validate input
		if (typeof fmt !== "string") {
			throw new TypeError("expected 'fmt' to be string, got: " + typeof fmt);
		}

		// get from attestationMap
		var fmtObj = globalAttestationMap.get(fmt);
		if (typeof fmtObj !== "object" ||
            typeof fmtObj.parseFn !== "function" ||
            typeof fmtObj.validateFn !== "function") {
			throw new Error(`no support for attestation format: ${fmt}`);
		}

		// call fn
		var ret = await fmtObj.validateFn.call(this);

		// validate return
		if (ret !== true) {
			throw new Error(`${fmt} validateFn did not return 'true'`);
		}

		// return result
		return ret;
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
	static addMdsCollection(mdsCollection) {
		if (!(mdsCollection instanceof MdsCollection)) {
			throw new Error("expected 'mdsCollection' to be instance of MdsCollection, got: " + mdsCollection);
		}
		mdsCollection.validate();
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
			throw new Error("must set MDS collection before attempting to find an MDS entry");
		}

		var ret = [];
		for (let collection of globalMdsCollection.values()) {
			let entry = collection.findEntry(id);
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
	static addExtension(extName, optionGeneratorFn, resultParserFn, resultValidatorFn) {
		if (typeof extName !== "string") {
			throw new Error("expected 'extName' to be String, got: " + extName);
		}

		if (globalExtensionMap.has(extName)) {
			throw new Error(`the extension '${extName}' has already been added`);
		}

		if (typeof optionGeneratorFn !== "function") {
			throw new Error("expected 'optionGeneratorFn' to be a Function, got: " + optionGeneratorFn);
		}

		if (typeof resultParserFn !== "function") {
			throw new Error("expected 'resultParserFn' to be a Function, got: " + resultParserFn);
		}

		if (typeof resultValidatorFn !== "function") {
			throw new Error("expected 'resultValidatorFn' to be a Function, got: " + resultValidatorFn);
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
			throw new Error("expected 'type' to be 'attestation' or 'assertion', got: " + type);
		}

		var ext = globalExtensionMap.get(extName);
		if (typeof ext !== "object" ||
            typeof ext.optionGeneratorFn !== "function") {
			throw new Error(`valid extension for '${extName}' not found`);
		}
		var ret = ext.optionGeneratorFn(extName, type, options);

		return ret;
	}

	static parseExtensionResult(extName, clientThing, authnrThing) {
		if (typeof extName !== "string") {
			throw new Error("expected 'extName' to be String, got: " + extName);
		}

		var ext = globalExtensionMap.get(extName);
		if (typeof ext !== "object" ||
            typeof ext.parseFn !== "function") {
			throw new Error(`valid extension for '${extName}' not found`);
		}
		var ret = ext.parseFn(extName, clientThing, authnrThing);

		return ret;
	}

	static validateExtensionResult(extName) {
		var ext = globalExtensionMap.get(extName);
		if (typeof ext !== "object" ||
            typeof ext.validateFn !== "function") {
			throw new Error(`valid extension for '${extName}' not found`);
		}
		var ret = ext.validateFn.call(this);

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
}

function checkOptType(opts, prop, type) {
	if (typeof opts !== "object") return;

	// undefined
	if (opts[prop] === undefined) return;

	// native type
	if (typeof type === "string") {
		if (typeof opts[prop] !== type) {
			throw new TypeError(`expected ${prop} to be ${type}, got: ${opts[prop]}`);
		}
	}

	// class type
	if (typeof type === "function") {
		if (!(opts[prop] instanceof type)) {
			throw new TypeError(`expected ${prop} to be ${type.name}, got: ${opts[prop]}`);
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
			throw new TypeError("expectedFactor should be 'first', 'second' or 'either'");
	}

	return flags;
}

function createExtensions(type, extObj) {
	/* eslint-disable no-invalid-this */
	var extensions = {};

	// default extensions
	var enabledExtensions = this.extSet;
	var extensionsOptions = this.extOptMap;

	// passed in extensions
	if (typeof extObj === "object") {
		enabledExtensions = new Set(Object.keys(extObj));
		extensionsOptions = new Map();
		for (let key of Object.keys(extObj)) {
			extensionsOptions.set(key, extObj[key]);
		}
	}

	// generate extension values
	for (let extension of enabledExtensions) {
		let extVal = this.generateExtensionOptions(extension, type, extensionsOptions.get(extension));
		if (extVal !== undefined) extensions[extension] = extVal;
	}

	return extensions;
}

// add 'none' attestation format
const noneAttestation = require("./attestations/none");
Fido2Lib.addAttestationFormat(
	noneAttestation.name,
	noneAttestation.parseFn,
	noneAttestation.validateFn
);

// add 'fido-u2f' attestation format
const u2fAttestation = require("./attestations/fidoU2F");
Fido2Lib.addAttestationFormat(
	u2fAttestation.name,
	u2fAttestation.parseFn,
	u2fAttestation.validateFn
);

// add 'packed' attestation format
const packedAttestation = require("./attestations/packed");
Fido2Lib.addAttestationFormat(
	packedAttestation.name,
	packedAttestation.parseFn,
	packedAttestation.validateFn
);

// add 'tpm' attestation format
const tpmAttestation = require("./attestations/tpm");
Fido2Lib.addAttestationFormat(
	tpmAttestation.name,
	tpmAttestation.parseFn,
	tpmAttestation.validateFn
);

// add 'android-safetynet' attestation format
const androidSafetyNetAttestation = require("./attestations/androidSafetyNet");
Fido2Lib.addAttestationFormat(
	androidSafetyNetAttestation.name,
	androidSafetyNetAttestation.parseFn,
	androidSafetyNetAttestation.validateFn
);


module.exports = {
	Fido2Lib,
};
