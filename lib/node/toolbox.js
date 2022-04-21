import * as crypto from "crypto";
import { URL } from "url";
import jwkToPem from "jwk-to-pem"; // CommonJS
import { parse as tldtsParse } from "tldts";
import { fromBER } from "asn1js";
import * as pkijs from "pkijs";
import * as cbor from "cbor-x";
import * as punycode from "punycode";
import * as jose from "node-jose";

function checkOrigin(str) {

	let originUrl = new URL(str);
	let origin = originUrl.origin;

	if (origin !== str) {
		throw new Error("origin was malformatted");
	}

	let isLocalhost = (originUrl.hostname == "localhost" || originUrl.hostname.endsWith(".localhost"));

	if (originUrl.protocol !== "https:" && !isLocalhost) {
		throw new Error("origin should be https");
	}

	if ((!validDomainName(originUrl.hostname) || !validEtldPlusOne(originUrl.hostname)) && !isLocalhost) {
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
	} catch (err) {
		throw new Error(`${name} is not a valid eTLD+1/url`);
	}

	if (!value.startsWith("http")) {
		throw new Error(`${name} must be http protocol`);
	}

	if (!rules.allowHttp && urlValue.protocol !== "https:") {
		throw new Error(`${name} should be https`);
	}

	// origin: base url without path including /
	if (!rules.allowPath && (value.endsWith("/") || urlValue.pathname !== "/")) { // urlValue adds / in path always
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
	const result = tldtsParse(value, { allowPrivateDomains: true });

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
	let ascii = punycode.encode(value);

	if (ascii.length < 1) {
		// return 'DOMAIN_TOO_SHORT';
		return false;
	}
	if (ascii.length > 255) {
		// return 'DOMAIN_TOO_LONG';
		return false;
	}
	
	// Check each part's length and allowed chars.
	let labels = ascii.split(".");
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
		/*if (label.charAt(label.length - 1) === '-') {
			// LABEL_ENDS_WITH_DASH
			return false;
		}*/
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

	if (validEtldPlusOne(value, name) && validDomainName(value, name)) return value; // if valid domain no need for futher checks

	return checkUrl(value, name, rules);
}

function checkRpId(rpId) {
	if (typeof rpId !== "string") {
		throw new Error("rpId must be a string");
	}

	let isLocalhost = (rpId === "localhost" || rpId.endsWith(".localhost"));

	if (isLocalhost) return rpId;

	return checkDomainOrUrl(rpId, "rpId");
}

function verifySignature(publicKey, expectedSignature, data, hashName) {
	const verify = crypto.createVerify(hashName || "SHA256");
	verify.write(new Uint8Array(data));
	verify.end();
	return verify.verify(publicKey, new Uint8Array(expectedSignature));
}

async function hashDigest(o, alg) {
	if (typeof o === "string") {
		o = new TextEncoder().encode(o);
	}
	let hash = crypto.createHash(alg || "sha256");
	hash.update(new Uint8Array(o));
	return new Uint8Array(hash.digest());
}

function randomValues(n) {
	return crypto.randomBytes(n);
}

function getHostname(urlIn) {
	return new URL(urlIn).hostname;
}

const envUnified = (typeof window !== "undefined") ? window.env : process.env;

let webcrypto;

/*

Disabled due to top level await not supported by rollup, for creating the cjs module

if(envUnified.FIDO2LIB_USENATIVECRYPTO) {
	// Opt-in to use native crypto, as it depends on the environment and is difficult to test
	// NodeJS crypto API is currently in experimental state
	console.warn("[FIDO2-LIB] Native crypto is enabled");
	// ToDo: Clarify where self.crypto is ever defined?
	if ((typeof self !== "undefined") && "crypto" in self) {
		webcrypto = self.crypto;
	} else {
		webcrypto = await import("crypto").webcrypto;
	}
} else {
	const { Crypto } = await import("@peculiar/webcrypto");
	webcrypto = new Crypto();
}*/

import { Crypto } from "@peculiar/webcrypto";
webcrypto = new Crypto();

const jwsCreateVerify = jose.default.JWS.createVerify;

const ToolBox = {
	checkOrigin,
	checkRpId,
	checkDomainOrUrl,
	checkUrl,
	verifySignature,
	jwkToPem,
	hashDigest,
	randomValues,
	getHostname,
	webcrypto,
	fromBER,
	pkijs,
	cbor,
	jwsCreateVerify,
};

const ToolBoxRegistration = {
	registerAsGlobal: () => {
		global.webauthnToolBox = ToolBox;
	},
};

export { ToolBoxRegistration, ToolBox };