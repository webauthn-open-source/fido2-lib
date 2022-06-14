import * as tools from "./toolbox.js";

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

function abToBuf(ab) {
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
const appendBuffer = function(buffer1, buffer2) {
	const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
	tmp.set(new Uint8Array(buffer1), 0);
	tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
	return tmp.buffer;
};

function coerceToArrayBuffer(buf, name) {
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
		buf = tools.base64.toArrayBuffer(buf, true);
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
			thing = tools.base64.fromArrayBuffer(
				coerceToArrayBuffer(thing, name),
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
			thing = tools.base64.fromArrayBuffer(
				coerceToArrayBuffer(thing, name),
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
	return JSON.parse(ab2str(coerceToArrayBuffer(b64, desc)));
}

function jsObjectToB64(obj) {
	return tools.base64.fromString(
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

export {
	arrayBufferEquals,
	abToBuf,
	abToHex,
	abToInt,
	abToPem,
	ab2str,
	appendBuffer,
	b64ToJsObject,
	coerceToArrayBuffer,
	coerceToBase64,
	coerceToBase64Url,
	isBase64Url,
	isPem,
	isPositiveInteger,
	jsObjectToB64,
	pemToBase64,
	str2ab,
	tools
};
