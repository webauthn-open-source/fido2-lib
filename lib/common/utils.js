import { base64 } from "./tools/base64/base64.js";
import { coseToJwk } from "../common/tools/cose-to-jwk/cose-to-jwk.js";

function abToStr(buf) {
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

	let pemRegex = /^-----BEGIN .+-----$\n([A-Za-z0-9+/=]|\n)*^-----END .+-----$/m;
	return !!pem.match(pemRegex);
}

function pemToBase64(pem) {
	if (!isPem(pem)) {
		throw new Error("expected PEM string as input");
	}

	let pemArr = pem.split("\n");
	// remove first and last lines
	pemArr = pemArr.slice(1, pemArr.length - 2);
	return pemArr.join("");
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

	let buf = new Uint8Array(ab);
	let cnt = ab.byteLength - 1;
	let ret = 0;
	buf.forEach((byte) => {
		ret |= (byte << (cnt * 8));
		cnt--;
	});

	return ret;
}

function abToPem(type, ab) {
	if (typeof type !== "string") {
		throw new Error("abToPem expected 'type' to be string like 'CERTIFICATE', got: " + type);
	}

	let str = coerceToBase64(ab, "pem buffer");

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
let appendBuffer = function(buffer1, buffer2) {
	let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
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
		buf = buf.replace(/\+/g, "-").replace(/\//g, "_").replace("=","");
		// base64 to Buffer
		buf = base64.toArrayBuffer(buf, true);
	}

	// Extract typed array from Array
	if(Array.isArray(buf)) {
		buf = new Uint8Array(buf);
	}

	// Extract ArrayBuffer from Node buffer
	if (typeof Buffer !== "undefined" && buf instanceof Buffer) {
		buf = new Uint8Array(buf);
		buf = buf.buffer;
	}

	// Extract arraybuffer from TypedArray
	if(buf instanceof Uint8Array) {
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
			thing = base64.fromArrayBuffer(coerceToArrayBuffer(thing, name));
		} catch (e) {
			throw new Error(`could not coerce '${name}' to string`);
		}
	}

	if (typeof thing !== "string") {
		throw new Error(`could not coerce '${name}' to string`);
	}

	return thing;
}

function strToAb(str) {
	let buf = new ArrayBuffer(str.length);
	let bufView = new Uint8Array(buf);
	for (let i = 0, strLen = str.length; i < strLen; i++) {
		bufView[i] = str.charCodeAt(i);
	}
	return buf;
}

function coerceToBase64Url(thing, name) {

	if (!name) {
		throw new TypeError("name not specified in coerceToBase64");
	}
	
	if (typeof thing !== "string") {
		try {
			thing = base64.fromArrayBuffer(coerceToArrayBuffer(thing, name), true);
		} catch (e) {
			throw new Error(`could not coerce '${name}' to string`);
		}
	}

	if (typeof thing !== "string") {
		throw new Error(`could not coerce '${name}' to string`);
	}
	
	return thing;
}

// Merged with previous abEqual
function abEqual(b1, b2) {
	if (!(b1 instanceof ArrayBuffer) ||
            !(b2 instanceof ArrayBuffer)) {
		console.log("not array buffers");
		return false;
	}

	if (b1.byteLength !== b2.byteLength) {
		console.log("not same length");
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
		new Uint8Array(ab),	x => ("00" + x.toString(16)).slice(-2)
	).join("");

	return result;
}

function tools() {
	if (typeof window !== "undefined" && window.webauthnToolBox) {
		return window.webauthnToolBox;
	} else if (typeof global !== "undefined" && global.webauthnToolBox) {
		return global.webauthnToolBox;
	} else {
		//console.log('wat', global.watWat);
		throw new Error("Webauthn global ToolBox not registered");
	}	
}

function b64ToJsObject(b64, desc) {
	return JSON.parse(abToStr(coerceToArrayBuffer(b64, desc)));
}

function jsObjectToB64(obj) {
	return base64.fromString(JSON.stringify(obj).replace(/[\u{0080}-\u{FFFF}]/gu,""));
}

export {
	abToStr,
	abToBuf,
	abToPem,
	abToInt,
	abToHex,
	abEqual,
	strToAb,
	isBase64Url,
	isPem,
	isPositiveInteger,
	appendBuffer,
	coerceToArrayBuffer,
	base64,
	coerceToBase64Url,
	coerceToBase64,
	coseToJwk,
	pemToBase64,
	tools,
	b64ToJsObject,
	jsObjectToB64
};
