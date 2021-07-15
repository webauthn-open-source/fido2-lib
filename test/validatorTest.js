"use strict";

const validator = require("../lib/validator");
const parser = require("../lib/parser");
const chai = require("chai");
var chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
var assert = chai.assert;
const h = require("fido2-helpers");
const { coerceToArrayBuffer } = require("../lib/utils");
const {
	printHex,
	cloneObject,
} = h.functions;

var attResp;

var runs = [
	{ functionName: "parseAuthnrAttestationResponse" },
	{ functionName: "parseAttestationObject" },
];

describe("attestation validation", function() {

	runs.forEach(function(run) {

		describe("parsing attestation with " + run.functionName, function() {

			beforeEach(function() {
				attResp = {
					request: {},
					requiredExpectations: new Set([
						"origin",
						"challenge",
						"flags",
					]),
					optionalExpectations: new Set([
						"rpId",
						"allowCredentials",
					]),
					expectations: new Map([
						["origin", "https://localhost:8443"],
						["challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w"],
						["flags", ["UP", "AT"]],
					]),
					clientData: parser.parseClientResponse(h.lib.makeCredentialAttestationNoneResponse),
					authnrData: run.functionName == "parseAuthnrAttestationResponse" ? parser[run.functionName](h.lib.makeCredentialAttestationNoneResponse) :  parser[run.functionName](h.lib.makeCredentialAttestationNoneResponse.response.attestationObject),
				};
				var testReq = cloneObject(h.lib.makeCredentialAttestationNoneResponse);
				testReq.rawId = h.lib.makeCredentialAttestationNoneResponse.rawId;
				testReq.response.clientDataJSON = h.lib.makeCredentialAttestationNoneResponse.response.clientDataJSON.slice(0);
				testReq.response.attestationObject = h.lib.makeCredentialAttestationNoneResponse.response.attestationObject.slice(0);
				attResp.request = testReq;

				validator.attach(attResp);
			});

			it("returns object", function() {
				assert.isObject(validator);
			});

			it("is attached", function() {
				assert.isFunction(validator.attach);
				assert.isFunction(attResp.validateOrigin);
				assert.isFunction(attResp.validateAttestation);
			});

			describe("validateExpectations", function() {
				it("returns true on valid expectations", async function() {
					var ret = await attResp.validateExpectations();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validExpectations);
				});

				it("throws if expectations aren't found", function() {
					delete attResp.expectations;
					return assert.isRejected(attResp.validateExpectations(), Error, "expectations should be of type Map");
				});

				it("throws if expectations aren't Map", function() {
					attResp.expectations = {};
					return assert.isRejected(attResp.validateExpectations(), Error, "expectations should be of type Map");
				});

				it("throws if optionalExpectations aren't Set", function() {
					attResp.optionalExpectations = { rpId: true };
					return assert.isRejected(attResp.validateExpectations(), Error, "optionalExpectations should be of type Set");
				});

				it("should not throw if  optionalExpectations are array", async function() {
					attResp.optionalExpectations = ["rpId"];
					assert.isFulfilled(attResp.validateExpectations());
				});

				it("throws if too many expectations", function() {
					attResp.expectations.set("foo", "bar");
					return assert.isRejected(attResp.validateExpectations(), Error, "wrong number of expectations: should have 3 but got 4");
				});

				it("throws if too many expectations, but expectations are valid", function() {
					attResp.expectations.set("prevCounter", 42);
					return assert.isRejected(attResp.validateExpectations(), Error, "wrong number of expectations: should have 3 but got 4");
				});

				it("throws if missing challenge", function() {
					attResp.expectations.delete("challenge");
					return assert.isRejected(attResp.validateExpectations(), Error, "expectation did not contain value for 'challenge'");
				});

				it("throws if missing flags", function() {
					attResp.expectations.delete("flags");
					return assert.isRejected(attResp.validateExpectations(), Error, "expectation did not contain value for 'flags'");
				});

				it("throws if missing origin", function() {
					attResp.expectations.delete("origin");
					return assert.isRejected(attResp.validateExpectations(), Error, "expectation did not contain value for 'origin'");
				});

				it("throws if challenge is undefined", function() {
					attResp.expectations.set("challenge", undefined);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected challenge should be of type String, got: undefined");
				});

				it("throws if challenge isn't string", function() {
					attResp.expectations.set("challenge", { foo: "bar" });
					return assert.isRejected(attResp.validateExpectations(), Error, "expected challenge should be of type String, got: object");
				});

				it("throws if challenge isn't base64 encoded string", function() {
					attResp.expectations.set("challenge", "miles&me");
					return assert.isRejected(attResp.validateExpectations(), Error, "expected challenge should be properly encoded base64url String");
				});

				it("calls checkOrigin");

				it("returns true if flags is Set", async function() {
					attResp.expectations.set("flags", new Set(["UP", "AT"]));
					var ret = await attResp.validateExpectations();
					assert.isTrue(ret);
				});

				it("throws if Set contains non-string", function() {
					attResp.expectations.set("flags", new Set([3, "UP", "AT"]));
					return assert.isRejected(attResp.validateExpectations(), Error, "expected flag unknown: 3");
				});

				it("throws if Array contains non-string", function() {
					attResp.expectations.set("flags", [3, "UP", "AT"]);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected flag unknown: 3");
				});

				it("throws on unknown flag", function() {
					attResp.expectations.set("flags", new Set(["foo", "UP", "AT"]));
					return assert.isRejected(attResp.validateExpectations(), Error, "expected flag unknown: foo");
				});

				it("throws on undefined flag", function() {
					attResp.expectations.set("flags", new Set([undefined, "UP", "AT"]));
					return assert.isRejected(attResp.validateExpectations(), Error, "expected flag unknown: undefined");
				});

				it("throws on invalid rpId type", function() {
					attResp.expectations.set("rpId", 123);
					return assert.isRejected(attResp.validateExpectations(), Error, "rpId must be a string");
				});

				it("throws on invalid rpId", function() {
					attResp.expectations.set("rpId", "test");
					return assert.isRejected(attResp.validateExpectations(), Error, "rpId is not a valid eTLD+1");
				});

				it("works with valid rpId", async function() {
					attResp.expectations.set("rpId", "google.com");
					var ret = await attResp.validateExpectations();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validExpectations);
				});

				it("works with localhost rpId", async function() {
					attResp.expectations.set("rpId", "localhost");
					var ret = await attResp.validateExpectations();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validExpectations);
				});

				it("works with valid allowCredentials", async function() {
					attResp.expectations.set("allowCredentials", [{ id: h.lib.assertionResponse.rawId, type: "public-key", transports: ["usb", "nfc"] }]);
					var ret = await attResp.validateExpectations();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validExpectations);
				});

				it("works with null allowCredentials", async function() {
					attResp.expectations.set("allowCredentials", null);
					var ret = await attResp.validateExpectations();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validExpectations);
				});

				it("throws on wrong allowCredentials type", function() {
					attResp.expectations.set("allowCredentials", { type: "public-key", transports: ["usb", "nfc"] });
					return assert.isRejected(attResp.validateExpectations(), Error, "expected allowCredentials to be null or array");
				});

				it("throws on missing id in allowCredentials", function() {
					attResp.expectations.set("allowCredentials", [{ type: "public-key", transports: ["usb", "nfc"] }]);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected id of allowCredentials[0] to be ArrayBuffer");
				});

				it("throws on null id in allowCredentials", function() {
					attResp.expectations.set("allowCredentials", [{ id: {}, type: "public-key", transports: ["usb", "nfc"] }]);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected id of allowCredentials[0] to be ArrayBuffer");
				});

				it("throws on wrong type of id in allowCredentials", function() {
					attResp.expectations.set("allowCredentials", [{ id: {}, type: "public-key", transports: ["usb", "nfc"] }]);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected id of allowCredentials[0] to be ArrayBuffer");
				});

				it("throws on missing type in allowCredentials element", function() {
					attResp.expectations.set("allowCredentials", [{ id: h.lib.assertionResponse.rawId, transports: ["usb", "nfc"] }]);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected type of allowCredentials[0] to be string with value 'public-key'");
				});

				it("throws on wrong type value in allowCredentials element", function() {
					attResp.expectations.set("allowCredentials", [{ id: h.lib.assertionResponse.rawId, type: "test", transports: ["usb", "nfc"] }]);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected type of allowCredentials[0] to be string with value 'public-key'");
				});

				it("throws on wrong transports type in allowCredentials element", function() {
					attResp.expectations.set("allowCredentials", [{ id: h.lib.assertionResponse.rawId, type: "public-key", transports: "test" }]);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected transports of allowCredentials[0] to be array or null");
				});

				it("throws on wrong transports value in allowCredentials element", function() {
					attResp.expectations.set("allowCredentials", [{ id: h.lib.assertionResponse.rawId, type: "public-key", transports: ["none", "nfc"] }]);
					return assert.isRejected(attResp.validateExpectations(), Error, "expected transports of allowCredentials[0] to be string with value 'usb', 'nfc', 'ble', 'internal' or null");
				});

				it("works with null transports in allowCredentials element", async function() {
					attResp.expectations.set("allowCredentials", [{ id: h.lib.assertionResponse.rawId, type: "public-key" }]);
					var ret = await attResp.validateExpectations();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validExpectations);
				});

				it("throws if counter is not a number");
				it("throws if counter is negative");
				it("throws if publicKey is not a string");
				it("throws if publicKey doesn't match PEM regexp");

				it("throws if requiredExpectations is undefined");
				it("throws if requiredExpectations is not Array or Set");
				it("passes if requiredExpectations is Array");
				it("passes if requiredExpectations is Set");
				it("throws if requiredExpectations field is missing");
				it("throws if more expectations were passed than requiredExpectations");
			});

			describe("validateCreateRequest", function() {
				it("returns true if request is valid", function() {
					var ret = attResp.validateCreateRequest();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validRequest);
				});

				it("returns true for U2F request", function() {
					var ret = attResp.validateCreateRequest();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validRequest);
				});

				it("throws if request is undefined", function() {
					attResp.request = undefined;
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected request to be Object, got undefined");
				});

				it("throws if response field is undefined", function() {
					delete attResp.request.response;
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected 'response' field of request to be Object, got undefined");
				});

				it("throws if response field is non-object", function() {
					attResp.request.response = 3;
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected 'response' field of request to be Object, got number");
				});

				it("throws if id field is undefined", function() {
					delete attResp.request.id;
					delete attResp.request.rawId;
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId undefined and id undefined");
				});

				it("throws if id field is non-string", function() {
					attResp.request.rawId = [];
					delete attResp.request.id;
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId object and id undefined");
				});

				it("throws if response.attestationObject is undefined", function() {
					delete attResp.request.response.attestationObject;
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected 'response.attestationObject' to be base64 String or ArrayBuffer");
				});

				it("throws if response.attestationObject is non-ArrayBuffer & non-String", function() {
					attResp.request.response.attestationObject = {};
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected 'response.attestationObject' to be base64 String or ArrayBuffer");
				});

				it("passes with response.attestationObject as ArrayBuffer", async function() {
					attResp.request.response.attestationObject = new ArrayBuffer();
					var ret = await attResp.validateCreateRequest();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validRequest);
				});

				it("passes with response.attestationObject as String", async function() {
					attResp.request.response.attestationObject = "";
					var ret = await attResp.validateCreateRequest();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validRequest);
				});

				it("throws if response.clientDataJSON is undefined", function() {
					delete attResp.request.response.clientDataJSON;
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
				});

				it("throws if response.clientDataJSON is non-ArrayBuffer & non-String", function() {
					attResp.request.response.clientDataJSON = {};
					assert.throws(() => {
						attResp.validateCreateRequest();
					}, TypeError, "expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
				});

				it("passes with response.clientDataJSON as ArrayBuffer", async function() {
					attResp.request.response.clientDataJSON = new ArrayBuffer();
					var ret = await attResp.validateCreateRequest();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validRequest);
				});

				it("passes with response.clientDataJSON as String", async function() {
					attResp.request.response.clientDataJSON = "";
					var ret = await attResp.validateCreateRequest();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.validRequest);
				});
			});

			describe("validateRawClientDataJson", function() {
				it("returns true if ArrayBuffer", async function() {
					var ret = await attResp.validateRawClientDataJson();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("rawClientDataJson"));
				});

				it("throws if missing", function() {
					attResp.clientData.delete("rawClientDataJson");
					return assert.isRejected(attResp.validateRawClientDataJson(), Error, "clientData clientDataJson should be ArrayBuffer");
				});

				it("throws if not ArrayBuffer", function() {
					attResp.clientData.set("rawClientDataJson", "foo");
					return assert.isRejected(attResp.validateRawClientDataJson(), Error, "clientData clientDataJson should be ArrayBuffer");
				});
			});

			describe("validateId", function() {
				it("returns true on ArrayBuffer", async function() {
					var ret = await attResp.validateId();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("rawId"));
				});

				it("throws on non-ArrayBuffer", function() {
					attResp.clientData.set("id", {});
					attResp.clientData.set("rawId", {});
					return assert.isRejected(attResp.validateId(), Error, "expected id to be of type ArrayBuffer");
				});

				it("throws on undefined", function() {
					attResp.clientData.set("id", undefined);
					attResp.clientData.set("rawId", undefined);
					return assert.isRejected(attResp.validateId(), Error, "expected id to be of type ArrayBuffer");
				});
			});

			describe("validateTransports", function() {
				it("returns true on array<string>", async function() {
					var ret = await attResp.validateTransports();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("transports"));
				});

				it("returns true on null", async function() {
					var ret = await attResp.validateTransports();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("transports"));
				});

				it("throws on non-Array", function() {
					attResp.authnrData.set("transports", "test");
					return assert.isRejected(attResp.validateTransports(), Error, "expected transports to be 'null' or 'array<string>'");
				});

				it("throws on non-Array<string>", function() {
					attResp.authnrData.set("transports", [1]);
					return assert.isRejected(attResp.validateTransports(), Error, "expected transports[0] to be 'string'");
				});

			});

			describe("validateOrigin", function() {
				it("accepts exact match", async function() {
					attResp.expectations.set("origin", "https://webauthn.bin.coffee:8080");
					attResp.clientData.set("origin", "https://webauthn.bin.coffee:8080");
					var ret = await attResp.validateOrigin();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("origin"));
				});

				it("throws on port mismatch", function() {
					attResp.expectations.set("origin", "https://webauthn.bin.coffee:8080");
					attResp.clientData.set("origin", "https://webauthn.bin.coffee:8443");
					return assert.isRejected(attResp.validateOrigin(), Error, "clientData origin did not match expected origin");
				});

				it("throws on domain mismatch", function() {
					attResp.expectations.set("origin", "https://webauthn.bin.coffee:8080");
					attResp.clientData.set("origin", "https://bin.coffee:8080");
					return assert.isRejected(attResp.validateOrigin(), Error, "clientData origin did not match expected origin");
				});

				it("throws on protocol mismatch", function() {
					attResp.expectations.set("origin", "http://webauthn.bin.coffee:8080");
					attResp.clientData.set("origin", "https://webauthn.bin.coffee:8080");
					return assert.isRejected(attResp.validateOrigin(), Error, "clientData origin did not match expected origin");
				});

				it("calls checkOrigin");
			});

			describe("checkOrigin", function() { });

			describe("validateCreateType", function() {
				it("returns true when 'webauthn.create'", async function() {
					var ret = await attResp.validateCreateType();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("type"));
				});

				it("throws when undefined", function() {
					attResp.clientData.set("type", undefined);
					return assert.isRejected(attResp.validateCreateType(), Error, "clientData type should be 'webauthn.create'");
				});

				it("throws on 'webauthn.get'", function() {
					attResp.clientData.set("type", "webauthn.get");
					return assert.isRejected(attResp.validateCreateType(), Error, "clientData type should be 'webauthn.create'");
				});

				it("throws on unknown string", function() {
					attResp.clientData.set("type", "asdf");
					return assert.isRejected(attResp.validateCreateType(), Error, "clientData type should be 'webauthn.create'");
				});
			});

			describe("validateGetType", function() {
				it("returns true when 'webauthn.get'", async function() {
					attResp.clientData.set("type", "webauthn.get");
					var ret = await attResp.validateGetType();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("type"));
				});

				it("throws when undefined", function() {
					attResp.clientData.set("type", undefined);
					return assert.isRejected(attResp.validateGetType(), Error, "clientData type should be 'webauthn.get'");
				});

				it("throws on 'webauthn.create'", function() {
					attResp.clientData.set("type", "webauthn.create");
					return assert.isRejected(attResp.validateGetType(), "clientData type should be 'webauthn.get'");
				});

				it("throws on unknown string", function() {
					attResp.clientData.set("type", "asdf");
					return assert.isRejected(attResp.validateGetType(), "clientData type should be 'webauthn.get'");
				});
			});

			describe("validateChallenge", function() {
				it("returns true if challenges match", async function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					var ret = await attResp.validateChallenge();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("challenge"));
				});

				it("accepts ending equal sign (1)", async function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					attResp.clientData.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w=");
					var ret = await attResp.validateChallenge();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("challenge"));
				});

				it("accepts ending equal signs (2)", async function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					attResp.clientData.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w==");
					var ret = await attResp.validateChallenge();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("challenge"));
				});

				it("throws on three equal signs", function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					attResp.clientData.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w===");
					return assert.isRejected(attResp.validateChallenge(), Error, "clientData challenge was not properly encoded base64url");
				});

				it("does not remove equal sign from middle of string", function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					attResp.clientData.set("challenge", "33EHav-jZ1v9qwH783aU-j0A=Rx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					return assert.isRejected(attResp.validateChallenge(), Error, "clientData challenge was not properly encoded base64url");
				});

				it("throws if challenge is not a string", function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					attResp.clientData.set("challenge", ["foo"]);
					return assert.isRejected(attResp.validateChallenge(), Error, "clientData challenge was not a string");
				});

				it("throws if challenge is base64url encoded", function() {
					attResp.expectations.set("challenge", "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg");
					attResp.clientData.set("challenge", "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg");
					return assert.isRejected(attResp.validateChallenge(), Error, "clientData challenge was not properly encoded base64url");
				});

				it("throws if challenge is not base64 string", function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					attResp.clientData.set("challenge", "miles&me");
					return assert.isRejected(attResp.validateChallenge(), Error, "clientData challenge was not properly encoded base64url");
				});

				it("throws on undefined challenge", function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					attResp.clientData.set("challenge", undefined);
					return assert.isRejected(attResp.validateChallenge(), Error, "clientData challenge was not a string");
				});

				it("throws on challenge mismatch", function() {
					attResp.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
					attResp.clientData.set("challenge", "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg");
					return assert.isRejected(attResp.validateChallenge(), Error, "clientData challenge mismatch");
				});
			});

			describe("validateRawAuthnrData", function() {
				it("returns true if ArrayBuffer", async function() {
					var ret = await attResp.validateRawAuthnrData();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("rawAuthnrData"));
				});

				it("throws if missing", function() {
					attResp.authnrData.delete("rawAuthnrData");
					return assert.isRejected(attResp.validateRawAuthnrData(), Error, "authnrData rawAuthnrData should be ArrayBuffer");
				});

				it("throws if not ArrayBuffer", function() {
					attResp.authnrData.set("rawAuthnrData", "foo");
					return assert.isRejected(attResp.validateRawAuthnrData(), Error, "authnrData rawAuthnrData should be ArrayBuffer");
				});
			});

			describe("validateAttestation", function() {
				it("accepts none", async function() {
					var ret = await attResp.validateAttestation();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("fmt"));
				});

				it("throws on unknown fmt", function() {
					attResp.authnrData.set("fmt", "asdf");
					return assert.isRejected(attResp.validateAttestation(), Error, "no support for attestation format: asdf");
				});

				it("throws on undefined fmt", function() {
					attResp.authnrData.delete("fmt");
					return assert.isRejected(attResp.validateAttestation(), Error, "expected 'fmt' to be string, got: undefined");
				});
			});

			describe("validateRpIdHash", function() {
				after(() => {
					attResp.expectations.delete("rpId");
				});

				it("returns true when matches", async function() {
					var ret = await attResp.validateRpIdHash();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("rpIdHash"));
				});

				it("throws when it doesn't match", function() {
					attResp.expectations.set("origin", "https://google.com");
					return assert.isRejected(attResp.validateRpIdHash(), Error, "authnrData rpIdHash mismatch");
				});

				it("throws when it doesn't match in case of invalid rpId", function() {
					attResp.expectations.set("origin", "localhost");
					attResp.expectations.set("rpId", "google.com");
					return assert.isRejected(attResp.validateRpIdHash(), Error, "authnrData rpIdHash mismatch");
				});

				it("throws when length mismatches", function() {
					attResp.authnrData.set("rpIdHash", new Uint8Array([1, 2, 3]).buffer);
					return assert.isRejected(attResp.validateRpIdHash(), Error, "authnrData rpIdHash length mismatch");
				});
			});

			describe("validateAaguid", function() {
				it("returns true on validation", async function() {
					var ret = await attResp.validateAaguid();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("aaguid"));
				});

				it("throws if too short", function() {
					attResp.authnrData.set("aaguid", new Uint8Array([1, 2, 3]).buffer);
					return assert.isRejected(attResp.validateAaguid(), Error, "authnrData AAGUID was wrong length");
				});
			});

			describe("validateCredId", function() {
				it("returns true when ArrayBuffer of correct length", async function() {
					var ret = await attResp.validateCredId();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("credId"));
					assert.isTrue(attResp.audit.journal.has("credIdLen"));
				});

				it("throws if length is undefined", function() {
					attResp.authnrData.delete("credIdLen");
					return assert.isRejected(attResp.validateCredId(), Error, "authnrData credIdLen should be number, got undefined");
				});

				it("throws if length is not number", function() {
					attResp.authnrData.set("credIdLen", new Uint8Array());
					return assert.isRejected(attResp.validateCredId(), Error, "authnrData credIdLen should be number, got object");
				});

				it("throws if length is wrong", function() {
					attResp.authnrData.set("credIdLen", 42);
					return assert.isRejected(attResp.validateCredId(), "authnrData credId was wrong length");
				});

				it("throws if credId is undefined", function() {
					attResp.authnrData.delete("credId");
					return assert.isRejected(attResp.validateCredId(), "authnrData credId should be ArrayBuffer");
				});

				it("throws if not array buffer", function() {
					attResp.authnrData.set("credId", "foo");
					return assert.isRejected(attResp.validateCredId(), "authnrData credId should be ArrayBuffer");
				});
			});

			describe("validatePublicKey", function() {
				it("returns true on validation", async function() {
					var ret = await attResp.validatePublicKey();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("credentialPublicKeyCose"));
					assert.isTrue(attResp.audit.journal.has("credentialPublicKeyJwk"));
					assert.isTrue(attResp.audit.journal.has("credentialPublicKeyPem"));
				});
			});

			describe("validateTokenBinding", function() {
				it("returns true if tokenBinding is undefined", async function() {
					var ret = await attResp.validateTokenBinding();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("tokenBinding"));
				});

				it("throws if tokenBinding is defined", function() {
					attResp.clientData.set("tokenBinding", "foo");
					return assert.isRejected(attResp.validateTokenBinding(), Error, "Token binding field malformed: foo");
				});
			});

			describe("validateFlags", function() {
				it("returns true on valid expectations", async function() {
					var ret = await attResp.validateFlags();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("flags"));
				});

				it("throws on invalid expectations", function() {
					attResp.expectations.set("flags", ["ED"]);
					return assert.isRejected(attResp.validateFlags(), Error, "expected flag was not set: ED");
				});

				it("throws if UV is set but UP is not set", function() {
					attResp.expectations.set("flags", ["UV"]);
					attResp.authnrData.set("flags", new Set(["UV"]));
					return assert.isRejected(attResp.validateFlags(), Error, "expected User Presence (UP) flag to be set if User Verification (UV) is set");
				});

				it("throws if UV is not set", function() {
					attResp.expectations.set("flags", ["UV"]);
					attResp.authnrData.set("flags", new Set(["ED"]));
					return assert.isRejected(attResp.validateFlags(), Error, "expected flag was not set: UV");
				});

				it("throws if UV but only UP is set", function() {
					attResp.expectations.set("flags", ["UV"]);
					attResp.authnrData.set("flags", new Set(["UP"]));
					return assert.isRejected(attResp.validateFlags(), Error, "expected flag was not set: UV");
				});

				it("returns true on UP with UP-or-UV", async function() {
					attResp.expectations.set("flags", ["UP-or-UV"]);
					attResp.authnrData.set("flags", new Set(["UP"]));
					var ret = await attResp.validateFlags();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("flags"));
				});

				it("returns true on UV with UP-or-UV", async function() {
					attResp.expectations.set("flags", ["UP-or-UV"]);
					attResp.authnrData.set("flags", new Set(["UV", "UP"]));
					var ret = await attResp.validateFlags();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("flags"));
				});

				it("throws if UP-or-UV and UV is set but not UP", function() {
					attResp.expectations.set("flags", ["UP-or-UV"]);
					attResp.authnrData.set("flags", new Set(["UV"]));
					return assert.isRejected(attResp.validateFlags(), Error, "expected User Presence (UP) flag to be set if User Verification (UV) is set");
				});

				it("throws if UP-or-UV and neither is set", function() {
					attResp.expectations.set("flags", ["UP-or-UV"]);
					attResp.authnrData.set("flags", new Set(["ED"]));
					return assert.isRejected(attResp.validateFlags(), Error, "expected User Presence (UP) or User Verification (UV) flag to be set and neither was");
				});

				it("throws if any of the RFU flags are set");
			});

			describe("validateInitialCounter", function() {
				it("returns true if valid", async function() {
					var ret = await attResp.validateInitialCounter();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.journal.has("counter"));
				});

				it("throws if not a number", function() {
					attResp.authnrData.set("counter", "foo");
					return assert.isRejected(attResp.validateInitialCounter(), Error, "authnrData counter wasn't a number");
				});
			});

			describe("validateAudit for 'none' attestation", function() {
				it("returns on all internal checks passed", async function() {
					await attResp.validateExpectations();
					await attResp.validateCreateRequest();
					// clientData validators
					await attResp.validateRawClientDataJson();
					await attResp.validateOrigin();
					await attResp.validateCreateType();
					await attResp.validateChallenge();
					await attResp.validateTokenBinding();
					await attResp.validateId();
					await attResp.validateTransports();
					// authnrData validators
					await attResp.validateRawAuthnrData();
					await attResp.validateAttestation();
					await attResp.validateRpIdHash();
					await attResp.validateAaguid();
					await attResp.validateCredId();
					await attResp.validatePublicKey();
					await attResp.validateFlags();
					await attResp.validateInitialCounter();

					// audit
					var ret = await attResp.validateAudit();
					assert.isTrue(ret);
					assert.isTrue(attResp.audit.complete);
				});

				it("throws on untested verifies", function() {
					return assert.isRejected(attResp.validateAudit(), Error, /^internal audit failed: .* was not validated$/);
				});

				it("throws on extra journal entries");

				it("throws on untested expectations");
				it("throws on untested request");
			});

			describe("validateAudit for assertion", function() {
				it("returns on all internal checks passed");
			});
		});
	});
});

describe("assertion validation", function() {
	var assnResp;
	beforeEach(function() {
		assnResp = {
			request: {},
			requiredExpectations: new Set([
				"origin",
				"challenge",
				"flags",
				"counter",
				"publicKey",
			]),
			optionalExpectations: new Set([
				"rpId",
				"allowCredentials",
			]),
			expectations: new Map([
				["origin", "https://localhost:8443"],
				["challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w"],
				["flags", ["UP", "AT"]],
				["counter", 300],
				["publicKey", h.lib.assnPublicKey],
				["allowCredentials", [{
					id: h.lib.assertionResponse.rawId,
					type: "public-key",
				}]],
			]),
			clientData: parser.parseClientResponse(h.lib.assertionResponse),
			authnrData: new Map([
				...parser.parseAuthnrAssertionResponse(h.lib.assertionResponse),
			]),
		};
		var testReq = cloneObject(h.lib.assertionResponse);
		testReq.rawId = h.lib.assertionResponse.rawId;
		testReq.response.clientDataJSON = h.lib.assertionResponse.response.clientDataJSON.slice(0);
		testReq.response.authenticatorData = h.lib.assertionResponse.response.authenticatorData.slice(0);
		testReq.response.signature = h.lib.assertionResponse.response.signature.slice(0);
		testReq.response.userHandle = h.lib.assertionResponse.response.userHandle.slice(0);
		assnResp.request = testReq;

		validator.attach(assnResp);
	});

	describe("validateUserHandle", function() {
		it("returns true when undefined", async function() {
			var ret = await assnResp.validateUserHandle();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.journal.has("userHandle"));
		});

		it("throws if not undefined", function() {
			assnResp.authnrData.set("userHandle", "foo");
			return assert.isRejected(assnResp.validateUserHandle(), Error, "unable to validate userHandle");
		});
	});

	describe("validateCounter", function() {
		it("returns true if counter has advanced", async function() {
			assert.strictEqual(assnResp.authnrData.get("counter"), 363);
			assnResp.expectations.set("prevCounter", 362);
			var ret = await assnResp.validateCounter();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.journal.has("counter"));
			assert.equal(assnResp.audit.info.get("counter-supported"), "true");
		});

		it("returns true if counter is not supported but do not add it to journal", async function() {
			assnResp.authnrData.set("counter", 0);
			assnResp.expectations.set("prevCounter", 0);
			var ret = await assnResp.validateCounter();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.journal.has("counter"));
			assert.equal(assnResp.audit.info.get("counter-supported"), "false");
		});

		it("throws if counter is the same", function() {
			assert.strictEqual(assnResp.authnrData.get("counter"), 363);
			assnResp.expectations.set("prevCounter", 363);
			return assert.isRejected(assnResp.validateCounter(), Error, "counter rollback detected");
		});

		it("throws if counter has rolled back", function() {
			assert.strictEqual(assnResp.authnrData.get("counter"), 363);
			assnResp.expectations.set("prevCounter", 364);
			return assert.isRejected(assnResp.validateCounter(), Error, "counter rollback detected");
		});
	});

	describe("validateExpectations", function() {
		it("returns true on valid expectations", async function() {
			var ret = await assnResp.validateExpectations();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validExpectations);
		});
	});

	describe("validateId", function() {
		it("returns true on ArrayBuffer", async function() {
			var ret = await assnResp.validateId();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.journal.has("rawId"));
		});

		it("throws on non-ArrayBuffer", function() {
			assnResp.clientData.set("id", {});
			assnResp.clientData.set("rawId", {});
			return assert.isRejected(assnResp.validateId(), Error, "expected id to be of type ArrayBuffer");
		});

		it("throws on undefined", function() {
			assnResp.clientData.set("id", undefined);
			assnResp.clientData.set("rawId", undefined);
			return assert.isRejected(assnResp.validateId(), Error, "expected id to be of type ArrayBuffer");
		});


		it("throws on allowCredentials not includes rawId", function() {
			assnResp.expectations.set("allowCredentials", [{ type: "public-key", id: coerceToArrayBuffer("dGVz", "tes") }]);
			assnResp.clientData.set("rawId", coerceToArrayBuffer("Y2lhbw==", "ciao"));
			return assert.isRejected(assnResp.validateId(), Error, "Credential ID does not match any value in allowCredentials");
		});
	});


	describe("validateAssertionSignature", function() {
		it("returns true on valid signature");
	});

	describe("validateAssertionResponse", function() {
		it("returns true if request is valid", async function() {
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("returns true for U2F request", async function() {
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("throws if request is undefined", function() {
			assnResp.request = undefined;
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected request to be Object, got undefined");
		});

		it("throws if response field is undefined", function() {
			delete assnResp.request.response;
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response' field of request to be Object, got undefined");
		});

		it("throws if response field is non-object", function() {
			assnResp.request.response = 3;
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response' field of request to be Object, got number");
		});

		it("throws if id field is undefined", function() {
			delete assnResp.request.id;
			delete assnResp.request.rawId;
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId undefined and id undefined");
		});

		it("throws if rawId field is non-string", function() {
			assnResp.request.rawId = {};
			delete assnResp.request.id;
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId object and id undefined");
		});

		it("throws if response.signature is undefined", function() {
			delete assnResp.request.response.signature;
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response.signature' to be base64 String or ArrayBuffer");
		});

		it("throws if response.signature is non-ArrayBuffer & non-String", function() {
			assnResp.request.response.signature = {};
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response.signature' to be base64 String or ArrayBuffer");
		});

		it("passes with response.signature as ArrayBuffer", async function() {
			assnResp.request.response.signature = new ArrayBuffer();
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("passes with response.signature as String", async function() {
			assnResp.request.response.signature = "";
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("throws if response.authenticatorData is undefined", function() {
			delete assnResp.request.response.authenticatorData;
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response.authenticatorData' to be base64 String or ArrayBuffer");
		});

		it("throws if response.authenticatorData is non-ArrayBuffer & non-String", function() {
			assnResp.request.response.authenticatorData = {};
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response.authenticatorData' to be base64 String or ArrayBuffer");
		});

		it("passes with response.authenticatorData as ArrayBuffer", async function() {
			assnResp.request.response.authenticatorData = new ArrayBuffer();
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("passes with response.authenticatorData as String", async function() {
			assnResp.request.response.authenticatorData = "";
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("returns true if response.userHandle is undefined", async function() {
			delete assnResp.request.response.userHandle;
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("throws if response.userHandle is non-ArrayBuffer & non-String", function() {
			assnResp.request.response.userHandle = {};
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response.userHandle' to be base64 String, ArrayBuffer, or undefined");
		});

		it("passes with response.userHandle as ArrayBuffer", async function() {
			assnResp.request.response.userHandle = new ArrayBuffer();
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("passes with response.userHandle as String", async function() {
			assnResp.request.response.userHandle = "";
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("throws if response.clientDataJSON is undefined", function() {
			delete assnResp.request.response.clientDataJSON;
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
		});

		it("throws if response.clientDataJSON is non-ArrayBuffer & non-String", function() {
			assnResp.request.response.clientDataJSON = {};
			assert.throws(() => {
				assnResp.validateAssertionResponse();
			}, TypeError, "expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
		});

		it("passes with response.clientDataJSON as ArrayBuffer", async function() {
			assnResp.request.response.clientDataJSON = new ArrayBuffer();
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});

		it("passes with response.clientDataJSON as String", async function() {
			assnResp.request.response.clientDataJSON = "";
			var ret = await assnResp.validateAssertionResponse();
			assert.isTrue(ret);
			assert.isTrue(assnResp.audit.validRequest);
		});
	});
});
