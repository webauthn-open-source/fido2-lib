const validator = require("../lib/validator");
const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");
const {
    printHex,
    cloneObject
} = h.functions;

var testObj;
describe("validator", function() {
    beforeEach(function() {
        testObj = {
            request: {},
            requiredExpectations: new Set([
                "origin",
                "challenge",
                "flags"
            ]),
            expectations: new Map([
                ["origin", "https://localhost:8443"],
                ["challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w"],
                ["flags", ["UP", "AT"]]
            ]),
            clientData: parser.parseClientData(h.lib.makeCredentialAttestationNoneResponse.response.clientDataJSON),
            authnrData: parser.parseAttestationObject(h.lib.makeCredentialAttestationNoneResponse.response.attestationObject)
        };
        var testReq = cloneObject(h.lib.makeCredentialAttestationNoneResponse);
        testReq.response.clientDataJSON = h.lib.makeCredentialAttestationNoneResponse.response.clientDataJSON.slice(0);
        testReq.response.attestationObject = h.lib.makeCredentialAttestationNoneResponse.response.attestationObject.slice(0);
        testObj.request = testReq;

        validator.attach(testObj);
    });

    it("returns object", function() {
        assert.isObject(validator);
    });

    it("is attached", function() {
        assert.isFunction(validator.attach);
        assert.isFunction(testObj.validateOrigin);
        assert.isFunction(testObj.validateAttestationSignature);
    });

    describe("validateExpectations", function() {
        it("returns true on valid expectations", function() {
            var ret = testObj.validateExpectations();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.validExpectations);
        });

        it("throws if expectations aren't found", function() {
            delete testObj.expectations;
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expectations should be of type Map");
        });

        it("throws if expectations aren't Map", function() {
            testObj.expectations = {};
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expectations should be of type Map");
        });

        it("throws if too many expectations", function() {
            testObj.expectations.set("foo", "bar");
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "wrong number of expectations: should have 3 but got 4");
        });

        it("throws if missing challenge", function() {
            testObj.expectations.delete("challenge");
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expectation did not contain value for 'challenge'");
        });

        it("throws if missing flags", function() {
            testObj.expectations.delete("flags");
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expectation did not contain value for 'flags'");
        });

        it("throws if missing origin", function() {
            testObj.expectations.delete("origin");
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expectation did not contain value for 'origin'");
        });

        it("throws if challenge is undefined", function() {
            testObj.expectations.set("challenge", undefined);
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expected challenge should be of type String, got: undefined");
        });

        it("throws if challenge isn't string", function() {
            testObj.expectations.set("challenge", { foo: "bar" });
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expected challenge should be of type String, got: object");
        });

        it("throws if challenge isn't base64 encoded string", function() {
            testObj.expectations.set("challenge", "miles&me");
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expected challenge should be properly encoded base64url String");
        });

        it("calls checkOrigin");

        it("returns true if flags is Set", function() {
            testObj.expectations.set("flags", new Set(["UP", "AT"]));
            var ret = testObj.validateExpectations();
            assert.isTrue(ret);
        });

        it("throws if Set contains non-string", function() {
            testObj.expectations.set("flags", new Set([3, "UP", "AT"]));
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expected flag unknown: 3");
        });

        it("throws if Array contains non-string", function() {
            testObj.expectations.set("flags", [3, "UP", "AT"]);
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expected flag unknown: 3");
        });

        it("throws on unknown flag", function() {
            testObj.expectations.set("flags", new Set(["foo", "UP", "AT"]));
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expected flag unknown: foo");
        });

        it("throws on undefined flag", function() {
            testObj.expectations.set("flags", new Set([undefined, "UP", "AT"]));
            assert.throws(() => {
                testObj.validateExpectations();
            }, Error, "expected flag unknown: undefined");
        });

        it("throws if requiredExpectations is undefined");
        it("throws if requiredExpectations is not Array or Set");
        it("passes if requiredExpectations is Array");
        it("passes if requiredExpectations is Set");
        it("throws if requiredExpectations field is missing");
        it("throws if more expectations were passed than requiredExpectations");
    });

    describe("validateCreateRequest", function() {
        it("returns true if request is valid", function() {
            var ret = testObj.validateCreateRequest();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.validRequest);
        });

        it("returns true for U2F request", function() {
            var ret = testObj.validateCreateRequest();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.validRequest);
        });

        it("throws if request is undefined", function() {
            testObj.request = undefined;
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected request to be Object, got undefined");
        });

        it("throws if response field is undefined", function() {
            delete testObj.request.response;
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected 'response' field of request to be Object, got undefined");
        });

        it("throws if response field is non-object", function() {
            testObj.request.response = 3;
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected 'response' field of request to be Object, got number");
        });

        it("throws if id field is undefined", function() {
            delete testObj.request.id;
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected 'id' field of request to be String, got undefined");
        });

        it("throws if id field is non-string", function() {
            testObj.request.id = [];
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected 'id' field of request to be String, got object");
        });

        it("throws if response.attestationObject is undefined", function() {
            delete testObj.request.response.attestationObject;
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected 'response.attestationObject' to be base64 String or ArrayBuffer");
        });

        it("throws if response.attestationObject is non-ArrayBuffer & non-String", function() {
            testObj.request.response.attestationObject = {};
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected 'response.attestationObject' to be base64 String or ArrayBuffer");
        });

        it("passes with response.attestationObject as ArrayBuffer", function() {
            testObj.request.response.attestationObject = new ArrayBuffer();
            var ret = testObj.validateCreateRequest();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.validRequest);
        });

        it("passes with response.attestationObject as String", function() {
            testObj.request.response.attestationObject = "";
            var ret = testObj.validateCreateRequest();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.validRequest);
        });

        it("throws if response.clientDataJSON is undefined", function() {
            delete testObj.request.response.clientDataJSON;
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
        });

        it("throws if response.clientDataJSON is non-ArrayBuffer & non-String", function() {
            testObj.request.response.clientDataJSON = {};
            assert.throws(() => {
                testObj.validateCreateRequest();
            }, TypeError, "expected 'response.clientDataJSON' to be base64 String or ArrayBuffer");
        });

        it("passes with response.clientDataJSON as ArrayBuffer", function() {
            testObj.request.response.clientDataJSON = new ArrayBuffer();
            var ret = testObj.validateCreateRequest();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.validRequest);
        });

        it("passes with response.clientDataJSON as String", function() {
            testObj.request.response.clientDataJSON = "";
            var ret = testObj.validateCreateRequest();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.validRequest);
        });


        // req { username: 'adam',
        //   id: 'Bo+VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd+GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT/e698IirQ==',
        //   response:
        //    { attestationObject: ArrayBuffer { byteLength: 900 },
        //      clientDataJSON: ArrayBuffer { byteLength: 209 } } }
    });

    describe("validateRawClientDataJson", function() {
        it("returns true if ArrayBuffer", function() {
            var ret = testObj.validateRawClientDataJson();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("rawClientDataJson"));
        });

        it("throws if missing", function() {
            testObj.clientData.delete("rawClientDataJson");
            assert.throws(() => {
                testObj.validateRawClientDataJson();
            }, Error, "clientData clientDataJson should have be ArrayBuffer");
        });

        it("throws if not ArrayBuffer", function() {
            testObj.clientData.set("rawClientDataJson", "foo");
            assert.throws(() => {
                testObj.validateRawClientDataJson();
            }, Error, "clientData clientDataJson should have be ArrayBuffer");
        });
    });

    describe("validateOrigin", function() {
        it("accepts exact match", function() {
            testObj.expectations.set("origin", "https://webauthn.bin.coffee:8080");
            testObj.clientData.set("origin", "https://webauthn.bin.coffee:8080");
            var ret = testObj.validateOrigin();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("origin"));
        });

        it("throws on port mismatch", function() {
            testObj.expectations.set("origin", "https://webauthn.bin.coffee:8080");
            testObj.clientData.set("origin", "https://webauthn.bin.coffee:8443");
            assert.throws(() => {
                testObj.validateOrigin();
            }, Error, "clientData origin did not match expected origin");
        });

        it("throws on domain mismatch", function() {
            testObj.expectations.set("origin", "https://webauthn.bin.coffee:8080");
            testObj.clientData.set("origin", "https://bin.coffee:8080");
            assert.throws(() => {
                testObj.validateOrigin();
            }, Error, "clientData origin did not match expected origin");
        });

        it("throws on protocol mismatch", function() {
            testObj.expectations.set("origin", "http://webauthn.bin.coffee:8080");
            testObj.clientData.set("origin", "https://webauthn.bin.coffee:8080");
            assert.throws(() => {
                testObj.validateOrigin();
            }, Error, "clientData origin did not match expected origin");
        });

        it("calls checkOrigin");
    });

    describe("checkOrigin", function() {});

    describe("validateCreateType", function() {
        it("returns true when 'webauthn.create'", function() {
            var ret = testObj.validateCreateType();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("type"));
        });

        it("throws when undefined", function() {
            testObj.clientData.set("type", undefined);
            assert.throws(() => {
                testObj.validateCreateType();
            }, Error, "clientData type should be 'webauthn.create'");
        });

        it("throws on 'webauthn.get'", function() {
            testObj.clientData.set("type", "webauthn.get");
            assert.throws(() => {
                testObj.validateCreateType();
            }, Error, "clientData type should be 'webauthn.create'");
        });

        it("throws on unknown string", function() {
            testObj.clientData.set("type", "asdf");
            assert.throws(() => {
                testObj.validateCreateType();
            }, Error, "clientData type should be 'webauthn.create'");
        });
    });

    describe("validateGetType", function() {
        it("returns true when 'webauthn.get'", function() {
            testObj.clientData.set("type", "webauthn.get");
            var ret = testObj.validateGetType();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("type"));
        });

        it("throws when undefined", function() {
            testObj.clientData.set("type", undefined);
            assert.throws(() => {
                testObj.validateGetType();
            }, Error, "clientData type should be 'webauthn.get'");
        });

        it("throws on 'webauthn.create'", function() {
            testObj.clientData.set("type", "webauthn.create");
            assert.throws(() => {
                testObj.validateGetType();
            }, Error, "clientData type should be 'webauthn.get'");
        });

        it("throws on unknown string", function() {
            testObj.clientData.set("type", "asdf");
            assert.throws(() => {
                testObj.validateGetType();
            }, Error, "clientData type should be 'webauthn.get'");
        });
    });

    describe("validateChallenge", function() {
        it("returns true if challenges match", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            var ret = testObj.validateChallenge();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("challenge"));
        });

        it("accepts ending equal sign (1)", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            testObj.clientData.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w=");
            var ret = testObj.validateChallenge();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("challenge"));
        });

        it("accepts ending equal signs (2)", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            testObj.clientData.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w==");
            var ret = testObj.validateChallenge();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("challenge"));
        });

        it("throws on three equal signs", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            testObj.clientData.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w===");
            assert.throws(() => {
                testObj.validateChallenge();
            }, Error, "clientData challenge was not properly encoded base64url");
        });

        it("does not remove equal sign from middle of string", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            testObj.clientData.set("challenge", "33EHav-jZ1v9qwH783aU-j0A=Rx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            assert.throws(() => {
                testObj.validateChallenge();
            }, Error, "clientData challenge was not properly encoded base64url");
        });

        it("throws if challenge is not a string", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            testObj.clientData.set("challenge", ["foo"]);
            assert.throws(() => {
                testObj.validateChallenge();
            }, Error, "clientData challenge was not a string");
        });

        it("throws if challenge is base64url encoded", function() {
            testObj.expectations.set("challenge", "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg");
            testObj.clientData.set("challenge", "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg");
            assert.throws(() => {
                testObj.validateChallenge();
            }, Error, "clientData challenge was not properly encoded base64url");
        });

        it("throws if challenge is not base64 string", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            testObj.clientData.set("challenge", "miles&me");
            assert.throws(() => {
                testObj.validateChallenge();
            }, Error, "clientData challenge was not properly encoded base64url");
        });

        it("throws on undefined challenge", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            testObj.clientData.set("challenge", undefined);
            assert.throws(() => {
                testObj.validateChallenge();
            }, Error, "clientData challenge was not a string");
        });

        it("throws on challenge mismatch", function() {
            testObj.expectations.set("challenge", "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
            testObj.clientData.set("challenge", "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg");
            assert.throws(() => {
                testObj.validateChallenge();
            }, Error, "clientData challenge mismatch");
        });
    });

    describe("validateRawAuthData", function() {
        it("returns true if ArrayBuffer", function() {
            var ret = testObj.validateRawAuthData();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("rawAuthData"));
        });

        it("throws if missing", function() {
            testObj.authnrData.delete("rawAuthData");
            assert.throws(() => {
                testObj.validateRawAuthData();
            }, Error, "authnrData rawAuthData should have be ArrayBuffer");
        });

        it("throws if not ArrayBuffer", function() {
            testObj.authnrData.set("rawAuthData", "foo");
            assert.throws(() => {
                testObj.validateRawAuthData();
            }, Error, "authnrData rawAuthData should have be ArrayBuffer");
        });
    });

    describe("validateAttestationSignature", function() {
        it("accepts none", function() {
            var ret = testObj.validateAttestationSignature();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("fmt"));
        });

        it("throws on unknown fmt", function() {
            assert.throws(() => {
                testObj.authnrData.set("fmt", "asdf");
                testObj.validateAttestationSignature();
            }, Error, "unknown clientData fmt: asdf");
        });

        it("throws on undefined fmt", function() {
            assert.throws(() => {
                testObj.authnrData.delete("fmt");
                testObj.validateAttestationSignature();
            }, Error, "unknown clientData fmt: undefined");
        });
    });

    describe("validateRpIdHash", function() {
        it("returns true when matches", function() {
            var ret = testObj.validateRpIdHash();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("rpIdHash"));
        });

        it("throws when it doesn't match", function() {
            testObj.clientData.set("origin", "https://google.com");
            assert.throws(() => {
                testObj.validateRpIdHash();
            }, Error, "authnrData rpIdHash mismatch");
        });

        it("throws when length mismatches", function() {
            testObj.authnrData.set("rpIdHash", new Uint8Array([1, 2, 3]).buffer);
            assert.throws(() => {
                testObj.validateRpIdHash();
            }, Error, "authnrData rpIdHash length mismatch");
        });
    });

    describe("validateAaguid", function() {
        it("returns true on validation", function() {
            var ret = testObj.validateAaguid();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("aaguid"));
        });

        it("throws if too short", function() {
            assert.throws(() => {
                testObj.authnrData.set("aaguid", new Uint8Array([1, 2, 3]).buffer);
                testObj.validateAaguid();
            }, Error, "authnrData AAGUID was wrong length");

        });
    });

    describe("validateCredId", function() {
        it("returns true when ArrayBuffer of correct length", function() {
            var ret = testObj.validateCredId();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("credId"));
            assert.isTrue(testObj.audit.journal.has("credIdLen"));
        });

        it("throws if length is undefined", function() {
            testObj.authnrData.delete("credIdLen");
            assert.throws(() => {
                testObj.validateCredId();
            }, Error, "authnrData credIdLen should be number, got undefined");
        });

        it("throws if length is not number", function() {
            testObj.authnrData.set("credIdLen", new Uint8Array());
            assert.throws(() => {
                testObj.validateCredId();
            }, Error, "authnrData credIdLen should be number, got object");
        });

        it("throws if length is wrong", function() {
            testObj.authnrData.set("credIdLen", 42);
            assert.throws(() => {
                testObj.validateCredId();
            }, Error, "authnrData credId was wrong length");
        });

        it("throws if credId is undefined", function() {
            testObj.authnrData.delete("credId");
            assert.throws(() => {
                testObj.validateCredId();
            }, Error, "authnrData credId should be ArrayBuffer");
        });

        it("throws if not array buffer", function() {
            testObj.authnrData.set("credId", "foo");
            assert.throws(() => {
                testObj.validateCredId();
            }, Error, "authnrData credId should be ArrayBuffer");
        });
    });

    describe("validatePublicKey", function() {
        it("returns true on validation", function() {
            var ret = testObj.validatePublicKey();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("credentialPublicKeyCose"));
            assert.isTrue(testObj.audit.journal.has("credentialPublicKeyJwk"));
            assert.isTrue(testObj.audit.journal.has("credentialPublicKeyPem"));
        });
    });

    describe("validateTokenBinding", function() {
        it("returns true if tokenBinding is undefined", function() {
            var ret = testObj.validateTokenBinding();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("tokenBinding"));
        });

        it("throws if tokenBinding is defined", function() {
            testObj.clientData.set("tokenBinding", "foo");
            assert.throws(() => {
                testObj.validateTokenBinding();
            }, Error, "Token binding not currently supported. Please submit a GitHub issue.");
        });
    });

    describe("validateFlags", function() {
        it("returns true on valid expectations", function() {
            var ret = testObj.validateFlags();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("flags"));
        });

        it("throws on invalid expectations", function() {
            testObj.expectations.set("flags", ["ED"]);
            assert.throws(() => {
                testObj.validateFlags();
            }, Error, "expected flag was not set: ED");
        });

        it("returns true on UP with UP-or-UV", function() {
            testObj.expectations.set("flags", ["UP-or-UV"]);
            testObj.authnrData.set("flags", new Set(["UP"]));
            var ret = testObj.validateFlags();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("flags"));
        });

        it("returns true on UV with UP-or-UV", function() {
            testObj.expectations.set("flags", ["UP-or-UV"]);
            testObj.authnrData.set("flags", new Set(["UV"]));
            var ret = testObj.validateFlags();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("flags"));
        });

        it("throws if UP-or-UV and neither is set", function() {
            testObj.expectations.set("flags", ["UP-or-UV"]);
            testObj.authnrData.set("flags", new Set(["ED"]));
            assert.throws(() => {
                testObj.validateFlags();
            }, Error, "expected User Presence (UP) or User Verification (UV) flag to be set and neither was");
        });
    });

    describe("validateInitialCounter", function() {
        it("returns true if valid", function() {
            var ret = testObj.validateInitialCounter();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.journal.has("counter"));
        });

        it("throws if not a number", function() {
            testObj.authnrData.set("counter", "foo");
            assert.throws(() => {
                testObj.validateInitialCounter();
            }, Error, "authnrData counter wasn't a number");
        });
    });

    describe("validateAudit", function() {
        it("returns on all internal checks passed", function() {
            testObj.validateExpectations();
            testObj.validateCreateRequest();
            // clientData validators
            testObj.validateRawClientDataJson();
            testObj.validateOrigin();
            testObj.validateCreateType();
            testObj.validateChallenge();
            testObj.validateTokenBinding();
            // authnrData validators
            testObj.validateRawAuthData();
            testObj.validateAttestationSignature();
            testObj.validateRpIdHash();
            testObj.validateAaguid();
            testObj.validateCredId();
            testObj.validatePublicKey();
            testObj.validateFlags();
            testObj.validateInitialCounter();

            // audit
            var ret = testObj.validateAudit();
            assert.isTrue(ret);
            assert.isTrue(testObj.audit.complete);
        });

        it("throws on untested verifies", function() {
            assert.throws(() => {
                testObj.validateAudit();
            }, Error, /^internal audit failed: .* was not validated$/);
        });

        it("throws on extra journal entries");

        it("throws on untested expectations");
        it("throws on untested request");
    });
});