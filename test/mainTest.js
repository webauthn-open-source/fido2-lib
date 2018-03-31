"use strict";

const { Fido2Lib } = require("../index");
const {
    Fido2CreateResponse,
    Fido2GetResponse
} = require("../lib/response");
var assert = require("chai").assert;
var sinon = require("sinon");
var h = require("fido2-helpers");
const noneAttestation = require("../lib/attestations/none");
const u2fAttestation = require("../lib/attestations/fidoU2F");

describe("Fido2Lib", function() {
    it("can create FIDO server object", function() {
        var fs = new Fido2Lib();
        assert(fs);
        assert.isFunction(fs.createCredentialChallenge);
        assert.isFunction(fs.createCredentialResponse);
        assert.isFunction(fs.getAssertionChallenge);
        assert.isFunction(fs.getAssertionResponse);
    });

    it("needs to check all the variations of options");
    it("can create a server with blacklist");
    it("can create server with crypto parameters");
    it("can create server with timeout");
    it("can create server with crypto size");
    it("can set rpid");
    it("sets default timeout values");
    it("sets default crypto params");
    it("sets default challenge size");

    describe("createCredentialChallenge", function() {
        var serv;
        beforeEach(function() {
            serv = new Fido2Lib();
        });

        it("returns a challenge", function() {
            return serv.createCredentialChallenge().then((chal) => {
                assert.isNumber(chal.timeout);
                assert.strictEqual(chal.timeout, 60000);
                assert.strictEqual(chal.challenge.length, 64);
            });
        });

        it("returns the right challenge based on options set in the constructor");
    });

    describe("createCredentialResponse", function() {
        var serv;
        beforeEach(function() {
            serv = new Fido2Lib();
        });

        it("validates a credential request with 'none' attestation", function() {
            return serv.createCredentialResponse(
                h.lib.makeCredentialAttestationNoneResponse,
                "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
                "https://localhost:8443",
                "either"
            ).then((res) => {
                assert.instanceOf(res, Fido2CreateResponse);
                return res;
            });
        });

        it("validates a credential request with 'u2f' attestation");
        it("catches bad requests");
    });

    describe("getAssertionChallenge", function() {
        var serv;
        beforeEach(function() {
            serv = new Fido2Lib();
        });

        it("returns a challenge", function() {
            return serv.getAssertionChallenge().then((chal) => {
                assert.isNumber(chal.timeout);
                assert.strictEqual(chal.timeout, 60000);
                assert.strictEqual(chal.challenge.length, 64);
            });
        });
    });

    describe("getAssertionResponse", function() {
        var serv;
        beforeEach(function() {
            serv = new Fido2Lib();
        });

        it("valid an assertion", function() {
            return serv.getAssertionResponse(
                h.lib.assertionResponse,
                "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
                "https://localhost:8443",
                "either",
                h.lib.assnPublicKey,
                362
            ).then((res) => {
                assert.instanceOf(res, Fido2GetResponse);
                return res;
            });
        });
    });

    describe("addAttestationFormat", function() {
        afterEach(function() {
            Fido2Lib.deleteAllAttestationFormats();
        });

        after(function() {
            // add 'none' attestation format
            Fido2Lib.addAttestationFormat(
                noneAttestation.name,
                noneAttestation.parseFn,
                noneAttestation.validateFn
            );
        });

        it("adds to map on success", function() {
            var serv = new Fido2Lib();
            assert.instanceOf(serv.attestationMap, Map);
            var prevSize = serv.attestationMap.size;
            var ret = Fido2Lib.addAttestationFormat("foo", function() {}, function() {});
            assert.isTrue(ret);
            assert.strictEqual(serv.attestationMap.size, prevSize + 1);
            assert.isTrue(serv.attestationMap.has("foo"));
            var newFmt = serv.attestationMap.get("foo");
            assert.isObject(newFmt);
            assert.strictEqual(Object.keys(newFmt).length, 2);
            assert.isFunction(newFmt.parseFn);
            assert.isFunction(newFmt.validateFn);
        });

        it("throws on bad fmt", function() {
            assert.throws(() => {
                Fido2Lib.addAttestationFormat({}, function() {}, function() {});
            }, TypeError, "expected 'fmt' to be string, got: object");
        });

        it("throws on duplicate fmt", function() {
            Fido2Lib.addAttestationFormat("foo", function() {}, function() {});
            assert.throws(() => {
                Fido2Lib.addAttestationFormat("foo", function() {}, function() {});
            }, Error, "can't add format: 'foo' already exists");
        });

        it("throws on bad parseFn", function() {
            assert.throws(() => {
                Fido2Lib.addAttestationFormat("foo", [], function() {});
            }, TypeError, "expected 'parseFn' to be string, got: object");
        });

        it("throws on bad validateFn", function() {
            assert.throws(() => {
                Fido2Lib.addAttestationFormat("foo", function() {}, "blah");
            }, TypeError, "expected 'validateFn' to be string, got: string");
        });
    });

    describe("parseAttestation", function() {
        var parseStub;
        var validateStub;
        beforeEach(function() {
            parseStub = sinon.stub();
            validateStub = sinon.stub();
            Fido2Lib.addAttestationFormat("foo", parseStub, validateStub);
        });

        afterEach(function() {
            Fido2Lib.deleteAllAttestationFormats();
        });

        after(function() {
            // add 'none' attestation format
            Fido2Lib.addAttestationFormat(
                noneAttestation.name,
                noneAttestation.parseFn,
                noneAttestation.validateFn
            );
        });

        it("returns Map on success", function() {
            var arg = new Map([
                ["test", "yup"]
            ]);
            parseStub.onCall(0).returns(arg);
            var ret = Fido2Lib.parseAttestation("foo", arg);
            assert.instanceOf(ret, Map);
            assert.strictEqual(parseStub.callCount, 1);
            assert.isTrue(parseStub.calledWith(arg));
        });

        it("success when returning empty map", function() {
            var arg = new Map();
            parseStub.onCall(0).returns(arg);
            var ret = Fido2Lib.parseAttestation("foo", arg);
            assert.instanceOf(ret, Map);
            assert.strictEqual(parseStub.callCount, 1);
            assert.isTrue(parseStub.calledWith(arg));
        });

        it("throws if parseFn doesn't return Map", function() {
            assert.throws(() => {
                Fido2Lib.parseAttestation("foo", { test: "yup" });
            }, Error, "foo parseFn did not return a Map");
        });

        it("throws on non-string format", function() {
            assert.throws(() => {
                Fido2Lib.parseAttestation({}, { test: "yup" });
            }, TypeError, "expected 'fmt' to be string, got: object");
        });

        it("throws on missing format", function() {
            assert.throws(() => {
                Fido2Lib.parseAttestation();
            }, TypeError, "expected 'fmt' to be string, got: undefined");
        });

        it("throws on missing data", function() {
            assert.throws(() => {
                Fido2Lib.parseAttestation("foo");
            }, TypeError, "expected 'attStmt' to be object, got: undefined");
        });
    });

    describe("validateAttestation", function() {
        var parseStub;
        var validateStub;
        var fakeRequest;
        beforeEach(function() {
            parseStub = sinon.stub();
            validateStub = sinon.stub();
            Fido2Lib.addAttestationFormat("foo", parseStub, validateStub);
            fakeRequest = {
                authnrData: new Map([
                    ["fmt", "foo"]
                ])
            };
        });

        afterEach(function() {
            Fido2Lib.deleteAllAttestationFormats();
        });

        after(function() {
            // add 'none' attestation format
            Fido2Lib.addAttestationFormat(
                noneAttestation.name,
                noneAttestation.parseFn,
                noneAttestation.validateFn
            );
            // add 'fido-u2f' attestation format
            Fido2Lib.addAttestationFormat(
                u2fAttestation.name,
                u2fAttestation.parseFn,
                u2fAttestation.validateFn
            );
        });

        it("returns Map on success", async function() {
            validateStub.onCall(0).returns(true);
            var arg = new Map();
            var ret = await Fido2Lib.validateAttestation.call(fakeRequest);
            assert.isTrue(ret);
            assert.strictEqual(validateStub.callCount, 1);
        });

        it("throws if validateFn doesn't return true", async function() {
            assert.isRejected(Fido2Lib.validateAttestation.call(fakeRequest), Error, "foo validateFn did not return 'true'");
        });

        it("throws on non-string format", function() {
            fakeRequest.authnrData.set("fmt", {});
            assert.isRejected(Fido2Lib.validateAttestation.call(fakeRequest), TypeError, "expected 'fmt' to be string, got: object");
        });

        it("throws on missing format", function() {
            fakeRequest.authnrData.clear();
            assert.isRejected(Fido2Lib.validateAttestation.call(fakeRequest), TypeError, "expected 'fmt' to be string, got: undefined");
        });
    });
});

/* JSHINT */
