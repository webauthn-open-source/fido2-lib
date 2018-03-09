const {
    Fido2Lib
} = require("../index.js");
var assert = require("chai").assert;
var h = require("fido2-helpers");

describe("Fido2Lib", function() {
    it("can create FIDO server object", function() {
        var fs = new Fido2Lib({
            serverDomain: "example.com"
        });
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
            serv = new Fido2Lib({
                serverDomain: "example.com"
            });
        });

        it("returns a challenge", function() {
            return serv.createCredentialChallenge().then((chal) => {
                assert.isString(chal.rp.id);
                assert.strictEqual(chal.rp.id, "example.com");
                assert.isString(chal.rp.name);
                assert.strictEqual(chal.rp.name, "example.com");
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
            serv = new Fido2Lib({
                serverDomain: "example.com"
            });
        });

        it("validates a credential request with 'none' attestation", function() {
            return serv.createCredentialResponse(
                h.lib.makeCredentialAttestationNoneResponse,
                "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
                "https://localhost:8443",
                "either"
            );
        });

        it("validates a credential request with 'u2f' attestation");
        it("catches bad requests");
    });

    describe("getAssertionChallenge", function() {
        it("generates a challenge");
    });

    describe("getAssertionResponse", function() {
        it("valid an assertion");
    });
});

/* JSHINT */