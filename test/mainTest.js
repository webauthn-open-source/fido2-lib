var Fido2Server = require ("../index.js");
var assert = require ("chai").assert;
// var helpers = require("fido2-helpers");

describe ("Fido2Server", function() {
    it("can create FIDO server object", function() {
        var fs = new Fido2Server();
        assert (fs);
        assert.isFunction (fs.getAttestationChallenge);
        assert.isFunction (fs.makeCredentialResponse);
        assert.isFunction (fs.getAssertionChallenge);
        assert.isFunction (fs.getAssertionResponse);
    });
    it ("needs to check all the variations of options");
    it ("can create a server with blacklist");
    it ("can create server with crypto parameters");
    it ("can create server with timeout");
    it ("can create server with crypto size");
    it ("can set rpid");
    it ("sets default timeout values");
    it ("sets default crypto params");
    it ("sets default challenge size");
});

describe ("getAttestationChallenge", function() {
    var serv;
    beforeEach(function() {
        serv = new Fido2Server();
    });

    it ("returns a challenge", function() {
        return serv.getAttestationChallenge().then((chal) => {
            assert.isArray (chal.blacklist);
            assert.isArray (chal.cryptoParameters);
            assert.isString (chal.attestationChallenge);
            assert.isNumber (chal.timeout);
            assert.strictEqual (chal.attestationChallenge.length, 64);
        });
    });
    it ("returns the right challenge based on options set in the constructor");
});

describe ("makeCredentialResponse", function() {
    var serv;
    beforeEach(function() {
        serv = new Fido2Server();
    });

    it ("creates a credential");
});
// describe ("getAssertionChallenge");
// describe ("getAssertionResponse");

/* JSHINT */
/* globals beforeEach */