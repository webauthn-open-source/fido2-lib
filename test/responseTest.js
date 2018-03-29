"use strict";

const {
    Fido2Response,
    Fido2CreateResponse,
    Fido2GetResponse
} = require("../lib/response");

var assert = require("chai").assert;
const h = require("fido2-helpers");
const { coerceToArrayBuffer } = require("../lib/utils");
const {
    printHex,
    cloneObject
} = h.functions;

describe("Fido2Response", function() {
    it("is function", function() {
        assert.isFunction(Fido2Response);
    });

    it("throws if called with new", function() {
        assert.throws(() => {
            new Fido2Response();
        }, Error, "Do not create with 'new' operator. Call 'Fido2CreateResponse.create()' or 'Fido2GetResponse.create()' instead.");
    });
});

describe("Fido2CreateResponse", function() {
    var testReq;
    beforeEach(() => {
        testReq = cloneObject(h.lib.makeCredentialAttestationNoneResponse);
        testReq.response.clientDataJSON = h.lib.makeCredentialAttestationNoneResponse.response.clientDataJSON.slice(0);
        testReq.response.attestationObject = h.lib.makeCredentialAttestationNoneResponse.response.attestationObject.slice(0);
    });

    it("is function", function() {
        assert.isFunction(Fido2CreateResponse);
    });

    it("throws if called with new", function() {
        assert.throws(() => {
            new Fido2CreateResponse();
        }, Error, "Do not create with 'new' operator. Call 'Fido2CreateResponse.create()' or 'Fido2GetResponse.create()' instead.");
    });

    it("passes with 'none' attestation", async function() {
        var ret = await Fido2CreateResponse.create(h.lib.makeCredentialAttestationNoneResponse, {
            origin: "https://localhost:8443",
            challenge: "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
            flags: ["UP", "AT"]
        });
        assert.instanceOf(ret, Fido2CreateResponse);
    });

    it.skip("passes with 'u2f' attestation", async function() {
        var ret = await Fido2CreateResponse.create(h.lib.makeCredentialAttestationU2fResponse, {
            origin: "https://localhost:8443",
            challenge: "Vu8uDqnkwOjd83KLj6Scn2BgFNLFbGR7Kq_XJJwQnnatztUR7XIBL7K8uMPCIaQmKw1MCVQ5aazNJFk7NakgqA",
            flags: ["UP", "AT"]
        });
        assert.instanceOf(ret, Fido2CreateResponse);
    });
    it("passes with 'tpm' attestation");
    it("passes with 'packed' attestation");
});

describe("Fido2GetResponse", function() {
    var testReq;
    beforeEach(() => {
        testReq = cloneObject(h.lib.makeCredentialAttestationNoneResponse);
        testReq.response.clientDataJSON = h.lib.makeCredentialAttestationNoneResponse.response.clientDataJSON.slice(0);
        testReq.response.attestationObject = h.lib.makeCredentialAttestationNoneResponse.response.attestationObject.slice(0);
    });

    it("is function", function() {
        assert.isFunction(Fido2GetResponse);
    });

    it("throws if called with new", function() {
        assert.throws(() => {
            new Fido2GetResponse();
        }, Error, "Do not create with 'new' operator. Call 'Fido2CreateResponse.create()' or 'Fido2GetResponse.create()' instead.");
    });

    it("returns Fido2GetResponse object on success", async function() {
        var ret = await Fido2GetResponse.create(h.lib.assertionResponse, {
            origin: "https://localhost:8443",
            challenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
            flags: ["UP"],
            prevCounter: 362,
            publicKey: h.lib.assnPublicKey
        });
        assert.instanceOf(ret, Fido2GetResponse);
    });
});
