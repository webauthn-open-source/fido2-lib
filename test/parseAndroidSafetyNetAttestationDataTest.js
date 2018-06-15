"use strict";

const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");
var {
    coerceToBase64,
    abEqual,
    printHex,
} = require("../lib/utils");

describe.skip("parseAttestationObject (tpm)", function() {
    it("parser is object", function() {
        assert.isObject(parser);
    });

    var ret;
    it("can parse", function() {
        ret = parser.parseAttestationObject(h.lib.makeCredentialAttestationSafetyNetResponse.response.attestationObject);
        // console.log("ret", ret);
    });
});
