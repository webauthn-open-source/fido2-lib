const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");

describe("parseAssertionData", function() {
    it("parser is object", function() {
        assert.isObject(parser);
    });

    it("parses assertion correctly", function() {
        var ret = parser.parseAssertionData(h.lib.assertionResponse.response.authenticatorData);
        console.log("authenticatorData", ret);
        assert.instanceOf(ret, Map);
    });
});