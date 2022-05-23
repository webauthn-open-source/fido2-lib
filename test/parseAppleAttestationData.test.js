// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

// Helpers
import * as h from "./helpers/fido2-helpers.js";

// Test subject
import {
	parseAuthnrAttestationResponse,
	parseAttestationObject
} from "../lib/main.js";

chai.use(chaiAsPromised.default);
const { assert } = chai;

const parser = {
	parseAuthnrAttestationResponse,
	parseAttestationObject,
};

const runs = [
	{ functionName: "parseAuthnrAttestationResponse" },
	{ functionName: "parseAttestationObject" },
];

runs.forEach(function(run) {
	describe(run.functionName + " (apple)", async function() {
		it("parses is object", function() {
			assert.equal(typeof parser, "object");
		});
	});
});
