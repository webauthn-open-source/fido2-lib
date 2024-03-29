// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

// Helpers
import * as h from "./helpers/fido2-helpers.js";

// Test subject
import { parseAttestationObject, parseAuthnrAttestationResponse } from "../lib/main.js";

chai.use(chaiAsPromised.default);
const { assert } = chai;

const parser = {
	parseAuthnrAttestationResponse,
	parseAttestationObject,
};

describe("parse attestation (android-safetynet)", function() {
	it("parser is object", function() {
		assert.equal(typeof parser, "object");
	});

	const runs = [
		{ functionName: "parseAuthnrAttestationResponse" },
		{ functionName: "parseAttestationObject" },
	];

	runs.forEach(function(run) {
		describe(run.functionName + " (android-safetynet)", function() {
			let ret;
			it("can parse", async function() {
				ret = (run.functionName == "parseAuthnrAttestationResponse")
					? await parser[run.functionName](
						h.lib.makeCredentialAttestationSafetyNetResponse,
					)
					: await parser[run.functionName](
						h.lib.makeCredentialAttestationSafetyNetResponse
							.response
							.attestationObject,
					);
			});

			it("has version", function() {
				assert.strictEqual(ret.get("ver"), "12685023");
			});

			it("has response", function() {
				assert.strictEqual(
					ret.get("response"),
					"eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlFaWpDQ0EzS2dBd0lCQWdJSVlrWW81RjBnODZrd0RRWUpLb1pJaHZjTkFRRUxCUUF3VkRFTE1Ba0dBMVVFQmhNQ1ZWTXhIakFjQmdOVkJBb1RGVWR2YjJkc1pTQlVjblZ6ZENCVFpYSjJhV05sY3pFbE1DTUdBMVVFQXhNY1IyOXZaMnhsSUVsdWRHVnlibVYwSUVGMWRHaHZjbWwwZVNCSE16QWVGdzB4TnpFeU1EUXhNekU0TkROYUZ3MHhPREV5TURNd01EQXdNREJhTUd3eEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlEQXBEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIREExTmIzVnVkR0ZwYmlCV2FXVjNNUk13RVFZRFZRUUtEQXBIYjI5bmJHVWdTVzVqTVJzd0dRWURWUVFEREJKaGRIUmxjM1F1WVc1a2NtOXBaQzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNVajh3WW9QaXhLYmJWOHNnWWd2TVRmWCtkSXNGVE9rZ0tPbGhUMGkwYmNERlpLMnJPeEpaMnVTTFNWaFl2aXBaTkUzSEpRWXV1WXdGaml5K3lrZmF0QUdTalJ6RjFiMzF1NDMvN29HNWpNaDNTMzdhbHdqVWI4Q1dpVHhvaXBWT1l3S0t6dVV5a3FFQ3RqbGhKNEFrV2FEUytaeEtFcU9hZTl0bkNnZUhsbFpFL09SZ2VNYXgyWE5Db0g2c3JURVJja3NqelpackFXeEtzZGZ2VnJYTnpDUjlEeFZBU3VJNkx6d2g4RFNsMkVPb2tic2FuWisrL0pxTWVBQkZmUHdqeXdyYjBwckVVeTBwYWVWc3VkKzBwZWV4Sy81K0U2a3BZR0s0WksybmtvVkx1Z0U1dGFIckFqODNRK1BPYmJ2T3pXY0ZrcG5WS3lqbzZLUUFtWDZXSkFnTUJBQUdqZ2dGR01JSUJRakFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQVRBZEJnTlZIUkVFRmpBVWdoSmhkSFJsYzNRdVlXNWtjbTlwWkM1amIyMHdhQVlJS3dZQkJRVUhBUUVFWERCYU1DMEdDQ3NHQVFVRkJ6QUNoaUZvZEhSd09pOHZjR3RwTG1kdmIyY3ZaM055TWk5SFZGTkhTVUZITXk1amNuUXdLUVlJS3dZQkJRVUhNQUdHSFdoMGRIQTZMeTl2WTNOd0xuQnJhUzVuYjI5bkwwZFVVMGRKUVVjek1CMEdBMVVkRGdRV0JCUUc4SXJRdEZSNkNVU2tpa2IzYWltc20yNmNCVEFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGSGZDdUZDYVozWjJzUzNDaHRDRG9INm1mcnBMTUNFR0ExVWRJQVFhTUJnd0RBWUtLd1lCQkFIV2VRSUZBekFJQmdabmdRd0JBZ0l3TVFZRFZSMGZCQ293S0RBbW9DU2dJb1lnYUhSMGNEb3ZMMk55YkM1d2Eya3VaMjl2Wnk5SFZGTkhTVUZITXk1amNtd3dEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRi9Sek5uQzVEekJVQnRuaDJudEpMV0VRaDl6RWVGWmZQTDlRb2tybEFvWGdqV2dOOHBTUlUxbFZHSXB0ek14R2h5My9PUlJaVGE2RDJEeThodkNEckZJMytsQ1kwMU1MNVE2WE5FNVJzMmQxUmlacE1zekQ0S1FaTkczaFowQkZOUS9janJDbUxCT0dLa0VVMWRtQVhzRkpYSmlPcjJDTlRCT1R1OUViTFdoUWZkQ0YxYnd6eXUrVzZiUVN2OFFEbjVPZE1TL1BxRTFkRWdldC82RUlSQjc2MUtmWlErL0RFNkxwM1RyWlRwT0ZERGdYaCtMZ0dPc3doRWxqOWMzdlpIR0puaGpwdDhya2Jpci8ydUxHZnhsVlo0SzF4NURSTjBQVUxkOXlQU21qZythajErdEh3STFtUW1aVlk3cXZPNURnaE94aEpNR2x6NmxMaVptem9nPSIsIk1JSUVYRENDQTBTZ0F3SUJBZ0lOQWVPcE1CejhjZ1k0UDVwVEhUQU5CZ2txaGtpRzl3MEJBUXNGQURCTU1TQXdIZ1lEVlFRTEV4ZEhiRzlpWVd4VGFXZHVJRkp2YjNRZ1EwRWdMU0JTTWpFVE1CRUdBMVVFQ2hNS1IyeHZZbUZzVTJsbmJqRVRNQkVHQTFVRUF4TUtSMnh2WW1Gc1UybG5iakFlRncweE56QTJNVFV3TURBd05ESmFGdzB5TVRFeU1UVXdNREF3TkRKYU1GUXhDekFKQmdOVkJBWVRBbFZUTVI0d0hBWURWUVFLRXhWSGIyOW5iR1VnVkhKMWMzUWdVMlZ5ZG1salpYTXhKVEFqQmdOVkJBTVRIRWR2YjJkc1pTQkpiblJsY201bGRDQkJkWFJvYjNKcGRIa2dSek13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRREtVa3ZxSHYvT0pHdW8ybklZYU5WV1hRNUlXaTAxQ1haYXo2VElITEdwL2xPSis2MDAvNGhibjd2bjZBQUIzRFZ6ZFFPdHM3RzVwSDBySm5uT0ZVQUs3MUc0bnpLTWZIQ0dVa3NXL21vbmErWTJlbUpRMk4rYWljd0pLZXRQS1JTSWdBdVBPQjZBYWhoOEhiMlhPM2g5UlVrMlQwSE5vdUIyVnp4b01YbGt5VzdYVVI1bXc2SmtMSG5BNTJYRFZvUlRXa050eTVvQ0lOTHZHbW5Sc0oxem91QXFZR1ZRTWMvN3N5Ky9FWWhBTHJWSkVBOEtidHlYK3I4c253VTVDMWhVcndhVzZNV09BUmE4cUJwTlFjV1RrYUllb1l2eS9zR0lKRW1qUjB2RkV3SGRwMWNTYVdJcjYvNGc3Mm43T3FYd2ZpbnU3WllXOTdFZm9PU1FKZUF6QWdNQkFBR2pnZ0V6TUlJQkx6QU9CZ05WSFE4QkFmOEVCQU1DQVlZd0hRWURWUjBsQkJZd0ZBWUlLd1lCQlFVSEF3RUdDQ3NHQVFVRkJ3TUNNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3SFFZRFZSME9CQllFRkhmQ3VGQ2FaM1oyc1MzQ2h0Q0RvSDZtZnJwTE1COEdBMVVkSXdRWU1CYUFGSnZpQjFkbkhCN0FhZ2JlV2JTYUxkL2NHWVl1TURVR0NDc0dBUVVGQndFQkJDa3dKekFsQmdnckJnRUZCUWN3QVlZWmFIUjBjRG92TDI5amMzQXVjR3RwTG1kdmIyY3ZaM055TWpBeUJnTlZIUjhFS3pBcE1DZWdKYUFqaGlGb2RIUndPaTh2WTNKc0xuQnJhUzVuYjI5bkwyZHpjakl2WjNOeU1pNWpjbXd3UHdZRFZSMGdCRGd3TmpBMEJnWm5nUXdCQWdJd0tqQW9CZ2dyQmdFRkJRY0NBUlljYUhSMGNITTZMeTl3YTJrdVoyOXZaeTl5WlhCdmMybDBiM0o1THpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUhMZUpsdVJUN2J2czI2Z3lBWjhzbzgxdHJVSVNkN080NXNrRFVtQWdlMWNueGhHMVAyY05tU3hiV3NvaUN0MmV1eDlMU0QrUEFqMkxJWVJGSFczMS82eG9pYzFrNHRiV1hrRENqaXIzN3hUVE5xUkFNUFV5RlJXU2R2dCtubFBxd25iOE9hMkkvbWFTSnVrY3hEak5TZnBEaC9CZDFsWk5nZGQvOGNMZHNFMyt3eXB1Zko5dVhPMWlRcG5oOXpidUZJd3NJT05HbDFwM0E4Q2d4a3FJL1VBaWgzSmFHT3FjcGNkYUNJemtCYVI5dVlRMVg0azJWZzVBUFJMb3V6Vnk3YThJVms2d3V5NnBtK1Q3SFQ0TFk4aWJTNUZFWmxmQUZMU1c4TndzVno5U0JLMlZxbjFOMFBJTW41eEE2TlpWYzdvODM1RExBRnNoRVdmQzdUSWUzZz09Il19.eyJub25jZSI6ImxXa0lqeDdPNHlNcFZBTmR2UkRYeXVPUk1Gb25VYlZadTQvWHk3SXB2ZFJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVFLZ2x4SHlmblJLQVpWcWlKZElxdHFmNEk5ZHgwb082L3pBTzhUbkRvanZFWkFxMkRaa0J5STFmY29XVlFFcS9PM0ZMSDVhT3d6YnJyeHJKNjVVNWRZcWxBUUlESmlBQklWZ2doNU9KZllSRHpWR0lvd0txVTU3QW5vVmpqZG1takdpOXpsTWtqQVZWOURBaVdDRHIwaVNpMHZpSUtOUE1USWROMjhnV05ta2N3T3I2RFF4NjZNUGZmM09kbSt1NmVKcUxCbDFIMlMydHJBQkhMaW5rbnN5Vk1QbS9CTlVWWjJKRmxyODAiLCJ0aW1lc3RhbXBNcyI6MTUyODkxMTYzNDM4NSwiYXBrUGFja2FnZU5hbWUiOiJjb20uZ29vZ2xlLmFuZHJvaWQuZ21zIiwiYXBrRGlnZXN0U2hhMjU2IjoiSk9DM1Vrc2xzdVZ6MTNlT3BuRkk5QnBMb3FCZzlrMUY2T2ZhUHRCL0dqTT0iLCJjdHNQcm9maWxlTWF0Y2giOmZhbHNlLCJhcGtDZXJ0aWZpY2F0ZURpZ2VzdFNoYTI1NiI6WyJHWFd5OFhGM3ZJbWwzL01mbm1TbXl1S0JwVDNCMGRXYkhSUi80Y2dxK2dBPSJdLCJiYXNpY0ludGVncml0eSI6ZmFsc2UsImFkdmljZSI6IlJFU1RPUkVfVE9fRkFDVE9SWV9ST00sTE9DS19CT09UTE9BREVSIn0.iCF6D2os8DYuDVOnt3zDJB2mSXnZjtWJtl_jzSDx5MrRC9A2fmFBZ6z5kpQZ2MiQ7ootj9WkHMgxqIhrX3dlh2POHAwkIS34ySjLVNsSPprE84eZgqSFLMEYT0GR2eVLHAMPN8n5R8K6buDOGF3nSi6GKzG57Zll8CSob2yiAS9r7spdA6H0TDH-NGzSdbMIId8fZD1dzFKNQr77b6lbIAFgQbRZBrnp-e-H4iH6d21oN2NAYRnR5YURacP6kGGj2cFxswE2908wxv9hiYNKNojeeu8Xc4It7PbhlAuO7ywhQFA81iPCCFm11B8cfUXbWA8l_2ttNPBEMGM6-Z6VyQ",
				);
			});
		});
	});
});
