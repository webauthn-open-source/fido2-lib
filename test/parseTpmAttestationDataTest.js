"use strict";

const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");
var {
    coerceToBase64
} = require("../lib/utils");


describe("parseAttestationObject (tpm)", function() {
    it("parser is object", function() {
        assert.isObject(parser);
    });

    var ret;
    it("can parse", function() {
        ret = parser.parseAttestationObject(h.lib.makeCredentialAttestationTpmResponse.response.attestationObject);
        // console.log("ret", ret);
    });

    it("parser returns Map with correct size", function() {
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 16);
    });

    it("parses fmt", function() {
        var fmt = ret.get("fmt");
        assert.strictEqual(fmt, "tpm");
    });

    it("parses attestation certificate", function() {
        var attCert = ret.get("attCert");

        assert.instanceOf(attCert, ArrayBuffer);
        assert.strictEqual(attCert.byteLength, 1186);
        attCert = coerceToBase64(attCert, "attCert");
        assert.strictEqual(attCert, "MIIEnjCCA4agAwIBAgIQL7RbTvD3QMOAUdc2F8018jANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtSUZYLUtleUlkLTQwQjg2ODJCOEQxODQ1MEEyQjA2ODQ5RDlCNUNEOTZGNENEREY0QkUwHhcNMTgwMzE5MjIxNjUwWhcNMjgwMzE5MjIxNjUwWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAklyX9jgSez7tYsp5Kq2E1p++9wS1EbQwn7KH0qJwwIfsJ3tmx+I2OWUj/++pIQ9ag+1v/46P4Bhi/eHgANsi0nktmH+NEFaF7EDKDtZ/Qe52rSCsA7LdF2riRoS305YrfbXn3HeRnGEcRPZkCOhtZVAIz2SoJBzqFdTCcMGACneXS2olcOm3SpAqY1zgednhveahtPaUVYnpv1yei5E82kAmAwB9Wxqx/yK0i4DRQqW0nVdW4INfch913ph+BFWijZIieShCaLv25JkkyPYJXugXt9H71eV91CfE/vshf0tP/7o/ZA7fir/1rIdNFFdpurvI708K1ce2mIgj/V3dtwIDAQABo4IB0TCCAc0wDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwbQYDVR0gAQH/BGMwYTBfBgkrBgEEAYI3FR8wUjBQBggrBgEFBQcCAjBEHkIAVABDAFAAQQAgACAAVAByAHUAcwB0AGUAZAAgACAAUABsAGEAdABmAG8AcgBtACAAIABJAGQAZQBuAHQAaQB0AHkwEAYDVR0lBAkwBwYFZ4EFCAMwUQYDVR0RAQH/BEcwRaRDMEExFjAUBgVngQUCAQwLaWQ6NDk0NjU4MDAxEzARBgVngQUCAgwIU0xCIDk2NjUxEjAQBgVngQUCAwwHaWQ6MDUyODAfBgNVHSMEGDAWgBRNDeeaLngPuj0cMQN+/a6ODsOwpzAdBgNVHQ4EFgQUwdMSw0PYqzB1qkNjLACqzVUeR1QwgZgGCCsGAQUFBwEBBIGLMIGIMIGFBggrBgEFBQcwAoZ5aHR0cDovL2F6Y3Nwcm9kbmN1YWlrcHVibGlzaC5ibG9iLmNvcmUud2luZG93cy5uZXQvbmN1LWlmeC1rZXlpZC00MGI4NjgyYjhkMTg0NTBhMmIwNjg0OWQ5YjVjZDk2ZjRjZGRmNGJlL2NlcnRpZmljYXRlLmNlcjANBgkqhkiG9w0BAQsFAAOCAQEAskH81SG3Qx2fAwZ3rMaAm0b1Js6ZY0qsWNmiU7vWAkpJQvHY+B2lA/45sm04LWbFFXN/C6j7frRqXqqQ1vcIbMrBCK12PcbVKaUaWRB8swTHmyPw6psnRxj91nfwk9txZGOVVLFZKQjaYLmjvfiQbFeEEyUyqUQQyAFdfP5Ll4MsaWv3TW9TMKqDuo1eMJdr2S9iCD59PO+msmeVsKEoIatiMdTH0OHMp42VKggf8Wi3NMqlumVQMeI5eF3hlmDLxaWvSGWBuRBbOGrKrBLBPnwzob4ST4fBZiu7dkG/NgBrzpPu+DYEMx1LzZRNeI3T7lg+O1FWweGIYDT6rL+g1A==");
    });

    it("parses x5c", function() {
        var x5c = ret.get("x5c");

        assert.isArray(x5c);
        assert.strictEqual(x5c.length, 1);
        var cert = x5c[0];

        assert.instanceOf(cert, ArrayBuffer);
        assert.strictEqual(cert.byteLength, 1516);
        cert = coerceToBase64(cert, "cert");
        assert.strictEqual(cert, "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");
    });

    it("parses alg", function() {
        var alg = ret.get("alg");

        assert.isNumber(alg);
        assert.strictEqual(alg, -262);
    });

    describe("certInfo", function() {
        var certInfo;
        it("exists", function() {
            certInfo = ret.get("certInfo");
        });

        it("is Map", function() {
            assert.instanceOf(certInfo, Map);
        });

        it("is correct length", function() {
            assert.strictEqual(certInfo.size, 14);
        });

        it("parses magic", function() {
            var magic = certInfo.get("magic");

            assert.strictEqual(magic, 0xff544347);
        });

        it("parses type", function() {
            var type = certInfo.get("type");

            assert.isString(type);
            assert.strictEqual(type, "TPM_ST_ATTEST_CERTIFY");
        });

        it("parses qualifiedSigner", function() {
            var qualifiedSignerHashType = certInfo.get("qualifiedSignerHashType");
            assert.strictEqual(qualifiedSignerHashType, "TPM_ALG_SHA256");

            var qualifiedSigner = certInfo.get("qualifiedSigner");
            assert.instanceOf(qualifiedSigner, ArrayBuffer);
            assert.strictEqual(qualifiedSigner.byteLength, 32);
            qualifiedSigner = coerceToBase64(qualifiedSigner, "qualifiedSigner");
            assert.strictEqual(qualifiedSigner, "+KrSaVwQePbiXC3u6h2AtZamAyG4klO/eoUCf9ZTsLw=");
        });

        it("parses extraData", function() {
            var extraData = certInfo.get("extraData");

            assert.instanceOf(extraData, ArrayBuffer);
            assert.strictEqual(extraData.byteLength, 20);
        });

        it("parses clock", function() {
            var clock = certInfo.get("clock");

            assert.instanceOf(clock, ArrayBuffer);
            assert.strictEqual(clock.byteLength, 8);
        });

        it("parses resetCount", function() {
            var resetCount = certInfo.get("resetCount");

            assert.strictEqual(resetCount, 1163738240);
        });

        it("parses restartCount", function() {
            var restartCount = certInfo.get("restartCount");

            assert.strictEqual(restartCount, 4148181485);
        });

        it("parses safe", function() {
            var safe = certInfo.get("safe");

            assert.strictEqual(safe, false);
        });

        it("parses firmwareVersion", function() {
            var firmwareVersion = certInfo.get("firmwareVersion");

            assert.instanceOf(firmwareVersion, ArrayBuffer);
            assert.strictEqual(firmwareVersion.byteLength, 8);
        });

        it("parses nameHashType", function() {
            var nameHashType = certInfo.get("nameHashType");

            assert.strictEqual(nameHashType, "TPM_ALG_SHA256");
        });

        it("parses name", function() {
            var name = certInfo.get("name");

            assert.instanceOf(name, ArrayBuffer);
            assert.strictEqual(name.byteLength, 32);
        });

        it("parses qualifiedNameHashType", function() {
            var qualifiedNameHashType = certInfo.get("qualifiedNameHashType");
            assert.strictEqual(qualifiedNameHashType, "TPM_ALG_SHA256");

            var qualifiedName = certInfo.get("qualifiedName");
            assert.instanceOf(qualifiedName, ArrayBuffer);
            assert.strictEqual(qualifiedName.byteLength, 32);
        });
    });

    describe("pubArea", function() {
        var pubArea;
        it("exists", function() {
            pubArea = ret.get("pubArea");
        });

        it("is Map", function() {
            assert.instanceOf(pubArea, Map);
        });

        it("is correct length", function() {
            assert.strictEqual(pubArea.size, 9);
        });

        it("parses type", function() {
            var type = pubArea.get("type");

            assert.strictEqual(type, "TPM_ALG_RSA");
        });

        it("parses nameAlg", function() {
            var nameAlg = pubArea.get("nameAlg");

            assert.strictEqual(nameAlg, "TPM_ALG_SHA256");
        });

        it("parses objectAttributes", function() {
            var objectAttributes = pubArea.get("objectAttributes");

            assert.instanceOf(objectAttributes, Set);
            assert.strictEqual(objectAttributes.size, 7);
            assert.isTrue(objectAttributes.has("FIXED_TPM"), "objectAttributes has FIXED_TPM");
            assert.isTrue(objectAttributes.has("FIXED_PARENT"), "objectAttributes has FIXED_PARENT");
            assert.isTrue(objectAttributes.has("SENSITIVE_DATA_ORIGIN"), "objectAttributes has SENSITIVE_DATA_ORIGIN");
            assert.isTrue(objectAttributes.has("USER_WITH_AUTH"), "objectAttributes has USER_WITH_AUTH");
            assert.isTrue(objectAttributes.has("NO_DA"), "objectAttributes has NO_DA");
            assert.isTrue(objectAttributes.has("DECRYPT"), "objectAttributes has DECRYPT");
            assert.isTrue(objectAttributes.has("SIGN_ENCRYPT"), "objectAttributes has SIGN_ENCRYPT");

        });

        it("parses authPolicy", function() {
            var authPolicy = pubArea.get("authPolicy");

            assert.instanceOf(authPolicy, ArrayBuffer);
            assert.strictEqual(authPolicy.byteLength, 32);
        });

        it("parses symmetric", function() {
            var symmetric = pubArea.get("symmetric");

            assert.strictEqual(symmetric, "TPM_ALG_NULL");
        });

        it("parses scheme", function() {
            var scheme = pubArea.get("scheme");

            assert.strictEqual(scheme, "TPM_ALG_NULL");
        });

        it("parses keyBits", function() {
            var keyBits = pubArea.get("keyBits");

            assert.strictEqual(keyBits, 2048);
        });

        it("parses exponent", function() {
            var exponent = pubArea.get("exponent");

            assert.isNumber(exponent);
            assert.strictEqual(exponent, 0);
        });

        it("parses unique", function() {
            var unique = pubArea.get("unique");

            assert.instanceOf(unique, ArrayBuffer);
            assert.strictEqual(unique.byteLength, 256);
        });
    });

    it("parses rawAuthnrData", function() {
        var rawAuthnrData = ret.get("rawAuthnrData");

        assert.instanceOf(rawAuthnrData, ArrayBuffer);
        assert.strictEqual(rawAuthnrData.byteLength, 359);
    });

    it("parses rpIdHash", function() {
        var rpIdHash = ret.get("rpIdHash");

        assert.instanceOf(rpIdHash, ArrayBuffer);
        assert.strictEqual(rpIdHash.byteLength, 32);
    });

    it("parses flags", function() {
        var flags = ret.get("flags");

        assert.instanceOf(flags, Set);
        assert.strictEqual(flags.size, 3);
        assert.isTrue(flags.has("UP"), "flags has UP");
        assert.isTrue(flags.has("UV"), "flags has UV");
        assert.isTrue(flags.has("AT"), "flags has AT");
    });

    it("parses counter", function() {
        var counter = ret.get("counter");

        assert.isNumber(counter);
        assert.strictEqual(counter, 0);
    });

    it("parses aaguid", function() {
        var aaguid = ret.get("aaguid");

        assert.instanceOf(aaguid, ArrayBuffer);
        assert.strictEqual(aaguid.byteLength, 16);
    });

    it("parses credId", function() {
        var credIdLen = ret.get("credIdLen");
        assert.strictEqual(credIdLen, 32);
        var credId = ret.get("credId");
        assert.instanceOf(credId, ArrayBuffer);
        assert.strictEqual(credId.byteLength, 32);
    });

    it("parses credentialPublicKeyCose", function() {
        var credentialPublicKeyCose = ret.get("credentialPublicKeyCose");

        assert.instanceOf(credentialPublicKeyCose, ArrayBuffer);
        assert.strictEqual(credentialPublicKeyCose.byteLength, 272);
    });

    it("parses credentialPublicKeyJwk", function() {
        var credentialPublicKeyJwk = ret.get("credentialPublicKeyJwk");

        assert.isObject(credentialPublicKeyJwk);
        assert.strictEqual(Object.keys(credentialPublicKeyJwk).length, 4);
        assert.strictEqual(credentialPublicKeyJwk.kty, "RSA");
        assert.strictEqual(credentialPublicKeyJwk.alg, "-257");
        assert.strictEqual(credentialPublicKeyJwk.n, "m2Zx+N1turdeUrpmYW//m4DOLEu3k0j3YS0JFqLQspj18y1mNP3YAHZio8l9bgQ50BguGaRf+GPEQR0zCV3ZXeHQOKyw3GV29ImxEQGRVCRZvS01HhuCrTS+AnkFXdgHbixR50EzB0BVEOoN7+1o9E01DYYorp5UQb3ltlqtGRxrSJt0VJf1DykGk5MxWln1WbULsA2pNFqEcAxqbW0pWzf69xGoXYpCOOeAQ2elpf1jrfIAuEyDFgxuVjlsoktcP0BZL2vu7QBqB6tVohf++JLmgVEq/jX26BYi2gEyZiDQ4VlT/KqkY/jKxD4GHn3RHaNDUTC6vVy3meTZwX1+Fw==");
        assert.strictEqual(credentialPublicKeyJwk.e, "AQAB");
    });

    it("parses credentialPublicKeyPem", function() {
        var credentialPublicKeyPem = ret.get("credentialPublicKeyPem");
        assert.isString(credentialPublicKeyPem);
        assert.strictEqual(credentialPublicKeyPem.length, 451);
    });
});
