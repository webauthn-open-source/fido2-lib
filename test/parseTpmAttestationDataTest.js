"use strict";

const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");
var { coerceToBase64, abEqual } = require("../lib/utils");

describe("parseAttestationObject (tpm)", function() {
  it("parser is object", function() {
    assert.isObject(parser);
  });

  var ret;
  it("can parse", function() {
    ret = parser.parseAttestationObject(
      h.lib.makeCredentialAttestationTpmResponse.response.attestationObject
    );
    // console.log("ret", ret);
  });

  it("parser returns Map with correct size", function() {
    assert.instanceOf(ret, Map);
    assert.strictEqual(ret.size, 18);
  });

  it("parses fmt", function() {
    var fmt = ret.get("fmt");
    assert.strictEqual(fmt, "tpm");
  });

  it("parses sig", function() {
    var sig = ret.get("sig");
    assert.instanceOf(sig, ArrayBuffer);
    assert.strictEqual(sig.byteLength, 256);

    var expectedSig = new Uint8Array([
      0x71,
      0x5d,
      0x62,
      0xcd,
      0x61,
      0x94,
      0x58,
      0x8b,
      0x34,
      0x0c,
      0x43,
      0x99,
      0x35,
      0x01,
      0x9d,
      0xae,
      0x23,
      0x4d,
      0x5e,
      0x8e,
      0xa7,
      0x6e,
      0xb1,
      0x83,
      0x2f,
      0x31,
      0x00,
      0x7a,
      0xcc,
      0x02,
      0x2b,
      0xd9,
      0xe3,
      0x60,
      0x60,
      0x8b,
      0x98,
      0xe9,
      0x07,
      0x56,
      0x04,
      0xb2,
      0x69,
      0xf8,
      0x6c,
      0x8c,
      0x21,
      0x0c,
      0x66,
      0x44,
      0x26,
      0xb8,
      0xf5,
      0x26,
      0x10,
      0xe3,
      0x03,
      0x2a,
      0x8b,
      0x2a,
      0xc6,
      0xea,
      0x7f,
      0xb6,
      0x25,
      0xd0,
      0xc0,
      0x6e,
      0x32,
      0x09,
      0x6f,
      0x53,
      0xc9,
      0x6a,
      0x08,
      0x35,
      0x61,
      0x9a,
      0xc9,
      0x0e,
      0x2f,
      0x72,
      0xbe,
      0x98,
      0xb3,
      0xe9,
      0x7a,
      0x28,
      0xc3,
      0xe4,
      0x83,
      0xff,
      0xdd,
      0xd9,
      0x5c,
      0xb0,
      0x85,
      0xfa,
      0x27,
      0x9d,
      0x32,
      0x43,
      0x05,
      0xf1,
      0x3f,
      0xe0,
      0x12,
      0x11,
      0x0f,
      0xad,
      0x06,
      0x47,
      0x4a,
      0x81,
      0xcd,
      0x36,
      0xab,
      0xb6,
      0x10,
      0xc7,
      0x40,
      0x53,
      0x2a,
      0x46,
      0xda,
      0x14,
      0xb6,
      0xe3,
      0xac,
      0x4c,
      0x5e,
      0x63,
      0x79,
      0xd5,
      0x37,
      0x11,
      0x03,
      0xe8,
      0x8d,
      0x10,
      0x39,
      0x88,
      0x23,
      0x42,
      0xda,
      0x76,
      0x82,
      0x09,
      0x9b,
      0x8c,
      0x49,
      0x44,
      0x5d,
      0x94,
      0xf9,
      0xa1,
      0x95,
      0x6e,
      0x6b,
      0x01,
      0xa4,
      0x59,
      0x54,
      0x5e,
      0x35,
      0x65,
      0x91,
      0x02,
      0x8b,
      0x98,
      0x85,
      0x38,
      0xcd,
      0xab,
      0x3b,
      0x45,
      0x29,
      0x1a,
      0xe4,
      0x12,
      0x2d,
      0x4b,
      0xeb,
      0xd4,
      0xca,
      0x90,
      0x3a,
      0xc0,
      0xf2,
      0xb4,
      0xc7,
      0xfb,
      0xa9,
      0x66,
      0x4c,
      0xbf,
      0x04,
      0xff,
      0xe7,
      0xff,
      0x01,
      0x17,
      0xa1,
      0x8d,
      0x74,
      0x1d,
      0xa5,
      0xd9,
      0x5c,
      0xe6,
      0x20,
      0x90,
      0x5b,
      0x57,
      0xa8,
      0x3c,
      0xcf,
      0xb7,
      0x63,
      0xd1,
      0xf4,
      0x64,
      0x8e,
      0x50,
      0x97,
      0x06,
      0x9f,
      0x14,
      0x1b,
      0x62,
      0xef,
      0x4e,
      0xae,
      0x52,
      0xb1,
      0xfb,
      0xa0,
      0xad,
      0x15,
      0x97,
      0x38,
      0x9f,
      0x01,
      0x91,
      0xd3,
      0x29,
      0x94,
      0xf7,
      0xe5,
      0xd2,
      0x6c,
      0xfa,
      0xb2,
      0xc5,
      0x3f,
      0x9f
    ]).buffer;

    assert.isTrue(abEqual(sig, expectedSig), "sig has correct value");
  });

  it("parses version", function() {
    var ver = ret.get("ver");
    assert.isString(ver);
    assert.strictEqual(ver, "2.0");
  });

  it("parses attestation certificate", function() {
    var attCert = ret.get("attCert");

    assert.instanceOf(attCert, ArrayBuffer);
    assert.strictEqual(attCert.byteLength, 1206);
    attCert = coerceToBase64(attCert, "attCert");
    assert.strictEqual(
      attCert,
      "MIIEsjCCA5qgAwIBAgIQEyidpWZzRxOSMNfrAvV1fzANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELTE1OTFENEI2RUFGOThEMDEwNDg2NEI2OTAzQTQ4REQwMDI2MDc3RDMwHhcNMTgwNTIwMTYyMDQ0WhcNMjgwNTIwMTYyMDQ0WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQ6XK2ujM11E7x4SL34p252ncyQTd3+4r5ALQhBbFKS95gUsuENTG+48GBQwu48i06cckm3eH20TUeJvn4+pj6i8LFOrIK14T3P3GFzbxgQLq1KVm63JWDdEXk789JgzQjHNO7DZFKWTEiktwmBUPUA88TjQcXOtrR5EXTrt1FzGzabOepFann3Ny/XtxI8lDZ3QLwPLJfmk7puGtkGNaXOsRC7GLAnoEB7UWvjiyKG6HAtvVTgxcW5OQnHFb9AHycU5QdukXrP0njdCpLCRR0Nq6VMKmVU3MaGh+DCwYEB32sPNPdDkPDWyk16ItwcmXqfSBV5ZOr8ifvcXbCWUWwIDAQABo4IB5TCCAeEwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwbQYDVR0gAQH/BGMwYTBfBgkrBgEEAYI3FR8wUjBQBggrBgEFBQcCAjBEHkIAVABDAFAAQQAgACAAVAByAHUAcwB0AGUAZAAgACAAUABsAGEAdABmAG8AcgBtACAAIABJAGQAZQBuAHQAaQB0AHkwEAYDVR0lBAkwBwYFZ4EFCAMwSgYDVR0RAQH/BEAwPqQ8MDoxODAOBgVngQUCAwwFaWQ6MTMwEAYFZ4EFAgIMB05QQ1Q2eHgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMB8GA1UdIwQYMBaAFMISqVvO+lb4wMFvsVvdAzRHs3qjMB0GA1UdDgQWBBSv4kXTSA8i3NUM0q57lrWpM8p/4TCBswYIKwYBBQUHAQEEgaYwgaMwgaAGCCsGAQUFBzAChoGTaHR0cHM6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1udGMta2V5aWQtMTU5MWQ0YjZlYWY5OGQwMTA0ODY0YjY5MDNhNDhkZDAwMjYwNzdkMy8zYjkxOGFlNC0wN2UxLTQwNTktOTQ5MS0wYWQyNDgxOTA4MTguY2VyMA0GCSqGSIb3DQEBCwUAA4IBAQAs+vqdkDX09fNNYqzbv3Lh0vl6RgGpPGl+MYgO8Lg1I9UKvEUaaUHm845ABS8m7r9p22RCWO6TSEPS0YUYzAsNuiKiGVna4nB9JWZaV9GDS6aMD0nJ8kNciorDsV60j0Yb592kv1VkOKlbTF7+Z10jaapx0CqhxEIUzEBb8y9Pa8oOaQf8ORhDHZp+mbn/W8rUzXSDS0rFbWKaW4tGpVoKGRH+f9vIeXxGlxVS0wqqRm/r+h1aZInta0OOiL/S4367gZyeLL3eUnzdd+eYySYn2XINPbVacK8ZifdsLMwiNtz5uM1jbqpEn2UoB3Hcdn0hc12jTLPWFfg7GiKQ0hk9"
    );
  });

  it("parses x5c", function() {
    var x5c = ret.get("x5c");

    assert.isArray(x5c);
    assert.strictEqual(x5c.length, 1);
    var cert = x5c[0];

    assert.instanceOf(cert, ArrayBuffer);
    assert.strictEqual(cert.byteLength, 1516);
    cert = coerceToBase64(cert, "cert");
    assert.strictEqual(
      cert,
      "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"
    );
  });

  it("parses alg", function() {
    var alg = ret.get("alg");

    assert.isObject(alg);
    assert.strictEqual(Object.keys(alg).length, 2);
    assert.strictEqual(alg.algName, "RSASSA-PKCS1-v1_5_w_SHA1");
    assert.strictEqual(alg.hashAlg, "SHA1");
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
      assert.strictEqual(certInfo.size, 15);
    });

    it("has raw data", function() {
      var rawCertInfo = certInfo.get("rawCertInfo");
      assert.instanceOf(rawCertInfo, ArrayBuffer);
      assert.strictEqual(rawCertInfo.byteLength, 161);

      var expectedRawCertInfo = new Uint8Array([
        0xff,
        0x54,
        0x43,
        0x47,
        0x80,
        0x17,
        0x00,
        0x22,
        0x00,
        0x0b,
        0xbc,
        0x59,
        0xf4,
        0xdf,
        0xd9,
        0xa6,
        0xa4,
        0x2d,
        0xc3,
        0xb8,
        0x66,
        0xaf,
        0xf2,
        0xdf,
        0x0d,
        0x19,
        0x82,
        0x6b,
        0xbf,
        0x01,
        0x4b,
        0x67,
        0xab,
        0x0a,
        0xd6,
        0xeb,
        0xb1,
        0x76,
        0x30,
        0x6b,
        0x80,
        0x07,
        0x00,
        0x14,
        0xac,
        0x9f,
        0x3f,
        0x05,
        0x69,
        0xc6,
        0x62,
        0xfb,
        0x09,
        0x14,
        0x91,
        0xf1,
        0xee,
        0xe3,
        0x18,
        0xc6,
        0xf0,
        0xc3,
        0xdf,
        0x9b,
        0x00,
        0x00,
        0x00,
        0x01,
        0xb1,
        0x5a,
        0x48,
        0xc7,
        0x68,
        0x40,
        0xf9,
        0xe3,
        0xd8,
        0xf3,
        0x9f,
        0x05,
        0x01,
        0xa9,
        0xe0,
        0xc4,
        0xa5,
        0x3f,
        0xbb,
        0xc4,
        0x13,
        0x00,
        0x22,
        0x00,
        0x0b,
        0x71,
        0x21,
        0xae,
        0xbf,
        0xa6,
        0xb9,
        0xaf,
        0xd0,
        0x70,
        0x32,
        0xf4,
        0x2f,
        0x09,
        0x25,
        0xe0,
        0xec,
        0x67,
        0x40,
        0x8d,
        0xd5,
        0x99,
        0xa5,
        0x7b,
        0xfa,
        0x0f,
        0x80,
        0xc7,
        0xf1,
        0x56,
        0x01,
        0x08,
        0x4f,
        0x00,
        0x22,
        0x00,
        0x0b,
        0x01,
        0x52,
        0x34,
        0x79,
        0x0f,
        0xc0,
        0x01,
        0x98,
        0xcd,
        0xbe,
        0xb8,
        0x54,
        0x10,
        0xc2,
        0xb6,
        0xab,
        0x8c,
        0x31,
        0xbb,
        0x02,
        0x05,
        0x3a,
        0x71,
        0xc8,
        0x0c,
        0x5d,
        0x10,
        0x96,
        0x38,
        0x5f,
        0xe3,
        0xb4
      ]).buffer;

      assert.isTrue(
        abEqual(rawCertInfo, expectedRawCertInfo),
        "rawCertInfo has correct value"
      );
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
      assert.strictEqual(
        qualifiedSigner,
        "vFn039mmpC3DuGav8t8NGYJrvwFLZ6sK1uuxdjBrgAc="
      );
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

      assert.strictEqual(resetCount, 1749088739);
    });

    it("parses restartCount", function() {
      var restartCount = certInfo.get("restartCount");

      assert.strictEqual(restartCount, 3639844613);
    });

    it("parses safe", function() {
      var safe = certInfo.get("safe");

      assert.strictEqual(safe, true);
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
      assert.strictEqual(pubArea.size, 10);
    });

    it("has raw data", function() {
      var rawPubArea = pubArea.get("rawPubArea");
      assert.instanceOf(rawPubArea, ArrayBuffer);
      assert.strictEqual(rawPubArea.byteLength, 310);

      var expectedRawPubArea = new Uint8Array([
        0x00,
        0x01,
        0x00,
        0x0b,
        0x00,
        0x06,
        0x04,
        0x72,
        0x00,
        0x20,
        0x9d,
        0xff,
        0xcb,
        0xf3,
        0x6c,
        0x38,
        0x3a,
        0xe6,
        0x99,
        0xfb,
        0x98,
        0x68,
        0xdc,
        0x6d,
        0xcb,
        0x89,
        0xd7,
        0x15,
        0x38,
        0x84,
        0xbe,
        0x28,
        0x03,
        0x92,
        0x2c,
        0x12,
        0x41,
        0x58,
        0xbf,
        0xad,
        0x22,
        0xae,
        0x00,
        0x10,
        0x00,
        0x10,
        0x08,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0xc5,
        0xda,
        0x6f,
        0x4d,
        0x93,
        0x57,
        0xbd,
        0xe2,
        0x02,
        0xf5,
        0xc5,
        0x58,
        0xcd,
        0x0a,
        0x31,
        0x56,
        0xd2,
        0x54,
        0xf2,
        0xe0,
        0xad,
        0x9a,
        0xb5,
        0x79,
        0x31,
        0xf9,
        0x82,
        0x6b,
        0x74,
        0x7d,
        0xe1,
        0xac,
        0x4f,
        0x29,
        0xd6,
        0x07,
        0x08,
        0x74,
        0xdc,
        0xe5,
        0x79,
        0x10,
        0xe1,
        0x98,
        0x44,
        0x49,
        0x9d,
        0x8e,
        0x42,
        0x47,
        0x03,
        0x39,
        0xb1,
        0x70,
        0xd0,
        0x22,
        0xb5,
        0x01,
        0xab,
        0x88,
        0xe9,
        0xc2,
        0xf4,
        0xed,
        0x30,
        0x2e,
        0x47,
        0x19,
        0xc7,
        0x0d,
        0xeb,
        0xe8,
        0x84,
        0x24,
        0x03,
        0xed,
        0x9b,
        0xdf,
        0xc2,
        0x27,
        0x30,
        0xa6,
        0x1a,
        0x1b,
        0x70,
        0xf6,
        0x16,
        0xc5,
        0xf1,
        0xb7,
        0x00,
        0xca,
        0xcf,
        0x78,
        0x46,
        0x13,
        0x7d,
        0xc4,
        0xb2,
        0xd4,
        0x69,
        0xa8,
        0xe1,
        0x5a,
        0xab,
        0x4f,
        0xad,
        0x86,
        0x57,
        0x08,
        0x40,
        0x22,
        0xd2,
        0x8f,
        0x44,
        0xd9,
        0x07,
        0x53,
        0x23,
        0x12,
        0x6b,
        0x70,
        0x07,
        0xc9,
        0x81,
        0x93,
        0x9f,
        0xdf,
        0x72,
        0x4c,
        0xaf,
        0x4f,
        0xbe,
        0x47,
        0x50,
        0x40,
        0x43,
        0x1a,
        0x4e,
        0xa0,
        0x64,
        0x43,
        0x0b,
        0xcb,
        0x2c,
        0xfa,
        0xd7,
        0xd0,
        0x5b,
        0xdb,
        0x9f,
        0x64,
        0xb5,
        0xb0,
        0xe0,
        0x95,
        0x2e,
        0xcf,
        0x86,
        0x79,
        0x27,
        0x3d,
        0x6c,
        0x6d,
        0xfa,
        0x81,
        0x60,
        0x1f,
        0x14,
        0x50,
        0x33,
        0x16,
        0xa1,
        0x3d,
        0x07,
        0x82,
        0xc3,
        0x1a,
        0x3e,
        0x6b,
        0xdd,
        0xed,
        0x3d,
        0x7b,
        0xc4,
        0x6b,
        0xc1,
        0xfa,
        0x9b,
        0xef,
        0x0d,
        0xff,
        0x83,
        0xb7,
        0xde,
        0xaf,
        0x14,
        0x6b,
        0x58,
        0x2c,
        0x46,
        0x44,
        0x82,
        0x1a,
        0x3c,
        0x62,
        0xed,
        0xba,
        0xa6,
        0xbe,
        0x42,
        0x2b,
        0xf0,
        0x4e,
        0x43,
        0xed,
        0xaf,
        0x5f,
        0xd3,
        0x78,
        0x30,
        0x86,
        0x15,
        0x3d,
        0x73,
        0x61,
        0xa2,
        0x03,
        0x06,
        0x1a,
        0x62,
        0x98,
        0xab,
        0x26,
        0xe1,
        0x33,
        0x7c,
        0xa1,
        0xc9,
        0xed,
        0x06,
        0x74,
        0x1a,
        0x59,
        0x05,
        0x47,
        0x79,
        0x88,
        0xe7,
        0x20,
        0x30,
        0x4e,
        0xae,
        0x18,
        0x9d,
        0x7f
      ]).buffer;

      assert.isTrue(
        abEqual(rawPubArea, expectedRawPubArea),
        "rawPubArea has correct value"
      );
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
      assert.isTrue(
        objectAttributes.has("FIXED_TPM"),
        "objectAttributes has FIXED_TPM"
      );
      assert.isTrue(
        objectAttributes.has("FIXED_PARENT"),
        "objectAttributes has FIXED_PARENT"
      );
      assert.isTrue(
        objectAttributes.has("SENSITIVE_DATA_ORIGIN"),
        "objectAttributes has SENSITIVE_DATA_ORIGIN"
      );
      assert.isTrue(
        objectAttributes.has("USER_WITH_AUTH"),
        "objectAttributes has USER_WITH_AUTH"
      );
      assert.isTrue(
        objectAttributes.has("NO_DA"),
        "objectAttributes has NO_DA"
      );
      assert.isTrue(
        objectAttributes.has("DECRYPT"),
        "objectAttributes has DECRYPT"
      );
      assert.isTrue(
        objectAttributes.has("SIGN_ENCRYPT"),
        "objectAttributes has SIGN_ENCRYPT"
      );
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
      assert.strictEqual(exponent, 65537);
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
    assert.strictEqual(
      credentialPublicKeyJwk.alg,
      "RSASSA-PKCS1-v1_5_w_SHA256"
    );
    assert.strictEqual(
      credentialPublicKeyJwk.n,
      "xdpvTZNXveIC9cVYzQoxVtJU8uCtmrV5MfmCa3R94axPKdYHCHTc5XkQ4ZhESZ2OQkcDObFw0CK1AauI6cL07TAuRxnHDevohCQD7ZvfwicwphobcPYWxfG3AMrPeEYTfcSy1Gmo4VqrT62GVwhAItKPRNkHUyMSa3AHyYGTn99yTK9PvkdQQEMaTqBkQwvLLPrX0Fvbn2S1sOCVLs+GeSc9bG36gWAfFFAzFqE9B4LDGj5r3e09e8Rrwfqb7w3/g7ferxRrWCxGRIIaPGLtuqa+QivwTkPtr1/TeDCGFT1zYaIDBhpimKsm4TN8ocntBnQaWQVHeYjnIDBOrhidfw=="
    );
    assert.strictEqual(credentialPublicKeyJwk.e, "AQAB");
  });

  it("parses credentialPublicKeyPem", function() {
    var credentialPublicKeyPem = ret.get("credentialPublicKeyPem");
    assert.isString(credentialPublicKeyPem);
    assert.strictEqual(credentialPublicKeyPem.length, 451);
  });
});
