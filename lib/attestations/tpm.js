/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

"use strict";

const {
    printHex,
    coerceToArrayBuffer,
    coerceToBase64,
    abEqual,
    abToBuf,
    abToPem,
} = require("../utils");

const {
    Certificate,
    CertManager
} = require("../certUtils");

const crypto = require("crypto");

function tpmParseFn(attStmt) {
    var ret = new Map();

    // x5c
    var x5c = attStmt.x5c;

    if (!Array.isArray(x5c)) {
        throw new TypeError("expected TPM attestation x5c field to be of type Array");
    }

    if (x5c.length < 1) {
        throw new TypeError("no certificates in TPM x5c field");
    }

    var newX5c = [];
    for (let cert of x5c) {
        cert = coerceToArrayBuffer(cert, "TPM x5c cert");
        newX5c.push(cert);
    }
    // first certificate MUST be the attestation cert
    ret.set("attCert", newX5c.shift());
    // the rest of the certificates (if any) are the certificate chain
    ret.set("x5c", newX5c);

    // ecdaa
    if (attStmt.ecdaaKeyId) ret.set("ecdaaKeyId", attStmt.ecdaaKeyId);

    // sig
    ret.set("sig", coerceToArrayBuffer(attStmt.sig, "tpm signature"));

    // sig
    ret.set("ver", attStmt.ver);

    // alg
    ret.set("alg", attStmt.alg);

    // certInfo
    var certInfo = parseCertInfo(coerceToArrayBuffer(attStmt.certInfo, "certInfo"));
    ret.set("certInfo", certInfo);

    // pubArea
    var pubArea = parsePubArea(coerceToArrayBuffer(attStmt.pubArea, "pubArea"));
    ret.set("pubArea", pubArea);

    return ret;
}

function parseCertInfo(certInfo) {
    if (!(certInfo instanceof ArrayBuffer)) {
        throw new Error("tpm attestation: expected certInfo to be ArrayBuffer");
    }

    var dv = new DataView(certInfo);
    var offset = 0;
    var ret;
    var ci = new Map();
    ci.set("rawCertInfo", certInfo);

    // TPM_GENERATED_VALUE magic number
    var magic = dv.getUint32(offset);
    // if this isn't the magic number, the rest of the parsing is going to fail
    if (magic !== 0xff544347) { // 0xFF + 'TCG'
        throw new Error("tpm attestation: certInfo had bad magic number: " + magic.toString(16));
    }
    ci.set("magic", magic);
    offset += 4;


    // TPMI_ST_ATTEST type
    var type = decodeStructureTag(dv.getUint16(offset));
    // if this isn't the right type, the rest of the parsing is going to fail
    if (type !== "TPM_ST_ATTEST_CERTIFY") {
        throw new Error("tpm attestation: got wrong type. expected 'TPM_ST_ATTEST_CERTIFY' got: " + type);
    }
    ci.set("type", type);
    offset += 2;

    // TPM2B_NAME qualifiedSigner
    ret = getTpm2bName(dv, offset);
    ci.set("qualifiedSignerHashType", ret.hashType);
    ci.set("qualifiedSigner", ret.nameHash);
    offset = ret.offset;

    // TPM2B_DATA extraData
    ret = getSizedElement(dv, offset);
    ci.set("extraData", ret.buf);
    offset = ret.offset;

    // TPMS_CLOCK_INFO clockInfo
    // UINT64 clock
    ci.set("clock", dv.buffer.slice(offset, offset + 8));
    offset += 8;
    // UINT32 resetCount
    ci.set("resetCount", dv.getUint32(offset));
    offset += 4;
    // UINT32 restartCount
    ci.set("restartCount", dv.getUint32(offset));
    offset += 4;
    // boolean safe
    ci.set("safe", !!dv.getUint8(offset));
    offset++;

    // UINT64 firmwareVersion
    ci.set("firmwareVersion", dv.buffer.slice(offset, offset + 8));
    offset += 8;

    // TPMU_ATTEST attested
    // TPM2B_NAME name
    ret = getTpm2bName(dv, offset);
    ci.set("nameHashType", ret.hashType);
    ci.set("name", ret.nameHash);
    offset = ret.offset;

    // TPM2B_NAME qualifiedName
    ret = getTpm2bName(dv, offset);
    ci.set("qualifiedNameHashType", ret.hashType);
    ci.set("qualifiedName", ret.nameHash);
    offset = ret.offset;

    if (offset !== certInfo.byteLength) {
        throw new Error("tpm attestation: left over bytes when parsing cert info");
    }

    return ci;
}

function parsePubArea(pubArea) {
    if (!(pubArea instanceof ArrayBuffer)) {
        throw new Error("tpm attestation: expected pubArea to be ArrayBuffer");
    }

    var dv = new DataView(pubArea);
    var offset = 0;
    var ret;
    var pa = new Map();
    pa.set("rawPubArea", pubArea);

    // TPMI_ALG_PUBLIC type
    var type = algIdToStr(dv.getUint16(offset));
    pa.set("type", type);
    offset += 2;

    // TPMI_ALG_HASH nameAlg
    pa.set("nameAlg", algIdToStr(dv.getUint16(offset)));
    offset += 2;

    // TPMA_OBJECT objectAttributes
    pa.set("objectAttributes", decodeObjectAttributes(dv.getUint32(offset)));
    offset += 4;

    // TPM2B_DIGEST authPolicy
    ret = getSizedElement(dv, offset);
    pa.set("authPolicy", ret.buf);
    offset = ret.offset;

    // TPMU_PUBLIC_PARMS parameters
    if (type !== "TPM_ALG_RSA") {
        throw new Error("tpm attestation: only TPM_ALG_RSA supported");
    }
    // TODO: support other types
    pa.set("symmetric", algIdToStr(dv.getUint16(offset)));
    offset += 2;
    pa.set("scheme", algIdToStr(dv.getUint16(offset)));
    offset += 2;
    pa.set("keyBits", dv.getUint16(offset));
    offset += 2;
    var exponent = dv.getUint32(offset);
    if (exponent === 0) exponent = 65536;
    pa.set("exponent", exponent);
    offset += 4;

    // TPMU_PUBLIC_ID unique
    ret = getSizedElement(dv, offset);
    pa.set("unique", ret.buf);
    offset = ret.offset;

    if (offset !== pubArea.byteLength) {
        throw new Error("tpm attestation: left over bytes when parsing public area");
    }

    return pa;
}

// eslint-disable complexity
function decodeStructureTag(t) {
    /* eslint complexity: ["off"] */
    switch (t) {
        case 0x00C4: return "TPM_ST_RSP_COMMAND";
        case 0x8000: return "TPM_ST_NULL";
        case 0x8001: return "TPM_ST_NO_SESSIONS";
        case 0x8002: return "TPM_ST_SESSIONS";
        case 0x8003: return "TPM_RESERVED_0x8003";
        case 0x8004: return "TPM_RESERVED_0x8004";
        case 0x8014: return "TPM_ST_ATTEST_NV";
        case 0x8015: return "TPM_ST_ATTEST_COMMAND_AUDIT";
        case 0x8016: return "TPM_ST_ATTEST_SESSION_AUDIT";
        case 0x8017: return "TPM_ST_ATTEST_CERTIFY";
        case 0x8018: return "TPM_ST_ATTEST_QUOTE";
        case 0x8019: return "TPM_ST_ATTEST_TIME";
        case 0x801A: return "TPM_ST_ATTEST_CREATION";
        case 0x801B: return "TPM_RESERVED_0x801B";
        case 0x8021: return "TPM_ST_CREATION";
        case 0x8022: return "TPM_ST_VERIFIED";
        case 0x8023: return "TPM_ST_AUTH_SECRET";
        case 0x8024: return "TPM_ST_HASHCHECK";
        case 0x8025: return "TPM_ST_AUTH_SIGNED";
        case 0x8029: return "TPM_ST_FU_MANIFEST";
        default:
            throw new Error("tpm attestation: unknown structure tag: " + t.toString(16));
    }
}

function decodeObjectAttributes(oa) {
    var attrList = [
        "RESERVED_0",
        "FIXED_TPM",
        "ST_CLEAR",
        "RESERVED_3",
        "FIXED_PARENT",
        "SENSITIVE_DATA_ORIGIN",
        "USER_WITH_AUTH",
        "ADMIN_WITH_POLICY",
        "RESERVED_8",
        "RESERVED_9",
        "NO_DA",
        "ENCRYPTED_DUPLICATION",
        "RESERVED_12",
        "RESERVED_13",
        "RESERVED_14",
        "RESERVED_15",
        "RESTRICTED",
        "DECRYPT",
        "SIGN_ENCRYPT",
        "RESERVED_19",
        "RESERVED_20",
        "RESERVED_21",
        "RESERVED_22",
        "RESERVED_23",
        "RESERVED_24",
        "RESERVED_25",
        "RESERVED_26",
        "RESERVED_27",
        "RESERVED_28",
        "RESERVED_29",
        "RESERVED_30",
        "RESERVED_31"
    ];

    var ret = new Set();

    for (let i = 0; i < 32; i++) {
        let bit = 1 << i;
        if (oa & bit) {
            ret.add(attrList[i]);
        }
    }

    return ret;
}

function getSizedElement(dv, offset) {
    var size = dv.getUint16(offset);
    offset += 2;
    var buf = dv.buffer.slice(offset, offset + size);
    dv = new DataView(buf);
    offset += size;

    return {
        size,
        dv,
        buf,
        offset
    };
}

function getTpm2bName(dvIn, oIn) {
    var {
        offset,
        dv
    } = getSizedElement(dvIn, oIn);

    var hashType = algIdToStr(dv.getUint16(0));
    var nameHash = dv.buffer.slice(2);

    return {
        hashType,
        nameHash,
        offset
    };
}

function algIdToStr(hashType) {
    var hashList = [
        "TPM_ALG_ERROR", // 0
        "TPM_ALG_RSA", // 1
        null,
        null,
        "TPM_ALG_SHA1", // 4
        "TPM_ALG_HMAC", // 5
        "TPM_ALG_AES", // 6
        "TPM_ALG_MGF1", // 7
        null,
        "TPM_ALG_KEYEDHASH", // 8
        "TPM_ALG_XOR", // A
        "TPM_ALG_SHA256", // B
        "TPM_ALG_SHA384", // C
        "TPM_ALG_SHA512", // D
        null,
        null,
        "TPM_ALG_NULL", // 10
        null,
        "TPM_ALG_SM3_256", // 12
        "TPM_ALG_SM4", // 13
        "TPM_ALG_RSASSA", // 14
        "TPM_ALG_RSAES", // 15
        "TPM_ALG_RSAPSS", // 16
        "TPM_ALG_OAEP", // 17
        "TPM_ALG_ECDSA" // 18
    ];

    return hashList[hashType];
}

async function tpmValidateFn() {
    var certInfo = this.authnrData.get("certInfo");
    var magic = certInfo.get("magic");
    if (magic !== 0xff544347) { // 0xFF + 'TCG'
        throw new Error("tpm attestation: certInfo had bad magic number: " + magic.toString(16));
    }

    var parsedAttCert = this.authnrData.get("attCert");

    // decode attestation cert
    var attCert = new Certificate(coerceToBase64(parsedAttCert, "parsedAttCert"));
    try {
        await attCert.verify();
    } catch (e) {
        let err = e;
        if (err.message === "Please provide issuer certificate as a parameter") {
            // err = new Error("Root attestation certificate for this token could not be found. Please contact your security key vendor.");
            this.audit.warning.set("attesation-not-validated", "could not validate attestation because the root attestation certification could not be found");
        } else {
            throw err;
        }
    }

    // public key from pubArea matches credentialPublicKey in credData
    var jwk = this.authnrData.get("credentialPublicKeyJwk");
    var pubArea = this.authnrData.get("pubArea");
    // check that algorithm is RSA
    // check n
    var webAuthnN = coerceToArrayBuffer(jwk.n, "jwk.n");
    var tpmN = pubArea.get("unique");
    // printHex("webAuthnN", webAuthnN);
    // printHex("tpmN", tpmN);
    if (!abEqual(webAuthnN, tpmN)) {
        throw new Error("tpm attesation: TPM public key didn't match RSA public key");
    }
    // check parameters: keyBits, exponent, scheme, symmetric
    var tpmExp = pubArea.get("exponent");
    var webAuthnExp;
    // if (tpmExp !== webAuthnExp) {
    //     throw new Error("WebAuthn exponent did not match TPM exponent");
    // }

    // verify extra data
    var rawAuthnrData = this.authnrData.get("rawAuthnrData");
    var rawClientData = this.clientData.get("rawClientDataJson");
    const cdHash = crypto.createHash("sha256");
    cdHash.update(abToBuf(rawClientData));
    var clientDataHashBuf = cdHash.digest();
    var clientDataHash = new Uint8Array(clientDataHashBuf).buffer;

    var alg = this.clientData.get("alg");
    function algToHashStr() {
        console.log("XXX THIS IS BAD XXX");
        return "SHA1";
    }
    var hashAlg = algToHashStr(alg);
    const attHash = crypto.createHash(hashAlg);
    attHash.update(abToBuf(rawAuthnrData));
    attHash.update(clientDataHashBuf);
    var extraDataHashBuf = attHash.digest();
    var generatedExtraDataHash = new Uint8Array(extraDataHashBuf).buffer;
    var extraData = certInfo.get("extraData");
    if (!abEqual(generatedExtraDataHash, extraData)) {
        throw new Error("extraData hash did not match authnrData + clientDataHash hashed");
    }

    // verify pubArea name
    var pubAreaName = certInfo.get("name");
    var pubAreaNameHashAlg = tpmHashToNpmHash(certInfo.get("nameHashType"));
    const pubAreaNameHash = crypto.createHash(pubAreaNameHashAlg);
    pubAreaNameHash.update(abToBuf(pubArea.get("rawPubArea")));
    var pubAreaNameHashBuf = pubAreaNameHash.digest();
    var generatedPubAreaNameHash = new Uint8Array(pubAreaNameHashBuf).buffer;
    if (!abEqual(generatedPubAreaNameHash, pubAreaName)) {
        throw new Error("pubAreaName hash did not match hash of publicArea");
    }

    // verify signature over certInfo
    var sig = this.authnrData.get("sig");
    var rawCertInfo = certInfo.get("rawCertInfo");
    var attCertPem = abToPem("CERTIFICATE", parsedAttCert);
    // console.log("hashAlg", hashAlg);
    // printHex("sig", sig);
    // printHex("rawCertInfo", rawCertInfo);
    // console.log("attCertPem", attCertPem);
    const verifySig = crypto.createVerify(hashAlg);
    verifySig.write(abToBuf(rawCertInfo));
    verifySig.end();
    var res = verifySig.verify(attCertPem, abToBuf(sig));
    if (!res) {
        throw new Error("TPM attestation signature verification failed");
    }

    // console.log("authnrData", this.authnrData);

    // https: //fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-authenticator-transports-extension-v1.2-ps-20170411.html
    // cert MUST be x.509v3
    if (attCert.getVersion() !== 3) {
        throw new Error("expected TPM attestation certificate to be x.509v3");
    }
}

function tpmHashToNpmHash(tpmHash) {
    switch (tpmHash) {
        case "TPM_ALG_SHA1": return "SHA1";
        case "TPM_ALG_SHA256": return "SHA256";
        case "TPM_ALG_SHA384": return "SHA384";
        case "TPM_ALG_SHA512": return "SHA512";
        default:
            throw new TypeError("Unsupported hash type: " + tpmHash);
    }
}

module.exports = {
    name: "tpm",
    parseFn: tpmParseFn,
    validateFn: tpmValidateFn
};
