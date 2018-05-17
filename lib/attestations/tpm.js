"use strict";

const {
    printHex,
    coerceToArrayBuffer,
    coerceToBase64,
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

    var x5c = attStmt.x5c;

    if (!Array.isArray(x5c)) {
        throw new TypeError("expected U2F attestation x5c field to be of type Array");
    }

    if (x5c.length < 1) {
        throw new TypeError("no certificates in U2F x5c field");
    }

    var newX5c = [];
    for (let cert of x5c) {
        cert = coerceToArrayBuffer(cert, "U2F x5c cert");
        newX5c.push(cert);
    }
    // first certificate MUST be the attestation cert
    ret.set("attCert", newX5c.shift());
    // the rest of the certificates (if any) are the certificate chain
    ret.set("x5c", newX5c);

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

    // TPM_GENERATED_VALUE magic number
    ci.set("magic", dv.getUint32(offset));
    offset += 4;

    // TPMI_ST_ATTEST type
    var type = dv.getUint16(offset);
    if (type === 0x8017) type = "TPM_ST_ATTEST_CERTIFY";
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
    pa.set("exponent", dv.getUint32(offset));
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

function tpmValidateFn() {
    var magic;
    if (magic !== 0xff544347) { // 0xFF + 'TCG'
        throw new Error("tpm attestation: certInfo had bad magic number: " + magic.toString(16));
    }

}

module.exports = {
    name: "tpm",
    parseFn: tpmParseFn,
    validateFn: tpmValidateFn
};
