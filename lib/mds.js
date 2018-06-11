"use strict";

const {
    coerceToBase64Url,
    coerceToArrayBuffer,
    ab2str,
    str2ab,
    abToPem,
    printHex,
    abEqual
} = require("./utils");

const {
    CertManager
} = require("./certUtils");

const crypto = require("crypto");

const jwt = require("jsonwebtoken");

const fidoMdsRootCert =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG\n" +
    "A1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFk\n" +
    "YXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoX\n" +
    "DTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxs\n" +
    "aWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRS\n" +
    "b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+\n" +
    "AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4ims\n" +
    "rfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYw\n" +
    "DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYw\n" +
    "HwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAw\n" +
    "ZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciW\n" +
    "DcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XU\n" +
    "YjdBz56jSA==\n" +
    "-----END CERTIFICATE-----\n";

class MdsEntry {
    constructor(mdsEntry, tocEntry) {
        for (let key of Object.keys(tocEntry)) {
            this[key] = tocEntry[key];
        }

        for (let key of Object.keys(mdsEntry)) {
            this[key] = mdsEntry[key];
        }

        // make fields more useable:

        // attachmentHint
        this.attachmentHint = attachmentHintToSet(this.attachmentHint);
        function attachmentHintToSet(hint) {
            var ret = [];
            if (hint & 0x0001) ret.push("internal");
            if (hint & 0x0002) ret.push("external");
            if (hint & 0x0004) ret.push("wired");
            if (hint & 0x0008) ret.push("wireless");
            if (hint & 0x0010) ret.push("nfc");
            if (hint & 0x0020) ret.push("bluetooth");
            if (hint & 0x0040) ret.push("network");
            if (hint & 0x0080) ret.push("ready");
            if (hint & 0xFF00) throw new Error("unknown attachment hint flags: " + hint & 0xFF00);
            return ret;
        }

        // attestationTypes
        if (!Array.isArray(this.attestationTypes)) throw new Error("expected attestationTypes to be Array, got: " + this.attestationTypes);
        this.attestationTypes = this.attestationTypes.map((att) => attestationTypeToStr(att));
        function attestationTypeToStr(att) {
            switch (att) {
                case 0x3E07: return "basic-full";
                case 0x3E08: return "basic-surrogate";
                case 0x3E09: return "ecdaa";
                default:
                    throw new Error("uknown attestation type: " + att);
            }
        }

        // authenticationAlgorithm
        this.authenticationAlgorithm = algToStr(this.authenticationAlgorithm);
        function algToStr(alg) {
            switch (alg) {
                case 0x0001: return "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW";
                case 0x0002: return "ALG_SIGN_SECP256R1_ECDSA_SHA256_DER";
                case 0x0003: return "ALG_SIGN_RSASSA_PSS_SHA256_RAW";
                case 0x0004: return "ALG_SIGN_RSASSA_PSS_SHA256_DER";
                case 0x0005: return "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW";
                case 0x0006: return "ALG_SIGN_SECP256K1_ECDSA_SHA256_DER";
                case 0x0007: return "ALG_SIGN_SM2_SM3_RAW";
                case 0x0008: return "ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW";
                case 0x0009: return "ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER";
                default:
                    throw new Error("unknown authentication algorithm: " + alg);
            }
        }

        // icon: TODO

        // keyProtection
        this.keyProtection = keyProtToSet(this.keyProtection);
        function keyProtToSet(kp) {
            var ret = [];
            if (kp & 0x0001) ret.push("software");
            if (kp & 0x0002) ret.push("hardware");
            if (kp & 0x0004) ret.push("tee");
            if (kp & 0x0008) ret.push("secure-element");
            if (kp & 0x0010) ret.push("remote-handle");
            if (kp & 0xFFE0) throw new Error("unknown key protection flags: " + kp & 0xFFE0);
            return ret;
        }

        // matcherProtection
        this.matcherProtection = matcherProtToArr(this.matcherProtection);
        function matcherProtToArr(mp) {
            var ret = [];
            if (mp & 0x0001) ret.push("software");
            if (mp & 0x0002) ret.push("hardware");
            if (mp & 0x0004) ret.push("tee");
            if (mp & 0xFFF8) throw new Error("unknown key protection flags: " + mp & 0xFFF8);
            return ret;
        }

        // publicKeyAlgAndEncoding
        this.publicKeyAlgAndEncoding = pkAlgAndEncodingToStr(this.publicKeyAlgAndEncoding);
        function pkAlgAndEncodingToStr(pkalg) {
            switch (pkalg) {
                case 0x0100: return "ALG_KEY_ECC_X962_RAW";
                case 0x0101: return "ALG_KEY_ECC_X962_DER";
                case 0x0102: return "ALG_KEY_RSA_2048_RAW";
                case 0x0103: return "ALG_KEY_RSA_2048_DER";
                case 0x0104: return "ALG_KEY_COSE";
                default:
                    throw new Error("unknown public key algorithm and encoding: " + pkalg);
            }
        }

        // tcDisplay
        this.tcDisplay = tcDisplayToArr(this.tcDisplay);
        function tcDisplayToArr(tcd) {
            var ret = [];
            if (tcd & 0x0001) ret.push("any");
            if (tcd & 0x0002) ret.push("priviledged-software");
            if (tcd & 0x0004) ret.push("tee");
            if (tcd & 0x0008) ret.push("hardware");
            if (tcd & 0x0010) ret.push("remote");
            if (tcd & 0xFFE0) throw new Error("unknown transaction confirmation display flags: " + tcd & 0xFFE0);
            return ret;
        }

        // userVerificationDetails
        this.userVerificationDetails = uvDetailsToSet(this.userVerificationDetails);
        function uvDetailsToSet(uvList) {
            var ret = [];
            if (!Array.isArray(uvList)) throw new Error("expected userVerificationDetails to be an Array, got: " + this.userVerificationDetails);
            uvList.forEach((uv) => {
                if (!Array.isArray(uv)) throw new Error("expected userVerification to be Array, got " + uv);
                let d = uv.map((desc) => {
                    let newDesc = {};
                    var descKey;

                    if ("caDesc" in desc) {
                        newDesc.type = "code";
                        descKey = "caDesc";
                    }

                    if ("baDesc" in desc) {
                        newDesc.type = "biometric";
                        descKey = "baDesc";
                    }

                    if ("paDesc" in desc) {
                        newDesc.type = "pattern";
                        descKey = "paDesc";
                    }

                    newDesc.userVerification = uvToArr(desc.userVerification);

                    for (let key of Object.keys(desc[descKey])) {
                        newDesc[key] = desc[descKey][key];
                    }
                    return newDesc;
                });
                ret.push(d);
            });
            return ret;
        }

        function uvToArr(uv) {
            var ret = [];
            if (uv & 0x00000001) ret.push("presence");
            if (uv & 0x00000002) ret.push("fingerprint");
            if (uv & 0x00000004) ret.push("passcode");
            if (uv & 0x00000008) ret.push("voiceprint");
            if (uv & 0x00000010) ret.push("faceprint");
            if (uv & 0x00000020) ret.push("location");
            if (uv & 0x00000040) ret.push("eyeprint");
            if (uv & 0x00000080) ret.push("pattern");
            if (uv & 0x00000100) ret.push("handprint");
            if (uv & 0x00000200) ret.push("none");
            if (uv & 0x00000400) ret.push("all");
            return ret;
        }
        // userVerificationDetails
        if (this.protocolFamily === undefined) this.protocolFamily = "uaf";

        // TODO: read spec for other values
    }
}

class MdsCollection {
    constructor() {
        this.toc = null;
        this.unvalidatedEntryList = new Map();
        this.entryList = new Map();
        this.validated = false;
    }

    async addToc(tocStr, rootCert, crls) {
        if (typeof tocStr !== "string" ||
            tocStr.length < 1) {
            throw new Error("expected MDS TOC to be non-empty string");
        }

        if (rootCert === undefined) {
            rootCert = fidoMdsRootCert;
        }

        // no npm JWT libraries seem to support x5c headers, so we have to get certs manually here...
        var jwtParts = tocStr.split(".");
        if (jwtParts.length !== 3) {
            throw new Error("MDS TOC JWT didn't have three parts");
        }
        var header = b64ToJsObject(jwtParts[0], "MDS TOC header");

        // check header
        if (typeof header.alg !== "string" ||
            typeof header.typ !== "string" ||
            !Array.isArray(header.x5c) ||
            header.x5c.length < 2) {
            throw new Error("malformed MDS TOC JWT header");
        }

        // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-service-v2.0-id-20180227.html#metadata-toc-object-processing-rules
        // The FIDO Server MUST follow these processing rules:
        //    The FIDO Server MUST be able to download the latest metadata TOC object from the well-known URL, when appropriate. The nextUpdate field of the Metadata TOC specifies a date when the download SHOULD occur at latest.
        //    If the x5u attribute is present in the JWT Header, then:
        //        The FIDO Server MUST verify that the URL specified by the x5u attribute has the same web-origin as the URL used to download the metadata TOC from. The FIDO Server SHOULD ignore the file if the web-origin differs (in order to prevent loading objects from arbitrary sites).
        //        The FIDO Server MUST download the certificate (chain) from the URL specified by the x5u attribute [JWS]. The certificate chain MUST be verified to properly chain to the metadata TOC signing trust anchor according to [RFC5280]. All certificates in the chain MUST be checked for revocation according to [RFC5280].
        //        The FIDO Server SHOULD ignore the file if the chain cannot be verified or if one of the chain certificates is revoked.
        //    If the x5u attribute is missing, the chain should be retrieved from the x5c attribute. If that attribute is missing as well, Metadata TOC signing trust anchor is considered the TOC signing certificate chain.
        //    Verify the signature of the Metadata TOC object using the TOC signing certificate chain (as determined by the steps above). The FIDO Server SHOULD ignore the file if the signature is invalid. It SHOULD also ignore the file if its number (no) is less or equal to the number of the last Metadata TOC object cached locally.
        //    Write the verified object to a local cache as required.

        // verify cert chain
        var rootCerts;
        if (Array.isArray(rootCert)) rootCerts = rootCert;
        else rootCerts = [rootCert];
        var ret = await CertManager.verifyCertChain(header.x5c, rootCerts, crls);

        // JWT verify
        var signingCert = header.x5c.shift();
        signingCert = abToPem("CERTIFICATE", signingCert);
        this.toc = jwt.verify(tocStr, signingCert);
        this.toc.raw = tocStr;

        return this.toc;
    }

    getToc() {
        return this.toc;
    }

    addEntry(entryStr) {
        if (typeof entryStr !== "string" ||
            entryStr.length < 1) {
            throw new Error("expected MDS entry to be non-empty string");
        }

        var newEntry = b64ToJsObject(entryStr, "MDS entry");
        newEntry.raw = entryStr;
        var newEntryId = getMdsEntryId(newEntry);
        this.unvalidatedEntryList.set(newEntryId, newEntry);
        // console.log("newEntry", newEntry);
    }

    validate() {
        // throw if no TOC
        if (typeof this.toc !== "object" || this.toc === null) {
            throw new Error("add MDS TOC before attempting to validate MDS collection");
        }

        // throw if no new entries
        if (this.unvalidatedEntryList.size < 1) {
            throw new Error("add MDS entries before attempting to validate MDS collection");
        }

        // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-service-v2.0-id-20180227.html#metadata-toc-object-processing-rules
        //    Iterate through the individual entries (of type MetadataTOCPayloadEntry). For each entry:
        //        Ignore the entry if the AAID, AAGUID or attestationCertificateKeyIdentifiers is not relevant to the relying party (e.g. not acceptable by any policy)
        //        Download the metadata statement from the URL specified by the field url. Some authenticator vendors might require authentication in order to provide access to the data. Conforming FIDO Servers SHOULD support the HTTP Basic, and HTTP Digest authentication schemes, as defined in [RFC2617].
        //        Check whether the status report of the authenticator model has changed compared to the cached entry by looking at the fields timeOfLastStatusChange and statusReport. Update the status of the cached entry. It is up to the relying party to specify behavior for authenticators with status reports that indicate a lack of certification, or known security issues. However, the status REVOKED indicates significant security issues related to such authenticators.
        //        Note
        //        Authenticators with an unacceptable status should be marked accordingly. This information is required for building registration and authentication policies included in the registration request and the authentication request [UAFProtocol].
        //        Compute the hash value of the (base64url encoding without padding of the UTF-8 encoded) metadata statement downloaded from the URL and verify the hash value to the hash specified in the field hash of the metadata TOC object. Ignore the downloaded metadata statement if the hash value doesn't match.
        //        Update the cached metadata statement according to the dowloaded one.

        this.unvalidatedEntryList.forEach((entry) => {
            // find matching TOC entry
            let entryId = getMdsEntryId(entry);
            let tocEntry = this.toc.entries.filter((te) => {
                let teId = getMdsEntryId(te);
                return teId === entryId;
            });

            if (tocEntry.length !== 1) {
                throw new Error(`found the wrong number of TOC entries for '${entryId}': ${tocEntry.length}`);
            }
            tocEntry = tocEntry[0];

            // validate hash
            const hash = crypto.createHash("sha256");
            // coerceToArrayBuffer(entry.raw, "MDS entry")
            hash.update(entry.raw);
            var entryHash = hash.digest();
            var tocEntryHash = coerceToArrayBuffer(tocEntry.hash, "MDS TOC entry hash");
            if (!(abEqual(entryHash, tocEntryHash))) {
                throw new Error("MDS entry hash did not match corresponding hash in MDS TOC");
            }

            // validate status report
            // TODO: maybe setValidateEntryCallback(fn);

            // add new entry to collection entryList
            this.entryList.set(entryId, new MdsEntry(entry, tocEntry));
        });
    }

    /**
     * Looks up an entry by AAID, AAGUID, or attestationCertificateKeyIdentifiers.
     * Only entries that have been validated will be found.
     * @param  {String|ArrayBuffer} id The AAID, AAGUID, or attestationCertificateKeyIdentifiers of the entry to find
     * @return {MdsEntry|null}    The MDS entry that was found, or null if no entry was found.
     */
    findEntry(id) {
        return this.entryList.get(id) || null;
    }

    iterateEntries() {

    }
}

function b64ToJsObject(b64, desc) {
    return JSON.parse(ab2str(coerceToArrayBuffer(b64, desc)));
}

function getMdsEntryId(obj) {
    if (typeof obj !== "object") {
        throw new Error("getMdsEntryId expected 'obj' to be object, got: " + obj);
    }

    if (typeof obj.aaid === "string") {
        return obj.aaid;
    }

    if (typeof obj.aaguid === "string") {
        return obj.aaguid;
    }

    if (typeof obj.attestationCertificateKeyIdentifiers === "string") {
        return obj.attestationCertificateKeyIdentifiers;
    }

    throw new Error("MDS entry didn't have a valid ID");
}

module.exports = {
    MdsEntry,
    MdsCollection
};
