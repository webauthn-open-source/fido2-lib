import { URL } from "std/node/url.ts";
import { getPublicSuffix } from "tldts";

import {
  exportSPKI,
  importJWK,
  importSPKI,
} from "jose";

import * as pkijs from "pkijs";
import { fromBER } from "asn1js";
import * as cbor from "cbor-x";

/* Internal utils, prepend with underscore */

// ToDo: Actually identify key
async function importSPKIHelper(raw) {
  let importSPKIResult;
  try {
    importSPKIResult = await importSPKI(raw, "ES256");
  } catch (_e) {
    if (!importSPKIResult) {
      try {
        importSPKIResult = await importSPKI(raw, "RS256");
      } catch (_e) {
        throw new Error("Unsupported key format");
      }
    }
  }
  return importSPKIResult;
}

/*
    Convert signature from DER to raw
    Expects Uint8Array
*/
function derToRaw(signature) {
  const rStart = signature[4] === 0 ? 5 : 4,
    rEnd = rStart + 32,
    sStart = signature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
  return new Uint8Array([
    ...signature.slice(rStart, rEnd),
    ...signature.slice(sStart),
  ]);
}

/* Exported utils */
function checkOrigin(str) {
  let originUrl = new URL(str);
  let origin = originUrl.origin;

  if (origin !== str) {
    throw new Error("origin was malformatted");
  }

  let isLocalhost = (originUrl.hostname == "localhost" ||
    originUrl.hostname.endsWith(".localhost"));

  if (originUrl.protocol !== "https:" && !isLocalhost) {
    throw new Error("origin should be https");
  }

  if (getPublicSuffix(originUrl.hostname) === null && !isLocalhost) {
    throw new Error("origin is not a valid eTLD+1");
  }

  return origin;
}

function checkUrl(value, name, rules = {}) {
  if (!name) {
    throw new TypeError("name not specified in checkUrl");
  }

  if (typeof value !== "string") {
    throw new Error(`${name} must be a string`);
  }

  let urlValue = null;
  try {
    urlValue = new URL(value);
  } catch (err) {
    throw new Error(`${name} is not a valid eTLD+1/url`);
  }

  if (!value.startsWith("http")) {
    throw new Error(`${name} must be http protocol`);
  }

  if (!rules.allowHttp && urlValue.protocol !== "https:") {
    throw new Error(`${name} should be https`);
  }

  // origin: base url without path including /
  if (!rules.allowPath && (value.endsWith("/") || urlValue.pathname !== "/")) { // urlValue adds / in path always
    throw new Error(`${name} should not include path in url`);
  }

  if (!rules.allowHash && urlValue.hash) {
    throw new Error(`${name} should not include hash in url`);
  }

  if (!rules.allowCred && (urlValue.username || urlValue.password)) {
    throw new Error(`${name} should not include credentials in url`);
  }

  if (!rules.allowQuery && urlValue.search) {
    throw new Error(`${name} should not include query string in url`);
  }

  return value;
}

function checkDomainOrUrl(value, name, rules = {}) {
  if (!name) {
    throw new TypeError("name not specified in checkDomainOrUrl");
  }

  if (typeof value !== "string") {
    throw new Error(`${name} must be a string`);
  }

  //if (getPublicSuffix(value) !== null) return value; // if valid domain no need for futher checks

  return checkUrl(value, name, rules);
}

function checkRpId(rpId) {
  if (typeof rpId !== "string") {
    throw new Error("rpId must be a string");
  }

  let isLocalhost = (rpId === "localhost" || rpId.endsWith(".localhost"));

  if (isLocalhost) return rpId;

  return checkDomainOrUrl(rpId, "rpId");
}

async function verifySignature(publicKey, expectedSignature, data, hashName) {
  try {
    const importedKey = await importSPKIHelper(publicKey);

    let uSignature = new Uint8Array(expectedSignature);

    // Copy algorithm and default hash
    let alg = importedKey.algorithm;
    if (!alg.hash) {
      alg.hash = { name: hashName || "SHA-256" };
    }

    // Convert signature
    if (alg.name === "ECDSA") {
      uSignature = await derToRaw(uSignature);
    }

    return await crypto.subtle.verify(
      alg,
      importedKey,
      new Uint8Array(uSignature),
      new Uint8Array(data),
    );
  } catch (_e) {
    return;
  }
}

async function jwkToPem(jwk) {
  // Set key as extractable
  jwk.ext = true;

  // Help JOSE find the correct path
  const algMap = {
    "RSASSA-PKCS1-v1_5_w_SHA256": "RS256",
    "ECDSA_w_SHA256": "ES256",
  };
  let alg = algMap[jwk.alg] || jwk.alg;
  const pubCryptoKey = await importJWK(jwk, alg);
  const pubSPKI = await exportSPKI(pubCryptoKey);

  return pubSPKI;
}

async function hashDigest(o, alg) {
  if (typeof o === "string") {
    o = new TextEncoder().encode(o);
  }
  let result = await crypto.subtle.digest(alg || "sha-256", o);
  return result;
}

function randomValues(n) {
  let byteArray = new Uint8Array(n);
  crypto.getRandomValues(byteArray);
  return byteArray;
}

function getHostname(urlIn) {
  return new URL(urlIn).hostname;
}

const webcrypto = crypto;

const ToolBox = {
  checkOrigin,
  checkRpId,
  checkDomainOrUrl,
  checkUrl,
  verifySignature,
  jwkToPem,
  hashDigest,
  randomValues,
  getHostname,
  webcrypto,
  fromBER,
  pkijs,
  cbor,
};

const ToolBoxRegistration = {
  registerAsGlobal: () => {
    window.webauthnToolBox = ToolBox;
  },
};

export { ToolBox, ToolBoxRegistration };
