"use strict";

var { Fido2Lib } = require("./lib/main.js");

// // add 'none' attestation format
// const noneAttestation = require("./lib/attestations/none");
// Fido2Lib.addAttestationFormat(
//     noneAttestation.name,
//     noneAttestation.parseFn,
//     noneAttestation.validateFn
// );

// // add 'fido-u2f' attestation format
// const u2fAttestation = require("./lib/attestations/fidoU2F");
// Fido2Lib.addAttestationFormat(
//     u2fAttestation.name,
//     u2fAttestation.parseFn,
//     u2fAttestation.validateFn
// );

module.exports = { Fido2Lib };
