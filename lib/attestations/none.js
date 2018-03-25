"use strict";

function noneParseFn(attStmt) {
    if (Object.keys(attStmt).length !== 0) {
        throw new Error("'none' attestation format: attStmt had fields");
    }

    return new Map();
}

function noneValidateFn(dataMap) {
    this.audit.journal.add("fmt");

    return true;
}

module.exports = {
    name: "none",
    parseFn: noneParseFn,
    validateFn: noneValidateFn
};
