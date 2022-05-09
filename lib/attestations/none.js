/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

function noneParseFn(attStmt) {
	if (Object.keys(attStmt).length !== 0) {
		throw new Error("'none' attestation format: attStmt had fields");
	}

	return new Map();
}

function noneValidateFn() {
	this.audit.journal.add("fmt");

	return true;
}

const noneAttestation = {
	name: "none",
	parseFn: noneParseFn,
	validateFn: noneValidateFn,
};

export { noneAttestation };
