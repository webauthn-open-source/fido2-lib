function appleParseFn(attStmt) {
  const ret = new Map();

  console.log(attStmt);

  return ret;
}

async function appleValidateFn() {}

const appleAttestation = {
  name: "apple",
  parseFn: appleParseFn,
  validateFn: appleValidateFn,
};

export { appleAttestation };
