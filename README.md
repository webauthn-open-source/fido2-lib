[![Node/Deno CI](https://github.com/webauthn-open-source/fido2-lib/actions/workflows/test.yml/badge.svg)](https://github.com/webauthn-open-source/fido2-lib/actions/workflows/test.yml)
[![Code Coverage](https://codecov.io/gh/webauthn-open-source/fido2-lib/branch/master/graph/badge.svg)](https://codecov.io/gh/webauthn-open-source/fido2-lib)
[![Known Vulnerabilities](https://snyk.io/test/github/webauthn-open-source/fido2-lib/badge.svg?targetFile=package.json)](https://snyk.io/test/github/webauthn-open-source/fido2-lib?targetFile=package.json) 
[![npm version](https://badge.fury.io/js/fido2-lib.svg)](https://badge.fury.io/js/fido2-lib) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/webauthn-open-source/fido2-lib/badge)](https://securityscorecards.dev/viewer/?uri=github.com/webauthn-open-source/fido2-lib)


## Overview

A library for performing FIDO 2.0 / WebAuthn server functionality

This library contains all the functionality necessary for implementing a full FIDO2 / WebAuthn server. It intentionally does not implement any kind of networking protocol (e.g. - REST endpoints) so that it can remain independent of any messaging protocols.

There are four primary functions:
1. [attestationOptions](https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#attestationOptions) - creates the challenge that will be sent to the client (e.g. - browser) for the credential create call. Note that the library does not keep track of sessions or context, so the caller is expected to associate the resulting challenge with a session so that it can be appropriately matched with a response.
2. [attestationResult](https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#attestationResult) - parses and validates the response from the client
3. [assertionOptions](https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#assertionOptions) - creates the challenge that will be sent to the client for credential assertion.
4. [assertionResult](https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#assertionResult) - parses and validates the response from the client

There is also an extension point for adding new attestation formats.

Full documentation can be found [here](https://webauthn-open-source.github.io/fido2-lib/).

For working examples see [OWASP Single Sign-On](https://github.com/OWASP/SSO_Project) and / or [webauthn.io](https://webauthn.io/)

## Features

* Works with Windows Hello
* Attestation formats: packed, tpm, android-safetynet, fido-u2f, none, apple
* Convenient API for adding more attestation formats
* Convenient API for adding extensions
* Metadata service (MDS) support enables authenticator root of trust and authenticator metadata
* Support for multiple simultaneous metadata services (e.g. FIDO MDS 1-3)
* Crypto families: ECDSA, RSA
* x509 cert parsing, support for FIDO-related extensions, and NIST Public Key Interoperability Test Suite (PKITS) chain validation (from [pki.js](https://github.com/PeculiarVentures/PKI.js/))
* Returns parsed and validated data, along with extra audit data for risk engines
* Support both CommonJS (`require`) and ESM (`import`) natively

## Getting started

### Node

``` bash
npm install fido2-lib --save
```

#### Import Library using CommonJS
```js
const { Fido2Lib } = require("fido2-lib");
```

#### Import Library using ESM-syntax

```js
import { Fido2Lib } from "fido2-lib";
```

### Deno

Import `dist/main.js` from a trusted source. Below is only an example, using the official deno.land repository.
It is recommended to [enable integrity checking](https://deno.land/manual/linking_to_external_code/integrity_checking).

```js
import { Fido2Lib } from "https://deno.land/x/fido2@$VERSION/dist/main.js";
```

<details>
  <summary>Add Type Declarations</summary>
  
  Firstly, you need to set up a [import map](https://deno.land/manual/basics/import_maps).
  Put the following lines into your import map.

  ```json
  {
    "imports": {
      "fido2-lib": "https://deno.land/x/fido2@$VERSION/dist/main.js"
    }
  }
  ```

  Then you can import the library like this:

  ```ts
  // @deno-types="https://deno.land/x/fido2@$VERSION/types/main.d.ts"
  import { Fido2Lib } from "fido2-lib";
  ```

</details>

Don't forget to replace `$VERSION` with the specific version. You can find the latest version by checking the redirection of [deno.land/x/fido2/dist/main.js](https://deno.land/x/fido2/dist/main.js) and [deno.land/x/fido2/types/main.d.ts](https://deno.land/x/fido2/types/main.d.ts).

## Examples

**Instantiate Library (Complex):**
``` js
// could also use one or more of the options below,
// which just makes the options calls easier later on:
const f2l = new Fido2Lib({
    timeout: 42,
    rpId: "example.com",
    rpName: "ACME",
    rpIcon: "https://example.com/logo.png",
    challengeSize: 128,
    attestation: "none",
    cryptoParams: [-7, -257],
    authenticatorAttachment: "platform",
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "required"
});
```

**Registration:**
``` js
const registrationOptions = await f2l.attestationOptions();

// make sure to add registrationOptions.user.id and registrationOptions.user.name
// save the challenge in the session information...
// send registrationOptions to client and pass them in to `navigator.credentials.create()`...
// get response back from client (clientAttestationResponse)

const attestationExpectations = {
    challenge: "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
    origin: "https://localhost:8443",
    factor: "either"
};
const regResult = await f2l.attestationResult(clientAttestationResponse, attestationExpectations); // will throw on error

// registration complete!
// save publicKey and counter from regResult to user's info for future authentication calls
```

**Authentication:**
``` js
const authnOptions = await f2l.assertionOptions();

// add allowCredentials to limit the number of allowed credential for the authentication process. For further details refer to webauthn specs: (https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials).
// save the challenge in the session information...
// send authnOptions to client and pass them in to `navigator.credentials.get()`...
// get response back from client (clientAssertionResponse)

const assertionExpectations = {
    // Remove the following comment if allowCredentials has been added into authnOptions so the credential received will be validate against allowCredentials array.
    // allowCredentials: [{
    //     id: "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
    //     type: "public-key",
    //     transports: ["usb"]
    // }],
    challenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
    origin: "https://localhost:8443",
    factor: "either",
    publicKey: "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERez9aO2wBAWO54MuGbEqSdWahSnG\n" +
        "MAg35BCNkaE3j8Q+O/ZhhKqTeIKm7El70EG6ejt4sg1ZaoQ5ELg8k3ywTg==\n" +
        "-----END PUBLIC KEY-----\n",
    prevCounter: 362
};
const authnResult = await f2l.assertionResult(clientAssertionResponse, assertionExpectations); // will throw on error

// authentication complete!
```

For a real-life example, refer to [OWASP Single Sign-On](https://github.com/OWASP/SSO_Project).

## Migration from v2 to v3

Generally v3 is assumed to be completely compatible with v2 - compatibility should have increased.
As many inner workings have been changed, please verify that your application still works with v3 and report issues, if you newly encounter bugs.


## Contributing

#### Setting up the environment

It's recommended to have both Deno (>=1.20) and Node 16-18 available to be able to run all checks and tests.

### Before committing

Please run ```npm run lint```, ```npm run test``` and ```deno task test``` before committing, to make sure every test and check passes.

See [package.json](/package.json) for available npm scripts, and [deno.jsonc](/deno.jsonc) for available Deno tasks.

Make sure to add tests if you add new features.

**Important:** Do not stage/commit `dist/main.js` and `dist/main.cjs`. These are generated and committed automatically by the CI-pipeline.

### Dependencies

When adding, removing or updating dependencies, start out with npm as usual. Then update `import_map.json` to the same versions shown by `npm list`, and run `deno task update-deps` to update the Deno lock-file.

### Pull Request

When you're finished with the changes, create a pull request.
- Enable the checkbox to [allow maintainer edits](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/allowing-changes-to-a-pull-request-branch-created-from-a-fork) so the branch can be updated for a merge.
Once you submit your PR, a team member will review your proposal. We may ask questions or request for additional information.
- If you run into any merge issues, checkout this [git tutorial](https://lab.github.com/githubtraining/managing-merge-conflicts) to help you resolve merge conflicts and other issues.

## Sponsor

Work for this project was supported by [Adam Power](https://github.com/apowers313).
