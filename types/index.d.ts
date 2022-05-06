/// <reference types="node" />

declare module "fido2-lib" {
  class Fido2Lib {
    constructor(opts?: Fido2LibOptions);

    attestationOptions(
      opts?: AttestationOptions
    ): Promise<PublicKeyCredentialCreationOptions>;
    attestationResult(
      res: AttestationResult,
      expected: ExpectedAttestationResult
    ): Promise<Fido2AttestationResult>;
    assertionOptions(
      opts?: AssertionOptions
    ): Promise<PublicKeyCredentialRequestOptions>;
    assertionResult(
      res: AssertionResult,
      expected: ExpectedAssertionResult
    ): Promise<Fido2AssertionResult>;
  }

  interface Fido2LibOptions {
    timeout?: number;
    rpId?: string;
    rpName?: string;
    rpIcon?: string;
    challengeSize?: number;
    authenticatorAttachment?: Attachment;
    authenticatorRequireResidentKey?: boolean;
    authenticatorUserVerification?: UserVerification;
    attestation?: Attestation;
    cryptoParams?: Array<number>;
  }

  interface AuthenticatorSelectionCriteria {
    attachment?: Attachment;
    requireResidentKey?: boolean;
    userVerification?: UserVerification;
  }

  interface AttestationOptions {
    extensionOptions?: any;
    extraData?: string;
  }

  interface AssertionOptions {
    extensionOptions?: any;
    extraData?: string;
  }

  interface PublicKeyCredentialCreationOptions {
    rp: { name: string; id: string; icon?: string };
    user: { id: string, name: string, displayName: string };
    challenge: ArrayBuffer;
    pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
    timeout?: number;
    attestation?: Attestation;
    authenticatorSelectionCriteria?: AuthenticatorSelectionCriteria;
    rawChallenge?: ArrayBuffer;
    extensions?: any;
  }

  type Attestation = "direct" | "indirect" | "none";
  type Attachment = "platform" | "cross-platform";
  type UserVerification = "required" | "preferred" | "discouraged";
  type Factor = "first" | "second" | "either";

  interface AttestationResult {
    id?: ArrayBuffer;
    rawId?: ArrayBuffer;
    transports?: string[];
    response: { clientDataJSON: string; attestationObject: string };
  }

  interface ExpectedAttestationResult {
    rpId?: string;
    origin: string;
    challenge: string;
    factor: Factor;
  }

  interface Fido2AttestationResult {
    authnrData: Map<string, any>;
    clientData: Map<string, any>;
    expectations: Map<string, string>;
    request: AttestationResult;
    audit: Audit;
  }

  interface Audit {
    validExpectations: boolean;
    validRequest: boolean;
    complete: boolean;
    journal: Set<string>;
    warning: Map<string, string>;
    info: Map<string, string>;
  }

  interface PublicKeyCredentialRequestOptions {
    challenge: ArrayBuffer;
    timeout?: number;
    rpId?: string;
    attestation?: Attestation;
    userVerification?: UserVerification;
    rawChallenge?: ArrayBuffer;
    extensions?: any;
    allowCredentials?: PublicKeyCredentialDescriptor[];
  }

  interface PublicKeyCredentialDescriptor {
    type: "public-key";
    id: ArrayBuffer;
    transports?: string[];
  }

  interface AssertionResult {
    id?: ArrayBuffer;
    rawId?: ArrayBuffer;
    response: {
      clientDataJSON: string;
      authenticatorData: ArrayBuffer;
      signature: string;
      userHandle?: string;
    };
  }

  interface ExpectedAssertionResult {
    rpId?: string;
    challenge: string;
    origin: string;
    factor: Factor;
    publicKey: string;
    prevCounter: number;
    userHandle: string | null;
    allowCredentials?: PublicKeyCredentialDescriptor[];
  }

  interface Fido2AssertionResult {
    authnrData: Map<string, any>;
    clientData: Map<string, any>;
    expectations: Map<string, string>;
    request: AttestationResult;
    audit: Audit;
  }
}
