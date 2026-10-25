import {
  encode as rlpEncode,
  decode as rlpDecode,
} from '@ethereumjs/rlp';
import {
  hexToBytes,
  keccak256,
} from 'viem';

import type {
  Signature,
  ZeroXString,
} from '@/utils';

// secp256k1 curve order / 2 (maximum value for low-S signatures)
// This prevents signature malleability by ensuring S is in the lower half of the curve order
//
// Exported so every signing path (legacy and native v2) enforces the
// same bound from one definition instead of each copying the magic
// number.
export const SECP256K1_N_DIV_2 = BigInt(
  '0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0'
);

export interface SignerAdapter {
  signDigest: (digest: ZeroXString) => Promise<Signature>;
}

export interface SignedTx<TUnsigned, TRequest> {
  kind: string;
  unsigned: TUnsigned;
  signatureHash: ZeroXString;
  txHash: ZeroXString;
  signature: Signature;
  toRequest: () => TRequest;
}

export interface PreparedTx<TUnsigned, TRequest> {
  kind: string;
  unsigned: TUnsigned;
  rlpBytes: Uint8Array;
  signatureHash: ZeroXString;
  attachSignature: (
    signature: Signature
  ) => SignedTx<TUnsigned, TRequest>;
  sign: (
    signer: SignerAdapter
  ) => Promise<SignedTx<TUnsigned, TRequest>>;
}

// Validate that S value is in the lower half of the curve order.
// This prevents signature malleability attacks. Exported so the
// native v2 signing path (src/signing/v2/prepare.ts) reuses this
// exact check instead of re-implementing it against a copied
// constant -- there is one definition of "low-S" for the whole SDK.
export function assertLowS(signature: Signature): void {
  let s: bigint;
  try {
    s = BigInt(signature.s);
  } catch {
    // A malformed hex string must surface as a typed SDK
    // error, not a raw SyntaxError from BigInt().
    throw new Error(
      '[1Money SDK]: Invalid signature - malformed S value (expected 0x-prefixed hex)'
    );
  }
  // S = 0 is not a valid signature scalar; reject it
  // together with high-S values so only signatures in
  // the valid low-S range pass.
  if (s <= 0n) {
    throw new Error(
      '[1Money SDK]: Invalid signature - S value must be greater than zero'
    );
  }
  if (s > SECP256K1_N_DIV_2) {
    throw new Error(
      '[1Money SDK]: Invalid signature - high S value detected (potential malleability)'
    );
  }
}

function validateSignature(signature: Signature): void {
  assertLowS(signature);
}

export function calcSignedTxHash(
  payloadRlpBytes: Uint8Array,
  signature: Signature
): ZeroXString {
  // Decode the payload to get the transaction fields
  const payloadFields = rlpDecode(payloadRlpBytes);

  // Prepare v value based on its type
  const v =
    typeof signature.v === 'boolean'
      ? signature.v
        ? Uint8Array.from([1])
        : new Uint8Array([])
      : BigInt(signature.v);

  // Use library's encode to create the signed transaction structure: [[fields], v, r, s]
  const encoded = rlpEncode([
    payloadFields,
    v,
    hexToBytes(signature.r),
    hexToBytes(signature.s),
  ]);

  return keccak256(encoded) as ZeroXString;
}

export function createPreparedTx<
  TUnsigned,
  TRequest,
>(params: {
  kind: string;
  unsigned: TUnsigned;
  rlpBytes: Uint8Array;
  toRequest: (
    unsigned: TUnsigned,
    signature: Signature
  ) => TRequest;
}): PreparedTx<TUnsigned, TRequest> {
  const signatureHash = keccak256(
    params.rlpBytes
  ) as ZeroXString;

  // Snapshot the caller's unsigned payload. The original
  // object stays reachable from the caller's scope, so
  // without a copy any later mutation would desynchronize
  // the signed bytes from the request actually sent
  // (the signature would authorize one payload while the
  // wire carried another).
  const unsigned = { ...params.unsigned } as TUnsigned;

  const attachSignature = (
    signature: Signature
  ): SignedTx<TUnsigned, TRequest> => {
    // Validate signature to prevent malleability attacks
    validateSignature(signature);

    return {
      kind: params.kind,
      unsigned,
      signatureHash,
      txHash: calcSignedTxHash(params.rlpBytes, signature),
      signature,
      toRequest: () =>
        params.toRequest(unsigned, signature),
    };
  };

  return {
    kind: params.kind,
    unsigned,
    rlpBytes: params.rlpBytes,
    signatureHash,
    attachSignature,
    sign: async signer =>
      attachSignature(
        await signer.signDigest(signatureHash)
      ),
  };
}
