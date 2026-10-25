import { rlpValue, type PlpPayload } from '@/utils';
import { buildTx } from './buildTx';
import { assertAddress, validateChainAndNonce } from './validate';

import type { TokenMetadataPayload } from '@/api/tokens/types';

export type TokenMetadataUnsigned = Omit<TokenMetadataPayload, 'signature'>;

export function validateTokenMetadata(unsigned: TokenMetadataUnsigned) {
  validateChainAndNonce(unsigned);
  assertAddress('token', unsigned.token);
}

export function tokenMetadataPayloadFields(
  unsigned: TokenMetadataUnsigned
): PlpPayload[] {
  // An omitted `additional_metadata` list is treated as
  // empty rather than crashing with a TypeError on
  // `.map`.
  const entries = unsigned.additional_metadata ?? [];

  const additionalMetadataRlp = entries.map(item => {
    // Each entry is serialized into the signed bytes, so
    // a missing `key` or `value` (silently rendered as
    // "undefined" on the wire) must be caught here, at
    // build time, instead of producing a signature the
    // node can never verify.
    if (item.key === undefined || item.value === undefined) {
      throw new Error(
        '[1Money SDK]: Invalid additional_metadata entry - both key and value are required'
      );
    }
    return rlpValue.list([
      rlpValue.string(item.key),
      rlpValue.string(item.value),
    ]);
  });

  return [
    rlpValue.string(unsigned.name),
    rlpValue.string(unsigned.uri),
    rlpValue.address(unsigned.token as `0x${string}`),
    rlpValue.list(additionalMetadataRlp),
  ];
}

export function prepareTokenMetadataTx(unsigned: TokenMetadataUnsigned) {
  validateTokenMetadata(unsigned);

  return buildTx<TokenMetadataUnsigned, TokenMetadataPayload>({
    kind: 'tokenMetadata',
    unsigned,
    payloadFields: tokenMetadataPayloadFields(unsigned),
    toRequest: (payload, signature) => ({
      ...payload,
      signature,
    }),
  });
}
