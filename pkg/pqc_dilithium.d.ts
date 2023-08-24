/* tslint:disable */
/* eslint-disable */
/**
* @returns {Keys}
*/
export function keypair(): Keys;
/**
* @param {Uint8Array} sig
* @param {Uint8Array} msg
* @param {Uint8Array} public_key
* @returns {boolean}
*/
export function verify(sig: Uint8Array, msg: Uint8Array, public_key: Uint8Array): boolean;
/**
*/
export class Keys {
  free(): void;
/**
*/
  constructor();
/**
* @param {Uint8Array} msg
* @returns {Uint8Array}
*/
  sign(msg: Uint8Array): Uint8Array;
/**
*/
  readonly pubkey: Uint8Array;
/**
*/
  readonly secret: Uint8Array;
}
/**
*/
export class Params {
  free(): void;
/**
*/
  static readonly publicKeyBytes: number;
/**
*/
  static readonly secretKeyBytes: number;
/**
*/
  static readonly signBytes: number;
}
