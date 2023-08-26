/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export function __wbg_keys_free(a: number): void;
export function keypair(): number;
export function keys_pubkey(a: number, b: number): void;
export function keys_secret(a: number, b: number): void;
export function keys_sign(a: number, b: number, c: number, d: number): void;
export function verify(a: number, b: number, c: number, d: number, e: number, f: number): number;
export function __wbg_params_free(a: number): void;
export function __wbg_get_params_publicKeyBytes(a: number): number;
export function __wbg_get_params_secretKeyBytes(a: number): number;
export function __wbg_get_params_signBytes(a: number): number;
export function keys_new(): number;
export function params_publicKeyBytes(): number;
export function params_secretKeyBytes(): number;
export function params_signBytes(): number;
export function __wbindgen_add_to_stack_pointer(a: number): number;
export function __wbindgen_free(a: number, b: number, c: number): void;
export function __wbindgen_malloc(a: number, b: number): number;
export function __wbindgen_exn_store(a: number): void;
