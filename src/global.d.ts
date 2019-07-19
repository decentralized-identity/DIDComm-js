declare module 'base-58'
declare module 'tweetnacl-sealedbox-js' {
  export function seal(buffer: Uint8Array, publicKey: Uint8Array): Uint8Array
  export function open(sealed: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array
}