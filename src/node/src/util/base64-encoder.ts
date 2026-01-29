/**
 * URL-safe Base64 encoding utilities (RFC 4648 Section 5).
 * Uses the alphabet: A-Z, a-z, 0-9, -, _ (no padding).
 */

/**
 * Encodes a Uint8Array to URL-safe Base64 string (no padding).
 * @param data - The data to encode.
 * @returns URL-safe Base64 encoded string.
 */
export function base64UrlEncode(data: Uint8Array): string {
  return Buffer.from(data).toString('base64url');
}

/**
 * Encodes a portion of a Uint8Array to URL-safe Base64 string.
 * @param data - The data to encode.
 * @param offset - Starting offset in the array.
 * @param length - Number of bytes to encode.
 * @returns URL-safe Base64 encoded string.
 */
export function base64UrlEncodeSubarray(
  data: Uint8Array,
  offset: number,
  length: number
): string {
  return Buffer.from(data.slice(offset, offset + length)).toString('base64url');
}

/**
 * Decodes a URL-safe Base64 string to Uint8Array.
 * @param encoded - The URL-safe Base64 encoded string.
 * @returns Decoded data as Uint8Array.
 */
export function base64UrlDecode(encoded: string): Uint8Array {
  return new Uint8Array(Buffer.from(encoded, 'base64url'));
}

/**
 * Encodes a Uint8Array to standard Base64 string.
 * @param data - The data to encode.
 * @returns Standard Base64 encoded string.
 */
export function base64Encode(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

/**
 * Decodes a standard Base64 string to Uint8Array.
 * @param encoded - The Base64 encoded string.
 * @returns Decoded data as Uint8Array.
 */
export function base64Decode(encoded: string): Uint8Array {
  return new Uint8Array(Buffer.from(encoded, 'base64'));
}
