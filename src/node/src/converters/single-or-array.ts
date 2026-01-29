/**
 * Normalizes a value that may be a single item or an array to always be an array.
 * This handles API responses where a field may return either a single object or an array.
 *
 * @param value - The value to normalize (single item, array, null, or undefined).
 * @returns An array containing the item(s), or an empty array if the value is null/undefined.
 *
 * @example
 * normalizeToArray({ id: 1 }); // [{ id: 1 }]
 * normalizeToArray([{ id: 1 }, { id: 2 }]); // [{ id: 1 }, { id: 2 }]
 * normalizeToArray(null); // []
 * normalizeToArray(undefined); // []
 */
export function normalizeToArray<T>(value: T | T[] | null | undefined): T[] {
  if (value === null || value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

/**
 * Normalizes Xbox display claims to ensure xui is always an array.
 * Xbox APIs may return xui as a single object or an array depending on the request.
 *
 * @param claims - The raw display claims from the API.
 * @returns Normalized claims with xui as an array.
 */
export function normalizeDisplayClaims<T extends { xui?: unknown }>(
  claims: T | null | undefined
): (Omit<T, 'xui'> & { xui: T extends { xui?: infer U } ? (U extends unknown[] ? U : U[]) : never }) | null {
  if (claims === null || claims === undefined) {
    return null;
  }

  return {
    ...claims,
    xui: normalizeToArray(claims.xui),
  } as Omit<T, 'xui'> & { xui: T extends { xui?: infer U } ? (U extends unknown[] ? U : U[]) : never };
}
