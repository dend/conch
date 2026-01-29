/**
 * Represents an Elliptic Curve proof key in JWK (JSON Web Key) format.
 * Used for Proof-of-Possession (PoP) authentication with Xbox Live services.
 */
export interface ProofKey {
  /**
   * Key type. Always 'EC' for Elliptic Curve.
   */
  readonly kty: 'EC';

  /**
   * Algorithm. Always 'ES256' (ECDSA using P-256 and SHA-256).
   */
  readonly alg: 'ES256';

  /**
   * Curve identifier. Always 'P-256' (NIST P-256 curve).
   */
  readonly crv: 'P-256';

  /**
   * Key use. Always 'sig' for signing.
   */
  readonly use: 'sig';

  /**
   * X coordinate of the public key point, Base64URL encoded.
   */
  readonly x: string;

  /**
   * Y coordinate of the public key point, Base64URL encoded.
   */
  readonly y: string;
}

/**
 * Creates a ProofKey object from JWK X and Y coordinates.
 * @param x - X coordinate, Base64URL encoded.
 * @param y - Y coordinate, Base64URL encoded.
 * @returns A ProofKey object.
 */
export function createProofKey(x: string, y: string): ProofKey {
  return {
    kty: 'EC',
    alg: 'ES256',
    crv: 'P-256',
    use: 'sig',
    x,
    y,
  };
}
