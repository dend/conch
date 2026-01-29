import { webcrypto } from 'crypto';
import { createProofKey, type ProofKey } from '../models/security/proof-key.js';

type CryptoKey = webcrypto.CryptoKey;

interface ECKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * Interface for Proof-of-Possession cryptographic providers.
 */
export interface IPoPCryptoProvider {
  /**
   * Gets the proof key containing the public key parameters.
   */
  getProofKey(): Promise<ProofKey>;

  /**
   * Signs data using the private key.
   * @param data - The data to sign.
   * @returns The ECDSA signature (IEEE P1363 format, 64 bytes for P-256).
   */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * ECDSA P-256 based Proof-of-Possession cryptographic provider.
 * Generates an ephemeral EC key pair and provides signing capabilities.
 */
export class ECDsaPoPCryptoProvider implements IPoPCryptoProvider {
  private keyPair: ECKeyPair | null = null;
  private proofKey: ProofKey | null = null;

  /**
   * Gets or generates the proof key containing the public key parameters.
   * The key is lazily generated on first access.
   * @returns A ProofKey object with the public key's X and Y coordinates.
   */
  async getProofKey(): Promise<ProofKey> {
    if (this.proofKey === null) {
      await this.ensureKeyPair();
    }
    return this.proofKey!;
  }

  /**
   * Signs data using the ECDSA private key with SHA-256.
   * @param data - The data to sign.
   * @returns The signature in IEEE P1363 format (r || s, 64 bytes total).
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    await this.ensureKeyPair();

    const signature = await webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.keyPair!.privateKey,
      data
    );

    return new Uint8Array(signature);
  }

  /**
   * Ensures the key pair is generated. Generates a new P-256 key pair if not already present.
   */
  private async ensureKeyPair(): Promise<void> {
    if (this.keyPair !== null) {
      return;
    }

    this.keyPair = (await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    )) as ECKeyPair;

    const jwk = await webcrypto.subtle.exportKey('jwk', this.keyPair.publicKey);

    if (!jwk.x || !jwk.y) {
      throw new Error('Failed to export public key coordinates');
    }

    this.proofKey = createProofKey(jwk.x, jwk.y);
  }
}
