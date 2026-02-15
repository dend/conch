// <copyright file="TokenEncryptionHelper.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System;
using System.Security.Cryptography;
using System.Text;

namespace Den.Dev.Conch.Storage
{
    /// <summary>
    /// Provides AES-256-GCM encryption and decryption for token storage.
    /// Uses PBKDF2-SHA256 with configurable key derivation.
    /// </summary>
    internal static class TokenEncryptionHelper
    {
        private static readonly byte[] Magic = new byte[] { 0x43, 0x48 }; // "CH"
        private const byte Version = 0x01;
        private const int SaltSize = 16;
        private const int IvSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;
        private const int HeaderSize = 2 + 1 + SaltSize + IvSize + TagSize; // 47 bytes
        private const int Pbkdf2Iterations = 600_000;

        /// <summary>
        /// Encrypts plaintext bytes using AES-256-GCM with PBKDF2-derived key.
        /// </summary>
        /// <param name="plaintext">The plaintext bytes to encrypt.</param>
        /// <param name="passphrase">The passphrase used for key derivation.</param>
        /// <param name="aad">Additional authenticated data for GCM.</param>
        /// <returns>The encrypted binary blob including header, salt, IV, tag, and ciphertext.</returns>
        public static byte[] Encrypt(byte[] plaintext, string passphrase, string aad)
        {
            var aadBytes = Encoding.UTF8.GetBytes(aad);
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var iv = RandomNumberGenerator.GetBytes(IvSize);
            var key = DeriveKey(salt, passphrase);

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];

            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Encrypt(iv, plaintext, ciphertext, tag, aadBytes);
            }

            var result = new byte[HeaderSize + ciphertext.Length];
            result[0] = Magic[0];
            result[1] = Magic[1];
            result[2] = Version;
            Buffer.BlockCopy(salt, 0, result, 3, SaltSize);
            Buffer.BlockCopy(iv, 0, result, 3 + SaltSize, IvSize);
            Buffer.BlockCopy(tag, 0, result, 3 + SaltSize + IvSize, TagSize);
            Buffer.BlockCopy(ciphertext, 0, result, HeaderSize, ciphertext.Length);

            return result;
        }

        /// <summary>
        /// Decrypts a binary blob produced by <see cref="Encrypt"/>.
        /// </summary>
        /// <param name="data">The encrypted binary blob.</param>
        /// <param name="passphrase">The passphrase used for key derivation.</param>
        /// <param name="aad">Additional authenticated data for GCM.</param>
        /// <returns>The decrypted plaintext bytes.</returns>
        /// <exception cref="CryptographicException">Thrown if the data is invalid, corrupted, or cannot be decrypted.</exception>
        public static byte[] Decrypt(byte[] data, string passphrase, string aad)
        {
            if (data.Length < HeaderSize)
            {
                throw new CryptographicException("Data too short to be a valid encrypted token file.");
            }

            if (data[0] != Magic[0] || data[1] != Magic[1])
            {
                throw new CryptographicException("Invalid magic bytes.");
            }

            if (data[2] != Version)
            {
                throw new CryptographicException($"Unsupported version: {data[2]}.");
            }

            var aadBytes = Encoding.UTF8.GetBytes(aad);
            var salt = new byte[SaltSize];
            var iv = new byte[IvSize];
            var tag = new byte[TagSize];
            Buffer.BlockCopy(data, 3, salt, 0, SaltSize);
            Buffer.BlockCopy(data, 3 + SaltSize, iv, 0, IvSize);
            Buffer.BlockCopy(data, 3 + SaltSize + IvSize, tag, 0, TagSize);

            var ciphertextLength = data.Length - HeaderSize;
            var ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(data, HeaderSize, ciphertext, 0, ciphertextLength);

            var key = DeriveKey(salt, passphrase);
            var plaintext = new byte[ciphertextLength];

            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Decrypt(iv, ciphertext, tag, plaintext, aadBytes);
            }

            return plaintext;
        }

        private static byte[] DeriveKey(byte[] salt, string passphrase)
        {
            var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);

            return Rfc2898DeriveBytes.Pbkdf2(passphraseBytes, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);
        }
    }
}
