// <copyright file="EncryptedFileTokenStore.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System;
using System.IO;
using System.Text;
using System.Text.Json;
using Den.Dev.Conch.Authentication;
using Den.Dev.Conch.Models.Security;

namespace Den.Dev.Conch.Storage
{
    /// <summary>
    /// AES-256-GCM encrypted file-based implementation of <see cref="IXboxTokenStore"/>.
    /// By default, tokens are encrypted with a machine-bound key derived from the machine name and user name.
    /// </summary>
    public class EncryptedFileTokenStore : IXboxTokenStore
    {
        private const string DefaultAad = "conch-tokens-v1";

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
        };

        private readonly string filePath;
        private readonly string passphrase;
        private readonly string aad;

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedFileTokenStore"/> class.
        /// </summary>
        /// <param name="filePath">Path to the encrypted token cache file.</param>
        /// <param name="passphrase">Passphrase for key derivation. Defaults to <c>Environment.MachineName + Environment.UserName</c> (machine-bound).</param>
        /// <param name="aad">Additional authenticated data for AES-GCM. Defaults to <c>"conch-tokens-v1"</c>.</param>
        public EncryptedFileTokenStore(string filePath, string? passphrase = null, string? aad = null)
        {
            this.filePath = filePath;
            this.passphrase = passphrase ?? (Environment.MachineName + Environment.UserName);
            this.aad = aad ?? DefaultAad;
        }

        /// <inheritdoc/>
        public XboxTokenCache? Load()
        {
            try
            {
                if (!File.Exists(this.filePath))
                {
                    return null;
                }

                var encrypted = File.ReadAllBytes(this.filePath);
                var json = TokenEncryptionHelper.Decrypt(encrypted, this.passphrase, this.aad);
                return JsonSerializer.Deserialize<XboxTokenCache>(json, JsonOptions);
            }
            catch (Exception)
            {
                // Any decryption/format error: delete the corrupt file and return null.
                TryDelete(this.filePath);
                return null;
            }
        }

        /// <inheritdoc/>
        public void Save(XboxTokenCache cache)
        {
            try
            {
                var directory = Path.GetDirectoryName(this.filePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var json = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(cache, JsonOptions));
                var encrypted = TokenEncryptionHelper.Encrypt(json, this.passphrase, this.aad);
                File.WriteAllBytes(this.filePath, encrypted);
            }
            catch (Exception)
            {
                // Silent fail on I/O errors per design.
            }
        }

        /// <inheritdoc/>
        public void Clear()
        {
            try
            {
                TryDelete(this.filePath);
            }
            catch (Exception)
            {
                // Silent fail on I/O errors per design.
            }
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (Exception)
            {
                // Silent fail.
            }
        }
    }
}
