// <copyright file="Base64Encoder.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System;

namespace Den.Dev.Conch.Util
{
    /// <summary>
    /// Helper class to provide URL-safe Base64 encoding for device token acquisition.
    /// </summary>
    public static class Base64Encoder
    {
        /// <summary>
        /// Encoding table containing safe characters for Base64 URLs.
        /// </summary>
        private static readonly char[] Base64Table =
        {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
        };

        /// <summary>
        /// Encodes a byte array using Base64 URL encoding.
        /// </summary>
        /// <param name="inArray">Array of bytes (8-bit unsigned integers).</param>
        /// <returns>If successful, returns a Base64 URL-encoded string.</returns>
        public static string Encode(byte[] inArray)
        {
            return Encode(inArray, 0, inArray?.Length ?? 0);
        }

        /// <summary>
        /// Encodes a subset of an array of 8-bit unsigned integers using Base64 URL encoding.
        /// </summary>
        /// <param name="inArray">Array of 8-bit unsigned integers.</param>
        /// <param name="offset">Offset in the array.</param>
        /// <param name="length">Number of elements to encode.</param>
        /// <returns>Base64 URL encoded string.</returns>
        /// <exception cref="ArgumentNullException">inArray is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">offset or length is invalid.</exception>
        private static string Encode(byte[] inArray, int offset, int length)
        {
            if (inArray is null)
            {
                throw new ArgumentNullException(nameof(inArray));
            }

            if (length < 0 || offset < 0 || inArray.Length < offset + length)
            {
                throw new ArgumentOutOfRangeException();
            }

            if (length == 0)
            {
                return string.Empty;
            }

            int lengthMod3 = length % 3;
            int limit = offset + (length - lengthMod3);
            char[] output = new char[(length + 2) / 3 * 4];
            int j = 0;

            // Encode blocks of 3 bytes to 4 Base64 characters
            for (int i = offset; i < limit; i += 3)
            {
                byte d0 = inArray[i];
                byte d1 = inArray[i + 1];
                byte d2 = inArray[i + 2];

                output[j++] = Base64Table[d0 >> 2];
                output[j++] = Base64Table[((d0 & 0x03) << 4) | (d1 >> 4)];
                output[j++] = Base64Table[((d1 & 0x0f) << 2) | (d2 >> 6)];
                output[j++] = Base64Table[d2 & 0x3f];
            }

            // Handle leftover bytes
            if (lengthMod3 == 2)
            {
                byte d0 = inArray[limit];
                byte d1 = inArray[limit + 1];
                output[j++] = Base64Table[d0 >> 2];
                output[j++] = Base64Table[((d0 & 0x03) << 4) | (d1 >> 4)];
                output[j++] = Base64Table[(d1 & 0x0f) << 2];
            }
            else if (lengthMod3 == 1)
            {
                byte d0 = inArray[limit];
                output[j++] = Base64Table[d0 >> 2];
                output[j++] = Base64Table[(d0 & 0x03) << 4];
            }

            return new string(output, 0, j);
        }
    }
}
