using System;
using System.IO;
using System.Security.Cryptography;
using AsarSharp.Integrity;
using AsarSharp.Utils;

namespace WandEnhancer.Core.Patching.Shared
{
    /// <summary>Electron hashes the raw ASAR header JSON, excluding pickle framing and file data.</summary>
    internal static class AsarHeaderHash
    {
        private const uint MaxHeaderSize = 64 * 1024 * 1024;

        public static string Compute(string asarPath)
        {
            using (var stream = File.OpenRead(asarPath))
            {
                var framing = new byte[16];
                if (stream.ReadFull(framing, 0, framing.Length) != framing.Length)
                {
                    throw new InvalidDataException("The ASAR header is truncated.");
                }

                uint sizePayload = BitConverter.ToUInt32(framing, 0);
                uint pickleSize = BitConverter.ToUInt32(framing, 4);
                uint payloadSize = BitConverter.ToUInt32(framing, 8);
                uint jsonSize = BitConverter.ToUInt32(framing, 12);
                long paddedPayloadSize = (4L + jsonSize + 3) & ~3L;
                if (sizePayload != 4 || jsonSize > MaxHeaderSize || payloadSize != paddedPayloadSize ||
                    pickleSize != paddedPayloadSize + 4 || 8L + pickleSize > stream.Length)
                {
                    throw new InvalidDataException("The ASAR header pickle sizes are invalid.");
                }

                var json = new byte[jsonSize];
                if (stream.ReadFull(json, 0, json.Length) != json.Length)
                {
                    throw new InvalidDataException("The ASAR header JSON is truncated.");
                }

                using (var sha = SHA256.Create())
                {
                    return IntegrityHelper.ToLowerHex(sha.ComputeHash(json));
                }
            }
        }
    }
}
