using System;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using WandEnhancer.Core.Patching.Shared;

namespace WandEnhancer.Core.Patching.Strategies.Static
{
    /// <summary>
    /// Synchronizes the named INTEGRITY/ELECTRONASAR PE resource with the modified archive.
    /// Only the hash bytes change; a backup preserves the original executable for Restore.
    /// </summary>
    internal static class AsarIntegrityResourcePatch
    {
        private const string BackupSuffix = ".asarhashbak";
        private const int HashLength = 64;
        private const uint DirectoryFlag = 0x80000000;
        private static readonly Regex HashValue = new Regex("\"value\"\\s*:\\s*\"(?<hash>[0-9a-fA-F]{64})\"");

        public static bool Patch(string exePath, string asarPath, Action<string, ELogType> log)
        {
            HashLocation location = Locate(exePath);
            if (location == null) return false;

            byte[] next = Encoding.ASCII.GetBytes(AsarHeaderHash.Compute(asarPath));
            string backup = exePath + BackupSuffix;
            if (File.Exists(backup))
            {
                ValidateHash(File.ReadAllBytes(backup));
            }
            else
            {
                // Publish only a complete backup, before touching the executable.
                string staging = backup + ".building";
                File.WriteAllBytes(staging, location.Bytes);
                File.Move(staging, backup);
            }

            WriteHash(exePath, location.Offset, next);
            log?.Invoke("[ENHANCER] ASAR integrity resource synchronized with app.asar.", ELogType.Info);
            return true;
        }

        public static void Restore(string exePath, string asarPath, Action<string, ELogType> log)
        {
            string backup = exePath + BackupSuffix;
            if (!File.Exists(backup)) return;

            byte[] original = File.ReadAllBytes(backup);
            ValidateHash(original);
            if (!string.Equals(Encoding.ASCII.GetString(original), AsarHeaderHash.Compute(asarPath), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("The ASAR integrity hash backup does not match the restored archive; keeping the backup.");
            }
            HashLocation location = Locate(exePath);
            if (location == null)
            {
                throw new InvalidDataException("The backed-up ASAR integrity resource could not be located; keeping its backup.");
            }

            WriteHash(exePath, location.Offset, original);
            File.Delete(backup);
            log?.Invoke("[ENHANCER] Original ASAR integrity resource restored in the executable.", ELogType.Info);
        }

        private static void WriteHash(string path, long offset, byte[] hash)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read))
            {
                stream.Position = offset;
                stream.Write(hash, 0, hash.Length);
            }
        }

        private static HashLocation Locate(string path)
        {
            using (var stream = File.OpenRead(path))
            using (var pe = new PEReader(stream, PEStreamOptions.LeaveOpen))
            using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
            {
                var directory = pe.PEHeaders.PEHeader.ResourceTableDirectory;
                if (directory.Size == 0) return null;
                long root = FileOffset(pe.PEHeaders, stream.Length, directory.RelativeVirtualAddress, directory.Size);
                uint type, name;
                if (!FindNamedEntry(reader, root, directory.Size, 0, "INTEGRITY", out type)) return null;
                RequireDirectory(type);
                if (!FindNamedEntry(reader, root, directory.Size, type & ~DirectoryFlag, "ELECTRONASAR", out name)) return null;
                RequireDirectory(name);

                long languages = RelativeOffset(root, directory.Size, name & ~DirectoryFlag, 24);
                stream.Position = languages + 12;
                int count = reader.ReadUInt16() + reader.ReadUInt16();
                if (count != 1) throw new InvalidDataException("The ASAR integrity resource has ambiguous language entries.");
                reader.ReadUInt32(); // language ID
                uint dataEntry = reader.ReadUInt32();
                if ((dataEntry & DirectoryFlag) != 0) throw new InvalidDataException("Unexpected ASAR integrity resource structure.");
                stream.Position = RelativeOffset(root, directory.Size, dataEntry, 16);
                uint rva = reader.ReadUInt32();
                uint length = reader.ReadUInt32();
                if (rva > int.MaxValue || length == 0 || length > 64 * 1024)
                    throw new InvalidDataException("The ASAR integrity resource size or address is invalid.");
                long offset = FileOffset(pe.PEHeaders, stream.Length, (int)rva, (int)length);
                stream.Position = offset;
                byte[] bytes = reader.ReadBytes((int)length);
                string json = new UTF8Encoding(false, true).GetString(bytes).TrimEnd('\0');
                JArray entries = JArray.Parse(json);
                var entry = entries.Count == 1 ? entries[0] as JObject : null;
                var matches = HashValue.Matches(json);
                if (entry == null || (string)entry["file"] != @"resources\app.asar" ||
                    (string)entry["alg"] != "SHA256" || matches.Count != 1 ||
                    (string)entry["value"] != matches[0].Groups["hash"].Value)
                {
                    throw new InvalidDataException("The detected ASAR integrity resource has an unsupported payload.");
                }

                Group hash = matches[0].Groups["hash"];
                byte[] existing = Encoding.ASCII.GetBytes(hash.Value);
                ValidateHash(existing);
                return new HashLocation(offset + Encoding.UTF8.GetByteCount(json.Substring(0, hash.Index)), existing);
            }
        }

        private static bool FindNamedEntry(BinaryReader reader, long root, int size, uint relative, string target, out uint value)
        {
            long table = RelativeOffset(root, size, relative, 16);
            reader.BaseStream.Position = table + 12;
            int count = reader.ReadUInt16() + reader.ReadUInt16();
            RelativeOffset(root, size, relative, 16L + count * 8L);
            bool found = false;
            value = 0;
            for (int i = 0; i < count; i++)
            {
                reader.BaseStream.Position = table + 16 + i * 8L;
                uint name = reader.ReadUInt32();
                uint child = reader.ReadUInt32();
                if ((name & DirectoryFlag) == 0) continue;
                reader.BaseStream.Position = RelativeOffset(root, size, name & ~DirectoryFlag, 2);
                int chars = reader.ReadUInt16();
                RelativeOffset(root, size, name & ~DirectoryFlag, 2L + chars * 2L);
                string text = Encoding.Unicode.GetString(reader.ReadBytes(chars * 2));
                if (!string.Equals(text, target, StringComparison.OrdinalIgnoreCase)) continue;
                if (found) throw new InvalidDataException("Duplicate named ASAR integrity resource entries.");
                found = true;
                value = child;
            }
            return found;
        }

        private static void RequireDirectory(uint entry)
        {
            if ((entry & DirectoryFlag) == 0) throw new InvalidDataException("Unexpected ASAR integrity resource directory.");
        }

        private static long RelativeOffset(long root, int size, uint relative, long length)
        {
            if (relative + length > size) throw new InvalidDataException("ASAR integrity resource directory exceeds its bounds.");
            return root + relative;
        }

        private static long FileOffset(PEHeaders headers, long fileLength, int rva, int size)
        {
            int index = headers.GetContainingSectionIndex(rva);
            if (index < 0) throw new InvalidDataException("ASAR integrity resource is outside the PE sections.");
            var section = headers.SectionHeaders[index];
            long relative = (long)rva - section.VirtualAddress;
            long offset = section.PointerToRawData + relative;
            if (size < 0 || relative < 0 || relative + size > section.SizeOfRawData || offset + size > fileLength)
                throw new InvalidDataException("ASAR integrity resource exceeds the PE file bounds.");
            return offset;
        }

        private static void ValidateHash(byte[] bytes)
        {
            if (bytes.Length != HashLength) throw new InvalidDataException("ASAR integrity hash must contain 64 hex characters.");
            foreach (byte b in bytes)
            {
                if (!(b >= '0' && b <= '9') && !(b >= 'a' && b <= 'f') && !(b >= 'A' && b <= 'F'))
                    throw new InvalidDataException("ASAR integrity hash contains non-hex characters.");
            }
        }

        private sealed class HashLocation
        {
            public HashLocation(long offset, byte[] bytes) { Offset = offset; Bytes = bytes; }
            public long Offset { get; }
            public byte[] Bytes { get; }
        }
    }
}
