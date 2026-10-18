using System;
using System.IO;
using WandEnhancer.Core.Patching.Shared;

namespace WandEnhancer.Core.Patching.Strategies.Static
{
    /// <summary>Handles the auxiliary service's independent check of the Electron ASAR fuse.</summary>
    internal static class AuxFuseIntegrityNeutralizer
    {
        private static readonly byte[] Stub = { 0x17, 0x2A }; // ldc.i4.1; ret

        public static int Neutralize(string auxPath, Action<string, ELogType> log)
        {
            long offset;
            using (var image = DotNetImage.Load(auxPath))
            {
                if (image == null) throw new InvalidDataException("The auxiliary service is not a managed image.");
                offset = image.FindBoolPredicateOffsetByTypeStringAnchor(ElectronFuseWire.SentinelText);
            }
            if (offset < 0) return -1;

            using (var stream = new FileStream(auxPath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            {
                stream.Position = offset;
                if (stream.ReadByte() == Stub[0] && stream.ReadByte() == Stub[1]) return 0;
                stream.Position = offset;
                stream.Write(Stub, 0, Stub.Length);
            }
            log?.Invoke("[ENHANCER] Auxiliary ASAR-fuse re-check neutralised.", ELogType.Info);
            return 1;
        }
    }
}
