using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

// Uses synthetic executables and temporary copies only. Never patches an installed client.
public static class StaticIntegrityTests
{
    private const string StaticNamespace = "WandEnhancer.Core.Patching.Strategies.Static.";
    private const string EmptyObjectHash = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
    private const string EmptyArrayHash = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945";
    private const string Sentinel = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
    private static Assembly enhancer;
    private static string scratch;
    private static int checks;

    public static void Run(Assembly assembly, string wandDirectory)
    {
        enhancer = assembly;
        scratch = Path.Combine(Path.GetTempPath(), "wand-integrity-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        try
        {
            Check(enhancer.GetType(StaticNamespace + "AsarIntegrityResourcePatch") != null,
                "Static patch must synchronize the executable's ASAR integrity resource");
            Check(enhancer.GetType(StaticNamespace + "AuxFuseIntegrityNeutralizer") != null,
                "Static patch must handle the auxiliary fuse re-check");
            TestHeaderHash();
            TestResourcePatch();
            TestAuxiliaryPredicate();
            TestStaticRestore(false);
            TestStaticRestore(true);
            if (!string.IsNullOrEmpty(wandDirectory)) TestRealFiles(wandDirectory);
            Console.WriteLine("Static integrity regression checks passed ({0} assertions).", checks);
        }
        finally { Directory.Delete(scratch, true); }
    }

    private static object Call(string type, string method, params object[] args)
    {
        try { return enhancer.GetType(type, true).GetMethod(method).Invoke(null, args); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        checks++;
    }

    private static void Reject(Action action, string message)
    {
        bool rejected = false;
        try { action(); }
        catch (Exception) { rejected = true; }
        Check(rejected, message);
    }

    private static string Hash(string path)
    {
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(path))
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    private static string WriteAsar(string name, string header)
    {
        string path = Path.Combine(scratch, name);
        byte[] json = Encoding.UTF8.GetBytes(header);
        int payload = (4 + json.Length + 3) & ~3;
        using (var writer = new BinaryWriter(File.Create(path)))
        {
            writer.Write(4);
            writer.Write(payload + 4);
            writer.Write(payload);
            writer.Write(json.Length);
            writer.Write(json);
            writer.Write(new byte[payload - 4 - json.Length]);
            writer.Write(Encoding.ASCII.GetBytes("body is not included in the header hash"));
        }
        return path;
    }

    private static void TestHeaderHash()
    {
        string type = "WandEnhancer.Core.Patching.Shared.AsarHeaderHash";
        string asar = WriteAsar("hash.asar", "{}");
        Check((string)Call(type, "Compute", asar) == EmptyObjectHash, "Hash only the raw JSON header");
        byte[] invalid = File.ReadAllBytes(asar);
        invalid[8] = 0;
        File.WriteAllBytes(asar, invalid);
        Reject(() => Call(type, "Compute", asar), "Reject inconsistent ASAR pickle sizes");
        File.WriteAllBytes(asar, new byte[10]);
        Reject(() => Call(type, "Compute", asar), "Reject truncated ASAR headers");
    }

    private static string ResourceJson(string hash)
    {
        return "[ { \"file\" : \"resources\\\\app.asar\", \"alg\" : \"SHA256\", \"value\" : \"" + hash + "\" } ]";
    }

    private static void TestResourcePatch()
    {
        string type = StaticNamespace + "AsarIntegrityResourcePatch";
        string exe = Compile("resource", "public class Empty {}", true);
        string original = EmptyArrayHash.ToUpperInvariant();
        string originalAsar = WriteAsar("original-resource.asar", "[]");
        PutResource(exe, ResourceJson(original));
        string before = Hash(exe);
        string asar = WriteAsar("resource.asar", "{}");
        Check((bool)Call(type, "Patch", exe, asar, null), "Find the named PE resource with formatted JSON");
        Check(ReadResource(exe).Contains(EmptyObjectHash), "Synchronize the resource to the ASAR header");
        Call(type, "Patch", exe, WriteAsar("second.asar", "[]"), null);
        Check(ReadResource(exe).Contains(EmptyArrayHash), "Repatch updates the resource again");
        string hashBackup = exe + ".asarhashbak";
        byte[] savedHash = File.ReadAllBytes(hashBackup);
        File.WriteAllBytes(hashBackup, Encoding.ASCII.GetBytes(new string('a', 64)));
        string patched = Hash(exe);
        Reject(() => Call(type, "Restore", exe, originalAsar, null), "Reject a valid-hex backup that does not match the pristine ASAR");
        Check(Hash(exe) == patched && File.Exists(hashBackup), "Rejected Restore preserves the executable and backup");
        File.WriteAllBytes(hashBackup, savedHash);
        Call(type, "Restore", exe, originalAsar, null);
        Check(Hash(exe) == before, "Restore the original executable byte-for-byte after repeated patches");
        Call(type, "Restore", exe, originalAsar, null);
        Check(Hash(exe) == before, "Restore is idempotent");

        string legacy = Compile("legacy", "public class Legacy {}", true);
        before = Hash(legacy);
        Check(!(bool)Call(type, "Patch", legacy, asar, null), "Skip absent resources on older builds");
        Check(Hash(legacy) == before, "An absent resource leaves the executable untouched");

        PutResource(legacy, ResourceJson("invalid"));
        before = Hash(legacy);
        Reject(() => Call(type, "Patch", legacy, asar, null), "A detected malformed resource must fail");
        Check(Hash(legacy) == before, "Malformed resource failure performs no write");
    }

    private static string PredicateSource(string name, string extra)
    {
        return "public class " + name + " { public static string Anchor = \"" + Sentinel +
            "\"; public bool Check() { return Anchor.Length < 0; } " + extra + " }";
    }

    private static void TestAuxiliaryPredicate()
    {
        string type = StaticNamespace + "AuxFuseIntegrityNeutralizer";
        string aux = Compile("aux", PredicateSource("Renamed", ""), false);
        Check(!(bool)InvokePredicate(aux, "Renamed"), "Fixture initially rejects the disabled fuse");
        Check((int)Call(type, "Neutralize", aux, null) == 1, "Locate the fuse predicate by its stable string anchor");
        Check((bool)InvokePredicate(aux, "Renamed"), "The patched predicate accepts the disabled fuse");
        Check((int)Call(type, "Neutralize", aux, null) == 0, "Auxiliary patch is idempotent");

        aux = Compile("ambiguous", PredicateSource("Renamed", "public bool Other() { return false; }"), false);
        string before = Hash(aux);
        Reject(() => Call(type, "Neutralize", aux, null), "Reject ambiguous predicates");
        Check(Hash(aux) == before, "An ambiguous predicate leaves the auxiliary image untouched");

        aux = Compile("owners", PredicateSource("One", "") + PredicateSource("Two", ""), false);
        Reject(() => Call(type, "Neutralize", aux, null), "Reject more than one anchored owner type");
        aux = Compile("noanchor", "public class Old { public bool Check() { return false; } }", false);
        before = Hash(aux);
        Check((int)Call(type, "Neutralize", aux, null) == -1, "Skip a genuinely absent auxiliary re-check");
        Check(Hash(aux) == before, "An older auxiliary image remains unchanged");
    }

    private static object InvokePredicate(string path, string type)
    {
        Assembly fixture = Assembly.Load(File.ReadAllBytes(path));
        Type target = fixture.GetType(type);
        return target.GetMethod("Check").Invoke(Activator.CreateInstance(target), null);
    }

    private static void TestStaticRestore(bool rollback)
    {
        string install = Path.Combine(scratch, rollback ? "rollback" : "restore", "app-1.0.0");
        string resources = Path.Combine(install, "resources");
        string unpacked = Path.Combine(resources, "app.asar.unpacked");
        string auxRoot = Path.Combine(unpacked, "static", "unpacked", "auxiliary");
        Directory.CreateDirectory(auxRoot);
        string exe = Path.Combine(install, "FixtureClient.exe");
        File.Copy(Compile("client", "public class Client {}", true), exe);
        PutResource(exe, ResourceJson(EmptyObjectHash));
        AppendFuse(exe); // Updating Win32 resources discards an executable's overlay.
        string originalExe = Hash(exe);
        string originalAsar = WriteAsar("original.asar", "{}");
        string asar = Path.Combine(resources, "app.asar");
        File.Copy(originalAsar, asar + ".backup");
        File.Copy(WriteAsar("patched.asar", "[]"), asar);
        string aux = Path.Combine(auxRoot, "FixtureAuxiliaryService.exe");
        string trust = "[System.Runtime.InteropServices.DllImport(\"wintrust.dll\")] private static extern int WinVerifyTrust(System.IntPtr a, System.IntPtr b, System.IntPtr c); public int Trust() { return WinVerifyTrust(System.IntPtr.Zero, System.IntPtr.Zero, System.IntPtr.Zero); }";
        File.Copy(Compile("service", PredicateSource("Gate", trust), false), aux);
        string backupAux = Path.Combine(unpacked + ".backup", "static", "unpacked", "auxiliary");
        Directory.CreateDirectory(backupAux);
        File.Copy(aux, Path.Combine(backupAux, Path.GetFileName(aux)));
        string originalAux = Hash(aux);

        object config = Activator.CreateInstance(enhancer.GetType("WandEnhancer.Models.WeModConfig", true));
        config.GetType().GetProperty("RootDirectory").SetValue(config, install, null);
        config.GetType().GetProperty("ExecutableName").SetValue(config, "FixtureClient.exe", null);
        config.GetType().GetProperty("BrandName").SetValue(config, "wand-fixture-" + Guid.NewGuid().ToString("N"), null);
        Type contextType = enhancer.GetType("WandEnhancer.Core.Patching.Strategies.PatchContext", true);
        object context = Activator.CreateInstance(contextType, config, null, unpacked);
        object strategy = Activator.CreateInstance(enhancer.GetType(StaticNamespace + "StaticStrategy", true));
        strategy.GetType().GetMethod("ApplyEnablement").Invoke(strategy, new[] { context });
        Check(ReadResource(exe).Contains(EmptyArrayHash), "Static strategy synchronizes the resource");
        Check((bool)InvokePredicate(aux, "Gate"), "Static strategy handles the auxiliary re-check");

        Type enhancerType = enhancer.GetType("WandEnhancer.Core.Enhancer", true);
        Type loggerType = typeof(Action<,>).MakeGenericType(typeof(string), enhancer.GetType("WandEnhancer.Core.ELogType", true));
        var logger = System.Linq.Expressions.Expression.Lambda(loggerType,
            System.Linq.Expressions.Expression.Empty(),
            System.Linq.Expressions.Expression.Parameter(typeof(string)),
            System.Linq.Expressions.Expression.Parameter(enhancer.GetType("WandEnhancer.Core.ELogType", true))).Compile();
        object instance = Activator.CreateInstance(enhancerType, config, logger);
        MethodInfo restore = rollback ? enhancerType.GetMethod("RollbackQuietly", BindingFlags.NonPublic | BindingFlags.Instance) : enhancerType.GetMethod("Restore");
        restore.Invoke(instance, null);
        Check(Hash(exe) == originalExe, "Pipeline " + (rollback ? "rollback" : "Restore") + " restores the executable byte-for-byte");
        Check(Hash(asar) == Hash(originalAsar), "Pipeline restores the original ASAR");
        Check(Hash(aux) == originalAux, "Pipeline restores the original auxiliary service");
        Check(!File.Exists(exe + ".fusebak") && !File.Exists(exe + ".asarhashbak"), "Pipeline removes executable patch backups");
    }

    private static void TestRealFiles(string directory)
    {
        // Read-only inputs: all mutation targets are copies inside scratch.
        string exe = Path.Combine(scratch, "RealWand.exe");
        File.Copy(Path.Combine(directory, "Wand.exe"), exe);
        string auxRelative = Path.Combine("static", "unpacked", "auxiliary", "WandAuxiliaryService.exe");
        string resources = Path.Combine(directory, "resources");
        string asar = Path.Combine(resources, File.Exists(Path.Combine(resources, "app.asar.backup")) ? "app.asar.backup" : "app.asar");
        RestoreCopiedHash(Path.Combine(directory, "Wand.exe"), exe, asar);
        string expected = (string)Call("WandEnhancer.Core.Patching.Shared.AsarHeaderHash", "Compute", asar);
        Check(ReadResource(exe).Contains(expected), "Real pristine ASAR hash matches the embedded resource");
        string before = Hash(exe);
        Call(StaticNamespace + "AsarIntegrityResourcePatch", "Patch", exe, WriteAsar("real-test.asar", "{}"), null);
        Check(ReadResource(exe).Contains(EmptyObjectHash), "Real executable resource is synchronized on a copy");
        Call(StaticNamespace + "AsarIntegrityResourcePatch", "Restore", exe, asar, null);
        Check(Hash(exe) == before, "Real executable copy restores byte-for-byte");
        string aux = Path.Combine(scratch, "RealAuxiliary.exe");
        File.Copy(Path.Combine(resources, Directory.Exists(Path.Combine(resources, "app.asar.unpacked.backup")) ? "app.asar.unpacked.backup" : "app.asar.unpacked", auxRelative), aux);
        Check((int)Call(StaticNamespace + "AuxFuseIntegrityNeutralizer", "Neutralize", aux, null) == 1,
            "Real auxiliary service exposes the expected fuse predicate");
        TestRealPipeline(directory);
    }

    private static void TestRealPipeline(string source)
    {
        string install = Path.Combine(scratch, "real-pipeline", "app-12.64.1");
        string resources = Path.Combine(install, "resources");
        Directory.CreateDirectory(resources);
        string exe = Path.Combine(install, "Wand.exe");
        File.Copy(Path.Combine(source, "Wand.exe"), exe);
        if (File.Exists(Path.Combine(source, "Wand.exe.fusebak")))
        {
            File.Copy(Path.Combine(source, "Wand.exe.fusebak"), exe + ".fusebak");
            Call("WandEnhancer.Core.Patching.Shared.DiskFusePatch", "Remove", exe, null);
        }
        string sourceResources = Path.Combine(source, "resources");
        string asar = Path.Combine(resources, "app.asar");
        File.Copy(Path.Combine(sourceResources, File.Exists(Path.Combine(sourceResources, "app.asar.backup")) ? "app.asar.backup" : "app.asar"), asar);
        RestoreCopiedHash(Path.Combine(source, "Wand.exe"), exe, asar);
        string unpacked = Path.Combine(resources, "app.asar.unpacked");
        CopyTree(Path.Combine(sourceResources, Directory.Exists(Path.Combine(sourceResources, "app.asar.unpacked.backup")) ? "app.asar.unpacked.backup" : "app.asar.unpacked"), unpacked);
        string originalExe = Hash(exe);
        string originalAsar = Hash(asar);

        Type installType = enhancer.GetType("WandEnhancer.Models.WeModConfig", true);
        object config = Activator.CreateInstance(installType);
        installType.GetProperty("RootDirectory").SetValue(config, install, null);
        installType.GetProperty("ExecutableName").SetValue(config, "Wand.exe", null);
        installType.GetProperty("BrandName").SetValue(config, "wand-fixture-" + Guid.NewGuid().ToString("N"), null);
        Type patchType = enhancer.GetType("WandEnhancer.Models.EPatchType", true);
        Type setType = typeof(HashSet<>).MakeGenericType(patchType);
        object selection = Activator.CreateInstance(setType);
        setType.GetMethod("Add").Invoke(selection, new[] { Enum.Parse(patchType, "ActivatePro") });
        Type patchConfigType = enhancer.GetType("WandEnhancer.Models.PatchConfig", true);
        object patchConfig = Activator.CreateInstance(patchConfigType);
        patchConfigType.GetProperty("PatchTypes").SetValue(patchConfig, selection, null);
        patchConfigType.GetProperty("Strategy").SetValue(patchConfig,
            Enum.Parse(enhancer.GetType("WandEnhancer.Models.EPatchStrategy", true), "Static"), null);
        Type loggerType = typeof(Action<,>).MakeGenericType(typeof(string), enhancer.GetType("WandEnhancer.Core.ELogType", true));
        var message = System.Linq.Expressions.Expression.Parameter(typeof(string));
        var level = System.Linq.Expressions.Expression.Parameter(enhancer.GetType("WandEnhancer.Core.ELogType", true));
        var logger = System.Linq.Expressions.Expression.Lambda(loggerType,
            System.Linq.Expressions.Expression.Call(typeof(Console).GetMethod("WriteLine", new[] { typeof(string) }), message),
            message, level).Compile();
        Type enhancerType = enhancer.GetType("WandEnhancer.Core.Enhancer", true);
        object instance = Activator.CreateInstance(enhancerType, config, logger, patchConfig);
        for (int attempt = 0; attempt < 2; attempt++)
        {
            enhancerType.GetMethod("Patch").Invoke(instance, null);
            Check(Hash(asar) != originalAsar, "The real ASAR was patched on the temporary installation");
            string headerHash = (string)Call("WandEnhancer.Core.Patching.Shared.AsarHeaderHash", "Compute", asar);
            Check(ReadResource(exe).Contains(headerHash), "Full pipeline resource matches the real patched ASAR");
            foreach (string bundle in Directory.GetFiles(unpacked, "*.js"))
            {
                string code = File.ReadAllText(bundle);
                if (!code.Contains("getUserAccount(") && !code.Contains("ACTION_SET_ACCOUNT")) continue;
                var start = new System.Diagnostics.ProcessStartInfo("node.exe", "--check \"" + bundle + "\"")
                    { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true };
                using (var node = System.Diagnostics.Process.Start(start))
                {
                    string error = node.StandardError.ReadToEnd();
                    node.WaitForExit();
                    Check(node.ExitCode == 0, "Patched real JavaScript must parse: " + error);
                }
            }
        }
        enhancerType.GetMethod("Restore").Invoke(instance, null);
        Check(Hash(exe) == originalExe, "Full real-file pipeline restores the original executable after repatching");
        Check(Hash(asar) == originalAsar, "Full real-file pipeline restores the original ASAR after repatching");
    }

    private static void RestoreCopiedHash(string sourceExe, string copiedExe, string originalAsar)
    {
        if (!File.Exists(sourceExe + ".asarhashbak")) return;
        File.Copy(sourceExe + ".asarhashbak", copiedExe + ".asarhashbak");
        Call(StaticNamespace + "AsarIntegrityResourcePatch", "Restore", copiedExe, originalAsar, null);
    }

    private static void CopyTree(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string file in Directory.GetFiles(source)) File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        foreach (string directory in Directory.GetDirectories(source)) CopyTree(directory, Path.Combine(destination, Path.GetFileName(directory)));
    }

    private static string Compile(string name, string source, bool fuse)
    {
        string path = Path.Combine(scratch, name + "-" + Guid.NewGuid().ToString("N") + ".dll");
        string sourcePath = Path.ChangeExtension(path, ".cs");
        File.WriteAllText(sourcePath, source);
        string csc = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe");
        var start = new System.Diagnostics.ProcessStartInfo(csc,
            "/nologo /target:library /out:\"" + path + "\" \"" + sourcePath + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        using (var compiler = System.Diagnostics.Process.Start(start))
        {
            string output = compiler.StandardOutput.ReadToEnd();
            compiler.WaitForExit();
            if (compiler.ExitCode != 0) throw new Exception("Fixture compilation failed: " + output);
        }
        if (fuse)
        {
            AppendFuse(path);
        }
        return path;
    }

    private static void AppendFuse(string path)
    {
        using (var stream = new FileStream(path, FileMode.Append))
        {
            byte[] wire = Encoding.ASCII.GetBytes(Sentinel + "\u0001\u0008" + "11111111");
            stream.Write(wire, 0, wire.Length);
        }
    }

    private static void PutResource(string path, string json)
    {
        IntPtr update = BeginUpdateResource(path, false);
        if (update == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        if (!UpdateResource(update, "INTEGRITY", "ELECTRONASAR", 1033, bytes, (uint)bytes.Length))
        { EndUpdateResource(update, true); throw new System.ComponentModel.Win32Exception(); }
        if (!EndUpdateResource(update, false)) throw new System.ComponentModel.Win32Exception();
    }

    private static string ReadResource(string path)
    {
        IntPtr module = LoadLibraryEx(path, IntPtr.Zero, 2);
        if (module == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        try
        {
            IntPtr info = FindResource(module, "ELECTRONASAR", "INTEGRITY");
            if (info == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
            byte[] bytes = new byte[SizeofResource(module, info)];
            Marshal.Copy(LockResource(LoadResource(module, info)), bytes, 0, bytes.Length);
            return Encoding.UTF8.GetString(bytes);
        }
        finally { FreeLibrary(module); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr BeginUpdateResource(string path, bool delete);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool UpdateResource(IntPtr update, string type, string name, ushort language, byte[] data, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool EndUpdateResource(IntPtr update, bool discard);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll")] private static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr FindResource(IntPtr module, string name, string type);
    [DllImport("kernel32.dll")] private static extern uint SizeofResource(IntPtr module, IntPtr info);
    [DllImport("kernel32.dll")] private static extern IntPtr LoadResource(IntPtr module, IntPtr info);
    [DllImport("kernel32.dll")] private static extern IntPtr LockResource(IntPtr resource);
}
