using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]

namespace OPAQUE.Net.Helpers
{
    internal static class NativeLibraryResolver
    {
        internal const string LibraryName = "opaque";

#pragma warning disable CA2255
        [ModuleInitializer]
#pragma warning restore CA2255
        internal static void Register()
        {
            try
            {
                NativeLibrary.SetDllImportResolver(typeof(NativeLibraryResolver).Assembly, Resolve);
            }
            catch (InvalidOperationException)
            {
                System.Diagnostics.Trace.TraceWarning(
                    "OPAQUE.Net: another DllImport resolver is registered for this assembly; the native library is loaded by it, not from the host-resolved directories.");
            }
        }

        internal static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath) =>
            libraryName == LibraryName ? Load(FileName(), CandidateDirectories(assembly)) : IntPtr.Zero;

        internal static string FileName() =>
            OperatingSystem.IsWindows() ? "opaque.dll" :
            OperatingSystem.IsMacOS() ? "libopaque.dylib" : "libopaque.so";

        internal static IReadOnlyList<string> CandidateDirectories(Assembly assembly)
        {
            var directories = new List<string>();
            if (AppContext.GetData("NATIVE_DLL_SEARCH_DIRECTORIES") is string hostDirectories)
            {
                directories.AddRange(hostDirectories.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));
            }

            if (!string.IsNullOrEmpty(assembly.Location) && Path.GetDirectoryName(assembly.Location) is string assemblyDirectory)
            {
                directories.Add(assemblyDirectory);
            }

            directories.Add(AppContext.BaseDirectory);
            return directories.Where(Path.IsPathFullyQualified).Distinct().ToList();
        }

        internal static IntPtr Load(string fileName, IReadOnlyList<string> directories)
        {
            var unloadable = new List<string>();
            foreach (string directory in directories)
            {
                string path = Path.Combine(directory, fileName);
                if (!File.Exists(path))
                {
                    continue;
                }

                if (NativeLibrary.TryLoad(path, out IntPtr handle))
                {
                    return handle;
                }

                unloadable.Add(path);
            }

            string found = unloadable.Count == 0
                ? ""
                : $" Found but could not be loaded (wrong architecture or C library?): {string.Join(", ", unloadable)}.";
            throw new DllNotFoundException(
                $"Could not load the native library '{fileName}' for {RuntimeInformation.RuntimeIdentifier}.{found} Probed: {string.Join(", ", directories)}.");
        }
    }
}
