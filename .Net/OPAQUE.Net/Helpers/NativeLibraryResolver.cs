using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OPAQUE.Net.Helpers
{
    /// <summary>
    /// Loads the native library only from the directories the .NET host itself resolved for this
    /// application (deps.json / runtimes/&lt;rid&gt;/native, the assembly and app directories), never by
    /// falling back to the operating system's search of a bare name (LD_LIBRARY_PATH, PATH, the
    /// working directory). A missing or unloadable library fails with the directories that were
    /// probed instead of silently picking up a library planted elsewhere.
    /// </summary>
    internal static class NativeLibraryResolver
    {
        internal const string LibraryName = "opaque";

        // CA2255 discourages module initializers in libraries; this is the one case it is meant for:
        // the resolver must be in place before the first P/Invoke of any entry type, with no init call.
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
                // A resolver is already registered for this assembly; keep the default probing.
            }
        }

        internal static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath) =>
            libraryName == LibraryName ? Load(FileName(), CandidateDirectories(assembly)) : IntPtr.Zero;

        // The csproj gives every RID's binary the same canonical name in the output and in runtimes/<rid>/native.
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
            return directories.Distinct().ToList();
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
