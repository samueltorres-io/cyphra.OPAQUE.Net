using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace OPAQUE.Net.Types.Handles
{
    internal sealed class StringHandle : BaseHandle<string>
    {
        private const int MaximumNativeStringLength = 64 * 1024;
        private static readonly UTF8Encoding StrictUtf8 = new(false, true);
        public StringHandle() : base() { }

        protected override void DoRelease()
        {
            free_string(handle);
        }

        protected override string GetValue()
        {
            if (IsInvalid)
            {
                return string.Empty;
            }

            int len = 0;
            while (len < MaximumNativeStringLength && Marshal.ReadByte(handle, len) != 0)
            {
                ++len;
            }

            if (len == MaximumNativeStringLength)
            {
                throw new InvalidOperationException("Native string is not NUL-terminated within the supported maximum length.");
            }

            // The buffer may hold a session or export key: wipe this intermediate copy. The returned
            // string is immutable and cannot be wiped (see docs/security.md).
            byte[] buffer = new byte[len];
            try
            {
                Marshal.Copy(handle, buffer, 0, buffer.Length);
                return StrictUtf8.GetString(buffer);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern void free_string(IntPtr handle);
    }
}
