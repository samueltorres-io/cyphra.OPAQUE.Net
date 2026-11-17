using System.Runtime.InteropServices;
using System.Security.Cryptography;
using OPAQUE.Net.Types.Exceptions;
using System.Text;

namespace OPAQUE.Net.Types.Handles
{
    internal sealed class StringHandle : BaseHandle<string>
    {
        private const int MaximumNativeStringLength = ParamGuard.MaximumProtocolMessageLength;
        private static readonly UTF8Encoding StrictUtf8 = new(false, true);

        protected override void DoRelease()
        {
            free_string(handle);
        }

        protected override string GetValue()
        {
            int len = 0;
            while (len <= MaximumNativeStringLength && Marshal.ReadByte(handle, len) != 0)
            {
                ++len;
            }

            if (len > MaximumNativeStringLength)
            {
                throw new InvalidOperationException("Native string is not NUL-terminated within the supported maximum length.");
            }

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
