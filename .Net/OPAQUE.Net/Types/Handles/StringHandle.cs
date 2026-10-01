using System.Runtime.InteropServices;
using System.Text;

namespace OPAQUE.Net.Types.Handles
{
    internal sealed class StringHandle : BaseHandle<string>
    {
        private const int MaximumNativeStringLength = 64 * 1024;
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

            byte[] buffer = new byte[len];
            Marshal.Copy(handle, buffer, 0, buffer.Length);

            return new UTF8Encoding(false, true).GetString(buffer);
        }

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern void free_string(IntPtr handle);
    }
}
