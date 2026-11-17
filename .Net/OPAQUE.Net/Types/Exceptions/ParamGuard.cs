using System.Text;

namespace OPAQUE.Net.Types.Exceptions
{
    internal static class ParamGuard
    {
        public const int MaximumPasswordLength = 1024;
        public const int MaximumIdentifierLength = 1024;
        public const int MaximumProtocolMessageLength = 64 * 1024;

        private static readonly UTF8Encoding StrictUtf8 = new(false, true);

        public static void ThrowIfInvalid(string? value, int maximumBytes, string paramName, bool required = false)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (required)
                {
                    throw new StringParamIsEmptyException(paramName);
                }
                return;
            }

            if (value.Length > maximumBytes)
            {
                throw TooLong(paramName, maximumBytes);
            }

            if (value.Contains('\0'))
            {
                throw new ArgumentException($"Parameter '{paramName}' must not contain NUL characters.", paramName);
            }

            int bytes;
            try
            {
                bytes = StrictUtf8.GetByteCount(value);
            }
            catch (EncoderFallbackException)
            {
                throw new ArgumentException($"Parameter '{paramName}' is not valid Unicode (unpaired surrogate).", paramName);
            }

            if (bytes > maximumBytes)
            {
                throw TooLong(paramName, maximumBytes);
            }
        }

        public static byte[] ToNativeUtf8(string value)
        {
            byte[] bytes = new byte[StrictUtf8.GetByteCount(value) + 1];
            StrictUtf8.GetBytes(value, bytes);
            return bytes;
        }

        private static ArgumentOutOfRangeException TooLong(string paramName, int maximumBytes) =>
            new(paramName, $"Parameter '{paramName}' exceeds the maximum length of {maximumBytes} UTF-8 bytes.");
    }
}
