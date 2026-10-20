using System.Text;

namespace OPAQUE.Net.Types.Exceptions
{
    internal static class ParamGuard
    {
        public const int MaximumPasswordLength = 1024;
        public const int MaximumIdentifierLength = 1024;
        public const int MaximumProtocolMessageLength = 64 * 1024;

        private static readonly UTF8Encoding StrictUtf8 = new(false, true);

        /// <summary>
        /// Rejects what the native boundary would silently alter: embedded NUL (truncates the value),
        /// unpaired surrogates (replaced by U+FFFD) and anything over <paramref name="maximumBytes"/>
        /// UTF-8 bytes, the unit the native side enforces. No Unicode normalization is applied.
        /// </summary>
        public static void ThrowIfInvalid(string? value, int maximumBytes, string paramName)
        {
            if (value is null)
            {
                return;
            }

            if (value.Length > maximumBytes)
            {
                // Every char takes at least one UTF-8 byte, so this is too long without encoding it.
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

        private static ArgumentOutOfRangeException TooLong(string paramName, int maximumBytes) =>
            new(paramName, $"Parameter '{paramName}' exceeds the maximum length of {maximumBytes} UTF-8 bytes.");
    }
}
