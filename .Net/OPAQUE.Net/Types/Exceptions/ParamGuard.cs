namespace OPAQUE.Net.Types.Exceptions
{
    internal static class ParamGuard
    {
        public const int MaximumPasswordLength = 1024;
        public const int MaximumIdentifierLength = 1024;
        public const int MaximumProtocolMessageLength = 64 * 1024;

        public static void ThrowIfLongerThan(string? value, int maximumLength, string paramName)
        {
            if (value is not null && value.Length > maximumLength)
            {
                throw new ArgumentOutOfRangeException(paramName, $"Parameter '{paramName}' exceeds the maximum length of {maximumLength} characters.");
            }
        }
    }
}
