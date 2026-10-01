namespace OPAQUE.Net.Types.Exceptions
{
    public class StringParamIsEmptyException : Exception
    {
        public const int MaximumPasswordLength = 1024;
        public const int MaximumIdentifierLength = 1024;
        public const int MaximumProtocolMessageLength = 64 * 1024;
        public StringParamIsEmptyException(string paramName) : base($"Parameter '{paramName}' can not be an empty string") { }

        public static void ThrowIfEmpty(string value, string paramName)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new StringParamIsEmptyException(paramName);
            }
        }

        public static void ThrowIfLongerThan(string? value, int maximumLength, string paramName)
        {
            if (value is not null && value.Length > maximumLength)
            {
                throw new ArgumentOutOfRangeException(paramName, $"Parameter '{paramName}' exceeds the maximum length of {maximumLength} characters.");
            }
        }
    }
}
