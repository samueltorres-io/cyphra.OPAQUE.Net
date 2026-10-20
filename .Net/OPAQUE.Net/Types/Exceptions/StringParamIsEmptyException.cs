namespace OPAQUE.Net.Types.Exceptions
{
    public class StringParamIsEmptyException : Exception
    {
        public const int MaximumPasswordLength = ParamGuard.MaximumPasswordLength;
        public const int MaximumIdentifierLength = ParamGuard.MaximumIdentifierLength;
        public const int MaximumProtocolMessageLength = ParamGuard.MaximumProtocolMessageLength;
        public StringParamIsEmptyException(string paramName) : base($"Parameter '{paramName}' can not be an empty string") { }

        public static void ThrowIfEmpty(string value, string paramName)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new StringParamIsEmptyException(paramName);
            }
        }

        [Obsolete("Use the argument checks performed by the public API; kept for source compatibility. Throws ArgumentOutOfRangeException, not this type.")]
        public static void ThrowIfLongerThan(string? value, int maximumLength, string paramName) =>
            ParamGuard.ThrowIfLongerThan(value, maximumLength, paramName);
    }
}
