namespace OPAQUE.Net.Types.Exceptions
{
    // An ArgumentException like every other argument check, so one catch covers them all.
    public class StringParamIsEmptyException : ArgumentException
    {
        public StringParamIsEmptyException(string paramName) : base($"Parameter '{paramName}' can not be an empty string", paramName) { }
    }
}
