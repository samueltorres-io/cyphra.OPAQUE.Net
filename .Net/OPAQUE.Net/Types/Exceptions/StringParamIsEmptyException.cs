namespace OPAQUE.Net.Types.Exceptions
{
    public class StringParamIsEmptyException : ArgumentException
    {
        public StringParamIsEmptyException(string paramName) : base($"Parameter '{paramName}' can not be an empty string", paramName) { }
    }
}
