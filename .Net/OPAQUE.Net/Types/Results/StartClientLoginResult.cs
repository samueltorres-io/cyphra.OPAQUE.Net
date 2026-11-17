namespace OPAQUE.Net.Types.Results
{
    public class StartClientLoginResult
    {
        public string ClientLoginState { get; private set; }
        public string StartLoginRequest { get; private set; }

        public StartClientLoginResult(string clientLoginState, string startLoginRequest)
        {
            ClientLoginState = clientLoginState;
            StartLoginRequest = startLoginRequest;
        }

        // Redacted: the properties hold secrets or flow state that must not end up in logs.
        public override string ToString() => nameof(StartClientLoginResult);
    }
}
