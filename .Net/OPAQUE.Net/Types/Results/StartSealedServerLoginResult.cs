namespace OPAQUE.Net.Types.Results
{
    public class StartSealedServerLoginResult
    {
        /// <summary>
        /// The server login state, encrypted and bound to the server setup and user identifier; expires after two
        /// minutes. Keep it in any server-side store, never send it to the client.
        /// </summary>
        public string SealedLoginState { get; private set; }

        /// <summary>The only value of this result that is sent to the client.</summary>
        public string LoginResponse { get; private set; }

        public StartSealedServerLoginResult(string sealedLoginState, string loginResponse)
        {
            SealedLoginState = sealedLoginState;
            LoginResponse = loginResponse;
        }

        public override string ToString() => nameof(StartSealedServerLoginResult);
    }
}
