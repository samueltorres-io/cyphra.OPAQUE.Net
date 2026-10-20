namespace OPAQUE.Net.Types.Results
{
    public class StartSealedServerLoginResult
    {
        /// <summary>
        /// The server login state, encrypted and authenticated with a key derived from the server setup.
        /// It reveals nothing about the session, cannot be forged or modified, is rejected by a server
        /// with a different setup, and expires after two minutes. It may be kept in any server-side
        /// store; it is still not meant for the client. It is not single-use: to refuse a replay inside
        /// the window, remember it (or its hash) until it expires and reject a second use.
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
