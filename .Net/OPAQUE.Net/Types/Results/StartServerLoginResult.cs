namespace OPAQUE.Net.Types.Results
{
    public class StartServerLoginResult
    {
        /// <summary>
        /// SERVER-SIDE SECRET. Never send this to the client, put it in a cookie, URL, log or shared cache.
        /// It contains the session key in clear and the material to forge the client's finish message, so
        /// anyone holding it can complete the login without the password. Keep it on the server only
        /// (e.g. in a server-side store keyed by an opaque id), give it a short TTL, pass it to
        /// <see cref="OpaqueServer.FinishLogin(string, string, out string?)"/> at most once and delete it
        /// afterwards. Only <see cref="LoginResponse"/> goes to the client.
        /// </summary>
        public string ServerLoginState { get; private set; }
        /// <summary>The only value of this result that is sent to the client.</summary>
        public string LoginResponse { get; private set; }

        public StartServerLoginResult(string serverLoginState, string loginResponse)
        {
            ServerLoginState = serverLoginState;
            LoginResponse = loginResponse;
        }
    }
}
