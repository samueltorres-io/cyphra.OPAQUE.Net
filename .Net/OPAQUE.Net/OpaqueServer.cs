using OPAQUE.Net.Helpers;
using OPAQUE.Net.Types.Exceptions;
using OPAQUE.Net.Types.Handles;
using OPAQUE.Net.Types.Results;
using System.Runtime.InteropServices;

namespace OPAQUE.Net
{
    public class OpaqueServer
    {
        public OpaqueServer() { }

        /// <summary>
        /// Creates the server setup
        /// </summary>
        /// <param name="serverSetup">The server setup</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool CreateSetup(out string? serverSetup)
        {
            serverSetup = FunctionHelper.TryExecute(create_server_setup)?.GetAndRelease();
            return !string.IsNullOrEmpty(serverSetup);
        }

        /// <summary>
        /// Gets the public key for a server setup
        /// </summary>
        /// <param name="serverSetup">String from <see cref="OpaqueServer.CreateSetup(out string?)"/></param>
        /// <param name="publicKey">The public key for the server setup</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool GetPublicKey(string serverSetup, out string? publicKey)
        {
            StringParamIsEmptyException.ThrowIfEmpty(serverSetup, nameof(serverSetup));
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup));

            publicKey = FunctionHelper.TryExecute(() => get_server_public_key(serverSetup))?.GetAndRelease();
            return !string.IsNullOrEmpty(publicKey);
        }

        /// <summary>
        /// Creates a registration response
        /// </summary>
        /// <param name="serverSetup">String from <see cref="OpaqueServer.CreateSetup(out string?)"/></param>
        /// <param name="userIdentifier">Current user identifier</param>
        /// <param name="registrationRequest"><see cref="StartClientRegistrationResult.RegistrationRequest"/> from <see cref="OpaqueClient.StartRegistration(string, out StartClientRegistrationResult?)"/></param>
        /// <param name="registrationResponse">The resposne from the registration</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool CreateRegistrationResponse(string serverSetup, string userIdentifier, string registrationRequest, out string? registrationResponse)
        {
            StringParamIsEmptyException.ThrowIfEmpty(serverSetup, nameof(serverSetup));
            StringParamIsEmptyException.ThrowIfEmpty(userIdentifier, nameof(userIdentifier));
            StringParamIsEmptyException.ThrowIfEmpty(registrationRequest, nameof(registrationRequest));
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup));
            ParamGuard.ThrowIfInvalid(userIdentifier, ParamGuard.MaximumIdentifierLength, nameof(userIdentifier));
            ParamGuard.ThrowIfInvalid(registrationRequest, ParamGuard.MaximumProtocolMessageLength, nameof(registrationRequest));

            registrationResponse = FunctionHelper.TryExecute(() => create_server_registration_response(serverSetup, userIdentifier, 
                registrationRequest))?.GetAndRelease();

            return !string.IsNullOrEmpty(registrationResponse);
        }

        /// <summary>
        /// Starts the login process for the server
        /// </summary>
        /// <param name="serverSetup">String from <see cref="OpaqueServer.CreateSetup(out string?)"/></param>
        /// <param name="startLoginRequest"><see cref="StartClientLoginResult.StartLoginRequest"/> from <see cref="OpaqueClient.StartLogin(string, out StartClientLoginResult?)"/></param>
        /// <param name="userIdentifier">Current user identifier</param>
        /// <param name="registrationRecord"><see cref="FinishClientRegistrationResult.RegistrationRecord"/> from <see cref="OpaqueClient.FinishRegistration(string, string, string, string?, string?, OPAQUE.Net.Types.Parameters.KSFConfig, out FinishClientRegistrationResult?)"/></param>
        /// <param name="result">A <see cref="StartServerLoginResult"/> filled with data if successful</param>
        /// <param name="e">The infrastructure exception, if the native call fails</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        [Obsolete("The raw ServerLoginState is a bearer secret: anyone holding it can finish the login without the password. Use StartSealedLogin/FinishSealedLogin.")]
        public bool StartLogin(string serverSetup, string startLoginRequest, string userIdentifier, string? registrationRecord, out StartServerLoginResult? result, out Exception? e)
        {
            return StartLogin(serverSetup, startLoginRequest, userIdentifier, registrationRecord, "", "", out result, out e);
        }

        /// <summary>
        /// Starts the login process for the server
        /// </summary>
        /// <param name="serverSetup">String from <see cref="OpaqueServer.CreateSetup(out string?)"/></param>
        /// <param name="startLoginRequest"><see cref="StartClientLoginResult.StartLoginRequest"/> from <see cref="OpaqueClient.StartLogin(string, out StartClientLoginResult?)"/></param>
        /// <param name="userIdentifier">Current user identifier</param>
        /// <param name="registrationRecord"><see cref="FinishClientRegistrationResult.RegistrationRecord"/> from <see cref="OpaqueClient.FinishRegistration(string, string, string, string?, string?, OPAQUE.Net.Types.Parameters.KSFConfig, out FinishClientRegistrationResult?)"/></param>
        /// <param name="clientIdentity">Current client identifier</param>
        /// <param name="serverIdentity">Current server identifier</param>
        /// <param name="result">A <see cref="StartServerLoginResult"/> filled with data if successful</param>
        /// <param name="e">The infrastructure exception, if the native call fails</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        [Obsolete("The raw ServerLoginState is a bearer secret: anyone holding it can finish the login without the password. Use StartSealedLogin/FinishSealedLogin.")]
        public bool StartLogin(string serverSetup, string startLoginRequest, string userIdentifier, 
            string? registrationRecord, string? clientIdentity, string? serverIdentity, out StartServerLoginResult? result, out Exception? e)
        {
            StringParamIsEmptyException.ThrowIfEmpty(serverSetup, nameof(serverSetup));
            StringParamIsEmptyException.ThrowIfEmpty(startLoginRequest, nameof(startLoginRequest));
            StringParamIsEmptyException.ThrowIfEmpty(userIdentifier, nameof(userIdentifier));
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup));
            ParamGuard.ThrowIfInvalid(startLoginRequest, ParamGuard.MaximumProtocolMessageLength, nameof(startLoginRequest));
            ParamGuard.ThrowIfInvalid(userIdentifier, ParamGuard.MaximumIdentifierLength, nameof(userIdentifier));
            ParamGuard.ThrowIfInvalid(registrationRecord, ParamGuard.MaximumProtocolMessageLength, nameof(registrationRecord));
            ParamGuard.ThrowIfInvalid(clientIdentity, ParamGuard.MaximumIdentifierLength, nameof(clientIdentity));
            ParamGuard.ThrowIfInvalid(serverIdentity, ParamGuard.MaximumIdentifierLength, nameof(serverIdentity));

            result = FunctionHelper.TryExecute(() => start_server_login(serverSetup, startLoginRequest, 
                userIdentifier, registrationRecord ?? "", clientIdentity ?? "", serverIdentity ?? ""), out e)?.GetAndRelease();

            return result != null;
        }

        /// <summary>
        /// Finishes the login process for the server
        /// </summary>
        /// <param name="serverLoginState"><see cref="StartServerLoginResult.ServerLoginState"/> from <see cref="OpaqueServer.StartLogin(string, string, string, string?, string?, string?, out StartServerLoginResult?, out Exception?)"/></param>
        /// <param name="finishLoginRequest"><see cref="FinishClientLoginResult.FinishLoginRequest"/> from <see cref="OpaqueClient.FinishLogin(string, string, string, string?, string?, OPAQUE.Net.Types.Parameters.KSFConfig, out FinishClientLoginResult?)"/></param>
        /// <param name="serverSessionKey">The generated session key</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        [Obsolete("The raw ServerLoginState is a bearer secret: anyone holding it can finish the login without the password. Use StartSealedLogin/FinishSealedLogin.")]
        public bool FinishLogin(string serverLoginState, string finishLoginRequest, out string? serverSessionKey)
        {
            StringParamIsEmptyException.ThrowIfEmpty(serverLoginState, nameof(serverLoginState));
            StringParamIsEmptyException.ThrowIfEmpty(finishLoginRequest, nameof(finishLoginRequest));
            ParamGuard.ThrowIfInvalid(serverLoginState, ParamGuard.MaximumProtocolMessageLength, nameof(serverLoginState));
            ParamGuard.ThrowIfInvalid(finishLoginRequest, ParamGuard.MaximumProtocolMessageLength, nameof(finishLoginRequest));

            serverSessionKey = FunctionHelper.TryExecute(() => finish_server_login(serverLoginState, finishLoginRequest))?.GetAndRelease();
            return !string.IsNullOrEmpty(serverSessionKey);
        }

        /// <summary>
        /// Starts the login process for the server and returns the server state sealed under
        /// <paramref name="serverSetup"/>. Prefer this over <c>StartLogin</c>: the raw state is a bearer
        /// secret, the sealed one is not. All instances serving the same users must share the setup.
        /// </summary>
        /// <param name="serverSetup">String from <see cref="OpaqueServer.CreateSetup(out string?)"/></param>
        /// <param name="startLoginRequest"><see cref="StartClientLoginResult.StartLoginRequest"/> from the client</param>
        /// <param name="userIdentifier">Current user identifier</param>
        /// <param name="registrationRecord">The user's registration record, or null/empty if the user does not exist</param>
        /// <param name="result">A <see cref="StartSealedServerLoginResult"/> filled with data if successful</param>
        /// <param name="e">The infrastructure exception, if the native call fails</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool StartSealedLogin(string serverSetup, string startLoginRequest, string userIdentifier,
            string? registrationRecord, out StartSealedServerLoginResult? result, out Exception? e)
        {
            return StartSealedLogin(serverSetup, startLoginRequest, userIdentifier, registrationRecord, "", "", out result, out e);
        }

        /// <summary>Starts the login process for the server with explicit client and server identifiers, returning the sealed server state.</summary>
        /// <param name="serverSetup">String from <see cref="OpaqueServer.CreateSetup(out string?)"/></param>
        /// <param name="startLoginRequest"><see cref="StartClientLoginResult.StartLoginRequest"/> from the client</param>
        /// <param name="userIdentifier">Current user identifier</param>
        /// <param name="registrationRecord">The user's registration record, or null/empty if the user does not exist</param>
        /// <param name="result">A <see cref="StartSealedServerLoginResult"/> filled with data if successful</param>
        /// <param name="e">The infrastructure exception, if the native call fails</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        /// <param name="clientIdentity">Current client identifier</param>
        /// <param name="serverIdentity">Current server identifier</param>
        public bool StartSealedLogin(string serverSetup, string startLoginRequest, string userIdentifier,
            string? registrationRecord, string? clientIdentity, string? serverIdentity, out StartSealedServerLoginResult? result, out Exception? e)
        {
            StringParamIsEmptyException.ThrowIfEmpty(serverSetup, nameof(serverSetup));
            StringParamIsEmptyException.ThrowIfEmpty(startLoginRequest, nameof(startLoginRequest));
            StringParamIsEmptyException.ThrowIfEmpty(userIdentifier, nameof(userIdentifier));
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup));
            ParamGuard.ThrowIfInvalid(startLoginRequest, ParamGuard.MaximumProtocolMessageLength, nameof(startLoginRequest));
            ParamGuard.ThrowIfInvalid(userIdentifier, ParamGuard.MaximumIdentifierLength, nameof(userIdentifier));
            ParamGuard.ThrowIfInvalid(registrationRecord, ParamGuard.MaximumProtocolMessageLength, nameof(registrationRecord));
            ParamGuard.ThrowIfInvalid(clientIdentity, ParamGuard.MaximumIdentifierLength, nameof(clientIdentity));
            ParamGuard.ThrowIfInvalid(serverIdentity, ParamGuard.MaximumIdentifierLength, nameof(serverIdentity));

            StartServerLoginResult? started = FunctionHelper.TryExecute(() => start_server_login_sealed(serverSetup, startLoginRequest,
                userIdentifier, registrationRecord ?? "", clientIdentity ?? "", serverIdentity ?? ""), out e)?.GetAndRelease();

            result = started == null ? null : new StartSealedServerLoginResult(started.ServerLoginState, started.LoginResponse);
            return result != null;
        }

        /// <summary>
        /// Finishes the login process for the server from a sealed state. Fails (false) for a state that
        /// was tampered with, expired, produced under another setup, or that is a raw legacy state.
        /// </summary>
        /// <param name="serverSetup">The same setup passed to <c>StartSealedLogin</c></param>
        /// <param name="sealedLoginState"><see cref="StartSealedServerLoginResult.SealedLoginState"/></param>
        /// <param name="finishLoginRequest"><see cref="FinishClientLoginResult.FinishLoginRequest"/> from the client</param>
        /// <param name="serverSessionKey">The generated session key</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool FinishSealedLogin(string serverSetup, string sealedLoginState, string finishLoginRequest, out string? serverSessionKey)
        {
            StringParamIsEmptyException.ThrowIfEmpty(serverSetup, nameof(serverSetup));
            StringParamIsEmptyException.ThrowIfEmpty(sealedLoginState, nameof(sealedLoginState));
            StringParamIsEmptyException.ThrowIfEmpty(finishLoginRequest, nameof(finishLoginRequest));
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup));
            ParamGuard.ThrowIfInvalid(sealedLoginState, ParamGuard.MaximumProtocolMessageLength, nameof(sealedLoginState));
            ParamGuard.ThrowIfInvalid(finishLoginRequest, ParamGuard.MaximumProtocolMessageLength, nameof(finishLoginRequest));

            serverSessionKey = FunctionHelper.TryExecute(() => finish_server_login_sealed(serverSetup, sealedLoginState, finishLoginRequest))?.GetAndRelease();
            return !string.IsNullOrEmpty(serverSessionKey);
        }

        /// <summary>
        /// Like <see cref="FinishSealedLogin(string, string, string, out string?)"/> but enforces single use:
        /// after the state and the client's finish message verify, <paramref name="tryConsume"/> is called once
        /// with a stable identifier of the state (SHA-256 hex of the sealed value). It must atomically record
        /// the identifier and return true only the first time it sees it; on false the login fails and no key is
        /// returned. Back it with storage shared by all instances (e.g. Redis <c>SET NX</c> with a TTL of at
        /// least 120 s), or use <see cref="LoginStateReplayCache"/> for a single instance.
        /// </summary>
        public bool FinishSealedLogin(string serverSetup, string sealedLoginState, string finishLoginRequest,
            Func<string, bool> tryConsume, out string? serverSessionKey)
        {
            ArgumentNullException.ThrowIfNull(tryConsume);
            if (!FinishSealedLogin(serverSetup, sealedLoginState, finishLoginRequest, out serverSessionKey))
            {
                return false;
            }

            if (tryConsume(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sealedLoginState)))))
            {
                return true;
            }

            serverSessionKey = null;
            return false;
        }

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle create_server_setup();

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle get_server_public_key([MarshalAs(UnmanagedType.LPUTF8Str)] string secret);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle create_server_registration_response([MarshalAs(UnmanagedType.LPUTF8Str)] string serverSetup, [MarshalAs(UnmanagedType.LPUTF8Str)] string userIdentifier, [MarshalAs(UnmanagedType.LPUTF8Str)] string registrationRequest);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StartServerLoginResultHandle start_server_login([MarshalAs(UnmanagedType.LPUTF8Str)] string serverSetup, [MarshalAs(UnmanagedType.LPUTF8Str)] string startLoginRequest,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string userIdentifier, [MarshalAs(UnmanagedType.LPUTF8Str)] string? registrationRecord, [MarshalAs(UnmanagedType.LPUTF8Str)] string? clientIdentity, [MarshalAs(UnmanagedType.LPUTF8Str)] string? serverIdentity);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle finish_server_login([MarshalAs(UnmanagedType.LPUTF8Str)] string serverLoginState, [MarshalAs(UnmanagedType.LPUTF8Str)] string finishLoginRequest);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StartServerLoginResultHandle start_server_login_sealed([MarshalAs(UnmanagedType.LPUTF8Str)] string serverSetup, [MarshalAs(UnmanagedType.LPUTF8Str)] string startLoginRequest,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string userIdentifier, [MarshalAs(UnmanagedType.LPUTF8Str)] string? registrationRecord, [MarshalAs(UnmanagedType.LPUTF8Str)] string? clientIdentity, [MarshalAs(UnmanagedType.LPUTF8Str)] string? serverIdentity);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle finish_server_login_sealed([MarshalAs(UnmanagedType.LPUTF8Str)] string serverSetup, [MarshalAs(UnmanagedType.LPUTF8Str)] string sealedLoginState, [MarshalAs(UnmanagedType.LPUTF8Str)] string finishLoginRequest);
    }
}
