using OPAQUE.Net.Helpers;
using OPAQUE.Net.Types.Exceptions;
using OPAQUE.Net.Types.Handles;
using OPAQUE.Net.Types.Results;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OPAQUE.Net
{
    public class OpaqueServer
    {
        /// <summary>
        /// Creates the server setup
        /// </summary>
        /// <param name="serverSetup">The server setup</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool CreateSetup(out string? serverSetup)
        {
            serverSetup = FunctionHelper.TryExecute(() => create_server_setup()?.GetAndRelease());
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
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup), required: true);

            byte[] setup = ParamGuard.ToNativeUtf8(serverSetup);
            try
            {
                publicKey = FunctionHelper.TryExecute(() => get_server_public_key(setup)?.GetAndRelease());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(setup);
            }
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
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup), required: true);
            ParamGuard.ThrowIfInvalid(userIdentifier, ParamGuard.MaximumIdentifierLength, nameof(userIdentifier), required: true);
            ParamGuard.ThrowIfInvalid(registrationRequest, ParamGuard.MaximumProtocolMessageLength, nameof(registrationRequest), required: true);

            byte[] setup = ParamGuard.ToNativeUtf8(serverSetup);
            try
            {
                registrationResponse = FunctionHelper.TryExecute(() => create_server_registration_response(setup, userIdentifier,
                    registrationRequest)?.GetAndRelease());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(setup);
            }

            return !string.IsNullOrEmpty(registrationResponse);
        }

        /// <summary>
        /// Starts the login process for the server and returns the server state sealed under
        /// <paramref name="serverSetup"/> and bound to <paramref name="userIdentifier"/>. All instances serving
        /// the same users must share the setup.
        /// </summary>
        /// <param name="serverSetup">String from <see cref="OpaqueServer.CreateSetup(out string?)"/></param>
        /// <param name="startLoginRequest"><see cref="StartClientLoginResult.StartLoginRequest"/> from the client</param>
        /// <param name="userIdentifier">Current user identifier</param>
        /// <param name="registrationRecord">The user's registration record, or null/empty if the user does not exist.
        /// A record that cannot be decoded is treated like an absent one: the client gets an ordinary response and
        /// the login fails at the finish step.</param>
        /// <param name="result">A <see cref="StartSealedServerLoginResult"/> filled with data if successful</param>
        /// <param name="e">An exception thrown while calling into the native library (for example a marshalling fault).
        /// Native failures, including an undecodable <paramref name="serverSetup"/>, a clock before 1970 or a sealing
        /// error, return false with this null, like a protocol failure; validate the setup once at startup with
        /// <see cref="GetPublicKey(string, out string?)"/>.</param>
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
        /// <param name="e">An exception thrown while calling into the native library (for example a marshalling fault).
        /// Native failures, including an undecodable <paramref name="serverSetup"/>, a clock before 1970 or a sealing
        /// error, return false with this null, like a protocol failure; validate the setup once at startup with
        /// <see cref="GetPublicKey(string, out string?)"/>.</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        /// <param name="clientIdentity">Current client identifier</param>
        /// <param name="serverIdentity">Current server identifier</param>
        public bool StartSealedLogin(string serverSetup, string startLoginRequest, string userIdentifier,
            string? registrationRecord, string? clientIdentity, string? serverIdentity, out StartSealedServerLoginResult? result, out Exception? e)
        {
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup), required: true);
            ParamGuard.ThrowIfInvalid(startLoginRequest, ParamGuard.MaximumProtocolMessageLength, nameof(startLoginRequest), required: true);
            ParamGuard.ThrowIfInvalid(userIdentifier, ParamGuard.MaximumIdentifierLength, nameof(userIdentifier), required: true);
            ParamGuard.ThrowIfInvalid(registrationRecord, ParamGuard.MaximumProtocolMessageLength, nameof(registrationRecord));
            ParamGuard.ThrowIfInvalid(clientIdentity, ParamGuard.MaximumIdentifierLength, nameof(clientIdentity));
            ParamGuard.ThrowIfInvalid(serverIdentity, ParamGuard.MaximumIdentifierLength, nameof(serverIdentity));

            byte[] setup = ParamGuard.ToNativeUtf8(serverSetup);
            try
            {
                result = FunctionHelper.TryExecute(() => start_server_login_sealed(setup, startLoginRequest,
                    userIdentifier, registrationRecord ?? "", clientIdentity ?? "", serverIdentity ?? "")?.GetAndRelease(), out e);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(setup);
            }

            return result != null;
        }

        /// <summary>Removed: a sealed state is bound to its user identifier, which this overload does not take.</summary>
        [Obsolete("Sealed states are bound to the user identifier and are single-use: call FinishSealedLogin(serverSetup, userIdentifier, sealedLoginState, finishLoginRequest, tryConsume, out serverSessionKey).", true)]
        public bool FinishSealedLogin(string serverSetup, string sealedLoginState, string finishLoginRequest, out string? serverSessionKey) =>
            throw new NotSupportedException("Use FinishSealedLogin(serverSetup, userIdentifier, sealedLoginState, finishLoginRequest, tryConsume, out serverSessionKey).");

        /// <summary>Removed: a sealed state is bound to its user identifier, which this overload does not take.</summary>
        [Obsolete("Sealed states are bound to the user identifier: call FinishSealedLogin(serverSetup, userIdentifier, sealedLoginState, finishLoginRequest, tryConsume, out serverSessionKey).", true)]
        public bool FinishSealedLogin(string serverSetup, string sealedLoginState, string finishLoginRequest,
            Func<string, bool> tryConsume, out string? serverSessionKey) =>
            throw new NotSupportedException("Use FinishSealedLogin(serverSetup, userIdentifier, sealedLoginState, finishLoginRequest, tryConsume, out serverSessionKey).");

        /// <summary>
        /// Finishes the login process for the server from a sealed state, once. Fails (false) for a state that
        /// was tampered with, expired, or produced under another setup or for another user. After the state and the client's finish message verify, <paramref name="tryConsume"/> is called
        /// once with a stable identifier of the state (SHA-256 hex of the sealed value). It must atomically record
        /// the identifier and return true only the first time it sees it; on false the login fails and no key is
        /// returned. Back it with storage shared by all instances (e.g. Redis <c>SET NX</c> with a TTL of at
        /// least 120 s), or use one process-wide <see cref="LoginStateReplayCache"/> for a single instance.
        /// </summary>
        /// <param name="serverSetup">The same setup passed to <c>StartSealedLogin</c></param>
        /// <param name="userIdentifier">The user identifier passed to <c>StartSealedLogin</c>. The login succeeds only
        /// for that exact value, so on success the session belongs to this user.</param>
        /// <param name="sealedLoginState"><see cref="StartSealedServerLoginResult.SealedLoginState"/></param>
        /// <param name="finishLoginRequest"><see cref="FinishClientLoginResult.FinishLoginRequest"/> from the client</param>
        /// <param name="tryConsume">Atomic first-use check, see above</param>
        /// <param name="serverSessionKey">The generated session key</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool FinishSealedLogin(string serverSetup, string userIdentifier, string sealedLoginState, string finishLoginRequest,
            Func<string, bool> tryConsume, out string? serverSessionKey)
        {
            ParamGuard.ThrowIfInvalid(serverSetup, ParamGuard.MaximumProtocolMessageLength, nameof(serverSetup), required: true);
            ParamGuard.ThrowIfInvalid(userIdentifier, ParamGuard.MaximumIdentifierLength, nameof(userIdentifier), required: true);
            ParamGuard.ThrowIfInvalid(sealedLoginState, ParamGuard.MaximumProtocolMessageLength, nameof(sealedLoginState), required: true);
            ParamGuard.ThrowIfInvalid(finishLoginRequest, ParamGuard.MaximumProtocolMessageLength, nameof(finishLoginRequest), required: true);
            ArgumentNullException.ThrowIfNull(tryConsume);

            byte[] setup = ParamGuard.ToNativeUtf8(serverSetup);
            try
            {
                serverSessionKey = FunctionHelper.TryExecute(() => finish_server_login_sealed(setup, userIdentifier, sealedLoginState, finishLoginRequest)?.GetAndRelease());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(setup);
            }
            if (string.IsNullOrEmpty(serverSessionKey))
            {
                serverSessionKey = null;
                return false;
            }

            // The native base64url decoder is canonical (no padding, no spare bits), so each blob has exactly
            // one string form and hashing the string cannot be dodged by re-encoding it.
            bool first = false;
            try
            {
                first = tryConsume(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sealedLoginState))));
            }
            finally
            {
                if (!first)
                {
                    serverSessionKey = null; // also when tryConsume throws: never hand out an unconsumed key
                }
            }

            return first;
        }

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle create_server_setup();

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle get_server_public_key(byte[] secret);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle create_server_registration_response(byte[] serverSetup, [MarshalAs(UnmanagedType.LPUTF8Str)] string userIdentifier, [MarshalAs(UnmanagedType.LPUTF8Str)] string registrationRequest);



        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StartSealedServerLoginResultHandle start_server_login_sealed(byte[] serverSetup, [MarshalAs(UnmanagedType.LPUTF8Str)] string startLoginRequest,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string userIdentifier, [MarshalAs(UnmanagedType.LPUTF8Str)] string? registrationRecord, [MarshalAs(UnmanagedType.LPUTF8Str)] string? clientIdentity, [MarshalAs(UnmanagedType.LPUTF8Str)] string? serverIdentity);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StringHandle finish_server_login_sealed(byte[] serverSetup, [MarshalAs(UnmanagedType.LPUTF8Str)] string userIdentifier, [MarshalAs(UnmanagedType.LPUTF8Str)] string sealedLoginState, [MarshalAs(UnmanagedType.LPUTF8Str)] string finishLoginRequest);
    }
}
