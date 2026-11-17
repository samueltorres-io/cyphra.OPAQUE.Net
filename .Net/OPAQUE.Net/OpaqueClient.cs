using OPAQUE.Net.Helpers;
using OPAQUE.Net.Types.Exceptions;
using OPAQUE.Net.Types.Handles;
using OPAQUE.Net.Types.Parameters;
using OPAQUE.Net.Types.Results;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OPAQUE.Net
{
    public class OpaqueClient
    {
        /// <summary>
        /// Starts the registration process
        /// </summary>
        /// <param name="password">User's Password</param>
        /// <param name="result">A <see cref="StartClientRegistrationResult"/> filled with data if successful</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool StartRegistration(string password, out StartClientRegistrationResult? result)
        {
            ParamGuard.ThrowIfInvalid(password, ParamGuard.MaximumPasswordLength, nameof(password), required: true);

            byte[] pw = ParamGuard.ToNativeUtf8(password);
            try
            {
                result = FunctionHelper.TryExecute(() => start_client_registration(pw)?.GetAndRelease());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pw);
            }
            return result != null;
        }

        /// <summary>
        /// Finishes the registration process for the client side
        /// </summary>
        /// <param name="password">Users's Password</param>
        /// <param name="registrationResponse">Out parameter from <see cref="OpaqueServer.CreateRegistrationResponse(string, string, string, out string?)"/></param>
        /// <param name="clientRegistrationState"><see cref="StartClientRegistrationResult.ClientRegistrationState"/> from <see cref="OpaqueClient.StartRegistration(string, out StartClientRegistrationResult?)"/></param>
        /// <param name="result">A <see cref="FinishClientRegistrationResult"/> filled with data if successful</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool FinishRegistration(string password, string registrationResponse, string clientRegistrationState, out FinishClientRegistrationResult? result)
        {
            return FinishRegistration(password, registrationResponse, clientRegistrationState, "", "", null, out result);
        }

        /// <summary>
        /// Finishes the registration process for the client side
        /// </summary>
        /// <param name="password">Users's Password</param>
        /// <param name="registrationResponse">Out parameter from <see cref="OpaqueServer.CreateRegistrationResponse(string, string, string, out string?)"/></param>
        /// <param name="clientRegistrationState"><see cref="StartClientRegistrationResult.ClientRegistrationState"/> from <see cref="OpaqueClient.StartRegistration(string, out StartClientRegistrationResult?)"/></param>
        /// <param name="clientIdentifier">Current client identifier</param>
        /// <param name="serverIdentifier">Current server identifier</param>
        /// <param name="result">A <see cref="FinishClientRegistrationResult"/> filled with data if successful</param>
        /// <param name="config">The configuration representing what Argon2id parameters to use. Defaults to MemoryConstrained if not provided</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool FinishRegistration(string password, string registrationResponse, string clientRegistrationState, 
            string? clientIdentifier, string? serverIdentifier, KSFConfig? config, out FinishClientRegistrationResult? result)
        {
            ParamGuard.ThrowIfInvalid(password, ParamGuard.MaximumPasswordLength, nameof(password), required: true);
            ParamGuard.ThrowIfInvalid(registrationResponse, ParamGuard.MaximumProtocolMessageLength, nameof(registrationResponse), required: true);
            ParamGuard.ThrowIfInvalid(clientRegistrationState, ParamGuard.MaximumProtocolMessageLength, nameof(clientRegistrationState), required: true);
            ParamGuard.ThrowIfInvalid(clientIdentifier, ParamGuard.MaximumIdentifierLength, nameof(clientIdentifier));
            ParamGuard.ThrowIfInvalid(serverIdentifier, ParamGuard.MaximumIdentifierLength, nameof(serverIdentifier));

            config ??= KSFConfig.Create(KSFConfigType.MemoryConstrained);

            byte[] pw = ParamGuard.ToNativeUtf8(password);
            try
            {
                result = FunctionHelper.TryExecute(() => finish_client_registration(pw, registrationResponse,
                    clientRegistrationState, clientIdentifier ?? "", serverIdentifier ?? "", (int)config.Type, (uint)(config.Iterations ?? 0), (uint)(config.Memory ?? 0), (uint)(config.Parallelism ?? 0))?.GetAndRelease());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pw);
            }

            return result != null;
        }

        /// <summary>
        /// Starts the login process
        /// </summary>
        /// <param name="password">Users's current password</param>
        /// <param name="result">A <see cref="StartClientLoginResult"/> filled with data if successful</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool StartLogin(string password, out StartClientLoginResult? result)
        {
            ParamGuard.ThrowIfInvalid(password, ParamGuard.MaximumPasswordLength, nameof(password), required: true);

            byte[] pw = ParamGuard.ToNativeUtf8(password);
            try
            {
                result = FunctionHelper.TryExecute(() => start_client_login(pw)?.GetAndRelease());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pw);
            }
            return result != null;
        }

        /// <summary>
        /// Finishes the login process for the client
        /// </summary>
        /// <param name="clientLoginState"><see cref="StartClientLoginResult.ClientLoginState"/> from <see cref="OpaqueClient.StartLogin(string, out StartClientLoginResult?)"/></param>
        /// <param name="serverLoginResponse"><see cref="StartSealedServerLoginResult.LoginResponse"/> from <see cref="OpaqueServer.StartSealedLogin(string, string, string, string?, string?, string?, out StartSealedServerLoginResult?, out Exception?)"/></param>
        /// <param name="password">Users's current password</param>
        /// <param name="result">A <see cref="FinishClientLoginResult"/> filled with data if successful</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool FinishLogin(string clientLoginState, string serverLoginResponse, string password, out FinishClientLoginResult? result)
        {
            return FinishLogin(clientLoginState, serverLoginResponse, password, "", "", null, out result);
        }

        /// <summary>
        /// Finishes the login process for the client
        /// </summary>
        /// <param name="clientLoginState"><see cref="StartClientLoginResult.ClientLoginState"/> from <see cref="OpaqueClient.StartLogin(string, out StartClientLoginResult?)"/></param>
        /// <param name="serverLoginResponse"><see cref="StartSealedServerLoginResult.LoginResponse"/> from <see cref="OpaqueServer.StartSealedLogin(string, string, string, string?, string?, string?, out StartSealedServerLoginResult?, out Exception?)"/></param>
        /// <param name="password">Users's current password</param>
        /// <param name="clientIdentifier">Current client identifier</param>
        /// <param name="serverIdentifier">Current server identifier</param>
        /// <param name="result">A <see cref="FinishClientLoginResult"/> filled with data if successful</param>
        /// <param name="config">The configuration representing what Argon2id parameters to use. Defaults to MemoryConstrained if not provided</param>
        /// <returns>True if succeeded, false otherwise. Out parameter will not be null if succeeded</returns>
        public bool FinishLogin(string clientLoginState, string serverLoginResponse, string password, string? clientIdentifier, 
            string? serverIdentifier, KSFConfig? config, out FinishClientLoginResult? result)
        {
            ParamGuard.ThrowIfInvalid(clientLoginState, ParamGuard.MaximumProtocolMessageLength, nameof(clientLoginState), required: true);
            ParamGuard.ThrowIfInvalid(serverLoginResponse, ParamGuard.MaximumProtocolMessageLength, nameof(serverLoginResponse), required: true);
            ParamGuard.ThrowIfInvalid(password, ParamGuard.MaximumPasswordLength, nameof(password), required: true);
            ParamGuard.ThrowIfInvalid(clientIdentifier, ParamGuard.MaximumIdentifierLength, nameof(clientIdentifier));
            ParamGuard.ThrowIfInvalid(serverIdentifier, ParamGuard.MaximumIdentifierLength, nameof(serverIdentifier));

            config ??= KSFConfig.Create(KSFConfigType.MemoryConstrained);

            byte[] pw = ParamGuard.ToNativeUtf8(password);
            try
            {
                result = FunctionHelper.TryExecute(() => finish_client_login(clientLoginState, serverLoginResponse,
                    pw, clientIdentifier ?? "", serverIdentifier ?? "", (int)config.Type, (uint)(config.Iterations ?? 0), (uint)(config.Memory ?? 0), (uint)(config.Parallelism ?? 0))?.GetAndRelease());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pw);
            }

            return result != null;
        }

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StartClientRegistrationResultHandle start_client_registration(byte[] password);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern FinishClientRegistrationResultHandle finish_client_registration(byte[] password, [MarshalAs(UnmanagedType.LPUTF8Str)] string registrationResponse,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string clientRegistrationState, [MarshalAs(UnmanagedType.LPUTF8Str)] string? clientIdentifier, [MarshalAs(UnmanagedType.LPUTF8Str)] string? serverIdentifier, int configType, uint iterations, uint memory, uint parallelism);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern StartClientLoginResultHandle start_client_login(byte[] password);

        [DllImport("opaque", CallingConvention = CallingConvention.Cdecl)]
        private static extern FinishClientLoginResultHandle finish_client_login([MarshalAs(UnmanagedType.LPUTF8Str)] string clientLoginState, [MarshalAs(UnmanagedType.LPUTF8Str)] string serverLoginResponse, byte[] password,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string? clientIdentifier, [MarshalAs(UnmanagedType.LPUTF8Str)] string? serverIdentifier, int configType, uint iterations, uint memory, uint parallelism);
    }
}
