using OPAQUE.Net;
using OPAQUE.Net.Helpers;
using OPAQUE.Net.Types.Exceptions;
using OPAQUE.Net.Types.Parameters;
using OPAQUE.Net.Types.Results;

namespace Test
{
    [TestClass]
    public class OpaqueTest
    {
        private void SetupAndRegister(string userIdentifier, string password, string? clientIdentifier, string? serverIdentifier, KSFConfig? config,
            out string serverSetup, out string registrationRecord, out string exportKey, out string serverStaticPublicKey)
        {
            serverSetup = "";
            registrationRecord = "";
            exportKey = "";
            serverStaticPublicKey = "";

            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();

            if (!server.CreateSetup(out string? serverSecret))
            {
                throw new Exception();
            }

            if (!client.StartRegistration(password, out StartClientRegistrationResult? clientRegistrationResult))
            {
                throw new Exception();
            }

            if (!server.CreateRegistrationResponse(serverSecret!, userIdentifier, clientRegistrationResult!.RegistrationRequest,
                out string? serverRegistrationResponse))
            {
                throw new Exception();
            }

            if (!client.FinishRegistration(password, serverRegistrationResponse!,
                clientRegistrationResult.ClientRegistrationState, clientIdentifier, serverIdentifier, config,
                out FinishClientRegistrationResult? finishRegistrationResult))
            {
                throw new Exception();
            }

            serverSetup = serverSecret!;
            registrationRecord = finishRegistrationResult!.RegistrationRecord;
            exportKey = finishRegistrationResult.ExportKey;
            serverStaticPublicKey = finishRegistrationResult.ServerStaticPublicKey;
        }

        [TestMethod]
        public void FullRegistrationAndLoginSucceeds()
        {
            string userIdentifier = "user123";
            string password = "hunter42";

            SetupAndRegister(userIdentifier, password, null, null, null, out string serverSetup, out string registrationRecord,
                out string exportKey, out string serverStaticPublicKey);

            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();

            if (!client.StartLogin(password, out StartClientLoginResult? clientLoginResult))
            {
                throw new Exception();
            }

            if (!server.StartLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartServerLoginResult? serverLoginResult, out _))
            {
                throw new Exception();
            }

            if (!client.FinishLogin(clientLoginResult.ClientLoginState, serverLoginResult!.LoginResponse, password,
                null, null, null, out FinishClientLoginResult? finishClientLoginResult))
            {
                throw new Exception();
            }

            if (!server.GetPublicKey(serverSetup, out string? serverPublicKey))
            {
                throw new Exception();
            }

            Assert.AreEqual(exportKey, finishClientLoginResult!.ExportKey);
            Assert.AreEqual(serverStaticPublicKey, finishClientLoginResult.ServerStaticPublicKey);
            Assert.AreEqual(finishClientLoginResult.ServerStaticPublicKey, serverPublicKey);

            if (!server.FinishLogin(serverLoginResult.ServerLoginState, finishClientLoginResult.FinishLoginRequest, out string? sessionKey))
            {
                throw new Exception();
            }

            Assert.AreEqual(sessionKey, finishClientLoginResult.SessionKey);
        }

        [TestMethod]
        public void FullRegistrationAndLoginSucceedsWithRFCDraftRecommendKSF()
        {
            string userIdentifier = "user123";
            string password = "hunter42";

            KSFConfig config = KSFConfig.Create(KSFConfigType.RfcDraftRecommended);

            SetupAndRegister(userIdentifier, password, null, null, config, out string serverSetup, out string registrationRecord,
                out string exportKey, out string serverStaticPublicKey);

            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();

            if (!client.StartLogin(password, out StartClientLoginResult? clientLoginResult))
            {
                throw new Exception();
            }

            if (!server.StartLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartServerLoginResult? serverLoginResult, out _))
            {
                throw new Exception();
            }

            if (!client.FinishLogin(clientLoginResult.ClientLoginState, serverLoginResult!.LoginResponse, password,
                null, null, config, out FinishClientLoginResult? finishClientLoginResult))
            {
                throw new Exception();
            }

            if (!server.GetPublicKey(serverSetup, out string? serverPublicKey))
            {
                throw new Exception();
            }

            Assert.AreEqual(exportKey, finishClientLoginResult!.ExportKey);
            Assert.AreEqual(serverStaticPublicKey, finishClientLoginResult.ServerStaticPublicKey);
            Assert.AreEqual(finishClientLoginResult.ServerStaticPublicKey, serverPublicKey);

            if (!server.FinishLogin(serverLoginResult.ServerLoginState, finishClientLoginResult.FinishLoginRequest, out string? sessionKey))
            {
                throw new Exception();
            }

            Assert.AreEqual(sessionKey, finishClientLoginResult.SessionKey);
        }

        [TestMethod]
        public void FullRegistrationAndLoginSucceedsWithCustomKSFConfig()
        {
            string userIdentifier = "user123";
            string password = "hunter42";

            KSFConfig config = KSFConfig.Create(KSFConfigType.Custom, 1, 65536, 4);

            SetupAndRegister(userIdentifier, password, null, null, config, out string serverSetup, out string registrationRecord,
                out string exportKey, out string serverStaticPublicKey);

            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();

            if (!client.StartLogin(password, out StartClientLoginResult? clientLoginResult))
            {
                throw new Exception();
            }

            if (!server.StartLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartServerLoginResult? serverLoginResult, out _))
            {
                throw new Exception();
            }

            if (!client.FinishLogin(clientLoginResult.ClientLoginState, serverLoginResult!.LoginResponse, password,
                null, null, config, out FinishClientLoginResult? finishClientLoginResult))
            {
                throw new Exception();
            }

            if (!server.GetPublicKey(serverSetup, out string? serverPublicKey))
            {
                throw new Exception();
            }

            Assert.AreEqual(exportKey, finishClientLoginResult!.ExportKey);
            Assert.AreEqual(serverStaticPublicKey, finishClientLoginResult.ServerStaticPublicKey);
            Assert.AreEqual(finishClientLoginResult.ServerStaticPublicKey, serverPublicKey);

            if (!server.FinishLogin(serverLoginResult.ServerLoginState, finishClientLoginResult.FinishLoginRequest, out string? sessionKey))
            {
                throw new Exception();
            }

            Assert.AreEqual(sessionKey, finishClientLoginResult.SessionKey);
        }

        [TestMethod]
        public void MisMatchedConfigFailsLogin()
        {
            string userIdentifier = "user123";
            string password = "hunter42";

            SetupAndRegister(userIdentifier, password, null, null, null, out string serverSetup, out string registrationRecord,
                out string exportKey, out string serverStaticPublicKey);

            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();

            if (!client.StartLogin(password, out StartClientLoginResult? clientLoginResult))
            {
                throw new Exception();
            }

            if (!server.StartLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartServerLoginResult? serverLoginResult, out _))
            {
                throw new Exception();
            }

            KSFConfig config = KSFConfig.Create(KSFConfigType.RfcDraftRecommended);

            bool finishLoginSucceeded = client.FinishLogin(clientLoginResult.ClientLoginState, serverLoginResult!.LoginResponse, password,
                null, null, config, out FinishClientLoginResult? finishClientLoginResult);

            Assert.AreEqual(false, finishLoginSucceeded);
        }

        [TestMethod]
        public void IncorrectPasswordFailsLogin()
        {
            string userIdentifier = "user123";
            string rightPassword = "hunter42";
            string wrongPassword = "hunter43";

            SetupAndRegister(userIdentifier, rightPassword, null, null, null, out string serverSetup,
                out string registrationRecord, out string exportKey, out string serverStaticPublicKey);

            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();

            if (!client.StartLogin(rightPassword, out StartClientLoginResult? clientLoginResult))
            {
                throw new Exception();
            }

            if (!server.StartLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartServerLoginResult? serverLoginResult, out _))
            {
                throw new Exception();
            }

            client.FinishLogin(clientLoginResult.ClientLoginState, serverLoginResult!.LoginResponse, wrongPassword, null,
                null, null, out FinishClientLoginResult? finishClientLoginResult);

            Assert.IsNull(finishClientLoginResult);
        }

        [TestMethod]
        public void IncorrectClientIdentifierFails()
        {
            string userIdentifier = "user123";
            string password = "hunter2";
            string clientIdentifier = "client123";

            SetupAndRegister(userIdentifier, password, clientIdentifier, null, null, out string serverSetup, out string registrationRecord,
                out string exportKey, out string serverStaticPublicKey);

            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();

            if (!client.StartLogin(password, out StartClientLoginResult? startClientLoginResult))
            {
                throw new Exception();
            }

            if (!server.StartLogin(serverSetup, startClientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                clientIdentifier, null, out StartServerLoginResult? startServerLoginResult, out _))
            {
                throw new Exception();
            }

            client.FinishLogin(startClientLoginResult.ClientLoginState, startServerLoginResult!.LoginResponse, password, clientIdentifier + "abc",
                null, null, out FinishClientLoginResult? finishClientLoginResult);

            Assert.IsNull(finishClientLoginResult);
        }

        [TestMethod]
        public void IncorrectServerIdentifierFails()
        {
            string userIdentifier = "user123";
            string password = "hunter2";
            string serverIdentifier = "server-ident";

            SetupAndRegister(userIdentifier, password, null, serverIdentifier, null, out string serverSetup, out string registrationRecord,
                out string exportKey, out string serverStaticPublicKey);

            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();

            if (!client.StartLogin(password, out StartClientLoginResult? startClientLoginResult))
            {
                throw new Exception();
            }

            if (!server.StartLogin(serverSetup, startClientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord, null,
                serverIdentifier + "-abc", out StartServerLoginResult? startServerLoginResult, out _))
            {
                throw new Exception();
            }

            client.FinishLogin(startClientLoginResult.ClientLoginState, startServerLoginResult!.LoginResponse, password, null, serverIdentifier, null, out FinishClientLoginResult? result);
            Assert.IsNull(result);
        }

        [TestMethod]
        public void ClientMethodsThrowsOnInvalidParams()
        {
            OpaqueClient client = new OpaqueClient();

            Assert.ThrowsException<StringParamIsEmptyException>(() => client.StartRegistration("", out _));

            Assert.ThrowsException<StringParamIsEmptyException>(() => client.FinishRegistration("", "Value", "Value", null, null, null, out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => client.FinishRegistration("Value", "", "Value", null, null, null, out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => client.FinishRegistration("Value", "Value", "", null, null, null, out _));

            Assert.ThrowsException<StringParamIsEmptyException>(() => client.StartLogin("", out _));

            Assert.ThrowsException<StringParamIsEmptyException>(() => client.FinishLogin("", "Value", "Value", null, null, null, out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => client.FinishLogin("Value", "", "Value", null, null, null, out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => client.FinishLogin("Value", "Value", "", null, null, null, out _));
        }

        [TestMethod]
        public void CustomKsfRejectsUnsafeParametersBeforeNativeInvocation()
        {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                KSFConfig.Create(KSFConfigType.Custom, -1, 65536, 4));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                KSFConfig.Create(KSFConfigType.Custom, 1, 65535, 4));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                KSFConfig.Create(KSFConfigType.Custom, 1, 1048577, 4));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                KSFConfig.Create(KSFConfigType.Custom, 1, 65536, 17));
        }

        [TestMethod]
        public void ServerMethodsThrowsOnInvalidParams()
        {
            OpaqueServer server = new OpaqueServer();

            Assert.ThrowsException<StringParamIsEmptyException>(() => server.GetPublicKey("", out _));

            Assert.ThrowsException<StringParamIsEmptyException>(() => server.CreateRegistrationResponse("", "Value", "Value", out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => server.CreateRegistrationResponse("Value", "", "Value", out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => server.CreateRegistrationResponse("Value", "Value", "", out _));

            Assert.ThrowsException<StringParamIsEmptyException>(() => server.StartLogin("", "Value", "Value", null, null, null, out _, out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => server.StartLogin("Value", "", "Value", null, null, null, out _, out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => server.StartLogin("Value", "Value", "", null, null, null, out _, out _));

            Assert.ThrowsException<StringParamIsEmptyException>(() => server.FinishLogin("", "Value", out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => server.FinishLogin("Value", "", out _));
        }

        // ---- adversarial and failure-mode coverage ----

        private const string User = "adversarial-user";
        private const string Password = "correct horse battery staple";

        private static string Flip(string base64Url)
        {
            // Flip one bit in the middle of the decoded payload; stays valid base64url.
            string padded = base64Url.Replace('-', '+').Replace('_', '/');
            padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
            byte[] bytes = Convert.FromBase64String(padded);
            bytes[bytes.Length / 2] ^= 0x01;
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static void Login(string serverSetup, string record, out StartServerLoginResult server, out FinishClientLoginResult client)
        {
            var c = new OpaqueClient();
            var s = new OpaqueServer();
            Assert.IsTrue(c.StartLogin(Password, out StartClientLoginResult? start));
            Assert.IsTrue(s.StartLogin(serverSetup, start!.StartLoginRequest, User, record, out StartServerLoginResult? serverResult, out _));
            Assert.IsTrue(c.FinishLogin(start.ClientLoginState, serverResult!.LoginResponse, Password, out FinishClientLoginResult? clientResult));
            server = serverResult;
            client = clientResult!;
        }

        [TestMethod]
        public void DeploymentFaultsAreNotSwallowedButProtocolFaultsAre()
        {
            Assert.ThrowsException<DllNotFoundException>(() => FunctionHelper.TryExecute<string>(() => throw new DllNotFoundException()));
            Assert.ThrowsException<EntryPointNotFoundException>(() => FunctionHelper.TryExecute<string>(() => throw new EntryPointNotFoundException(), out _));
            Assert.ThrowsException<BadImageFormatException>(() => FunctionHelper.TryExecute<string>(() => throw new BadImageFormatException()));

            Assert.IsNull(FunctionHelper.TryExecute<string>(() => throw new InvalidOperationException()));
            Assert.IsNull(FunctionHelper.TryExecute<string>(() => throw new InvalidOperationException(), out Exception? e));
            Assert.IsInstanceOfType(e, typeof(InvalidOperationException));
        }

        [TestMethod]
        public void TamperedFinalizationIsRejectedByServer()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            Login(setup, record, out StartServerLoginResult server, out FinishClientLoginResult client);

            Assert.IsFalse(new OpaqueServer().FinishLogin(server.ServerLoginState, Flip(client.FinishLoginRequest), out string? key));
            Assert.IsTrue(string.IsNullOrEmpty(key));
        }

        [TestMethod]
        public void FinalizationFromAnotherSessionIsRejected()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            Login(setup, record, out StartServerLoginResult serverA, out _);
            Login(setup, record, out _, out FinishClientLoginResult clientB);

            Assert.IsFalse(new OpaqueServer().FinishLogin(serverA.ServerLoginState, clientB.FinishLoginRequest, out _));
        }

        [TestMethod]
        public void TamperedServerResponseYieldsNoKeysOnClient()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            var c = new OpaqueClient();
            Assert.IsTrue(c.StartLogin(Password, out StartClientLoginResult? start));
            Assert.IsTrue(new OpaqueServer().StartLogin(setup, start!.StartLoginRequest, User, record, out StartServerLoginResult? server, out _));

            Assert.IsFalse(c.FinishLogin(start.ClientLoginState, Flip(server!.LoginResponse), Password, out FinishClientLoginResult? result));
            Assert.IsNull(result);
        }

        [TestMethod]
        public void UnknownUserGetsAResponseButCannotAuthenticate()
        {
            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();
            Assert.IsTrue(server.CreateSetup(out string? setup));
            Assert.IsTrue(client.StartLogin(Password, out StartClientLoginResult? start));

            // No registration record: the server must still answer (no user enumeration here).
            Assert.IsTrue(server.StartLogin(setup!, start!.StartLoginRequest, "nobody", null, out StartServerLoginResult? response, out _));
            Assert.IsFalse(client.FinishLogin(start.ClientLoginState, response!.LoginResponse, Password, out FinishClientLoginResult? result));
            Assert.IsNull(result);
        }

        [TestMethod]
        public void EachLoginProducesAFreshSessionKey()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            Login(setup, record, out _, out FinishClientLoginResult first);
            Login(setup, record, out _, out FinishClientLoginResult second);

            Assert.AreNotEqual(first.SessionKey, second.SessionKey);
            Assert.AreEqual(first.ExportKey, second.ExportKey);
        }

        [TestMethod]
        public void GarbageProtocolInputReturnsFalseInsteadOfThrowingOrCrashing()
        {
            OpaqueServer server = new OpaqueServer();
            OpaqueClient client = new OpaqueClient();
            Assert.IsTrue(server.CreateSetup(out string? setup));

            foreach (string garbage in new[] { "x", "!!!", "AAAA", new string('A', 200), "////" })
            {
                Assert.IsFalse(server.GetPublicKey(garbage, out _));
                Assert.IsFalse(server.CreateRegistrationResponse(garbage, User, garbage, out _));
                Assert.IsFalse(server.CreateRegistrationResponse(setup!, User, garbage, out _));
                Assert.IsFalse(server.StartLogin(setup!, garbage, User, null, out _, out _));
                Assert.IsFalse(server.FinishLogin(garbage, garbage, out _));
                Assert.IsFalse(client.FinishRegistration(Password, garbage, garbage, out _));
                Assert.IsFalse(client.FinishLogin(garbage, garbage, Password, out _));
            }
        }

        [TestMethod]
        public void OversizedInputsAreRejectedBeforeNativeInvocation()
        {
            OpaqueServer server = new OpaqueServer();
            string huge = new string('A', StringParamIsEmptyException.MaximumProtocolMessageLength + 1);
            string longId = new string('u', StringParamIsEmptyException.MaximumIdentifierLength + 1);

            Assert.ThrowsException<ArgumentOutOfRangeException>(() => server.GetPublicKey(huge, out _));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => server.CreateRegistrationResponse("a", longId, "a", out _));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => server.StartLogin("a", "a", "u", null, longId, null, out _, out _));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new OpaqueClient().StartRegistration(new string('p', StringParamIsEmptyException.MaximumPasswordLength + 1), out _));
        }
    }
}
