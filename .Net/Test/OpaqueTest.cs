// The legacy raw-state API is obsolete on purpose; these tests still cover it (and its replacement).
#pragma warning disable CS0618
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

            KSFConfig config = KSFConfig.CreateRfcDraftRecommended(true);

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

            KSFConfig config = KSFConfig.CreateRfcDraftRecommended(true);

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
  
        [TestMethod]
        public void NulAndUnpairedSurrogatesAreRejected()
        {
            var client = new OpaqueClient();
            var server = new OpaqueServer();
            foreach (string bad in new[] { "abc\0TAIL", "\0", "pw\uD800", "\uDC00pw" })
            {
                Assert.ThrowsException<ArgumentException>(() => client.StartRegistration(bad, out _));
                Assert.ThrowsException<ArgumentException>(() => client.StartLogin(bad, out _));
                Assert.ThrowsException<ArgumentException>(() => server.CreateRegistrationResponse("a", bad, "a", out _));
                Assert.ThrowsException<ArgumentException>(() => server.StartLogin("a", "a", "u", null, bad, null, out _, out _));
            }
        }

        [TestMethod]
        public void LengthLimitIsMeasuredInUtf8Bytes()
        {
            var client = new OpaqueClient();
            // 342 CJK chars = 1026 bytes: used to return a silent false.
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => client.StartRegistration(new string('\u4e2d', 342), out _));
            Assert.IsTrue(client.StartRegistration(new string('\u4e2d', 341), out _));
        }

        [TestMethod]
        public void ValidBoundaryInputsStillAccepted()
        {
            var client = new OpaqueClient();
            Assert.IsTrue(client.StartRegistration(new string('p', 1024), out _));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => client.StartRegistration(new string('p', 1025), out _));
            // Valid surrogate pairs (4 bytes each) and NFD text are legitimate; 256 emoji = 1024 bytes.
            Assert.IsTrue(client.StartRegistration(string.Concat(Enumerable.Repeat("\U0001F600", 256)), out _));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => client.StartRegistration(string.Concat(Enumerable.Repeat("\U0001F600", 257)), out _));
            Assert.IsTrue(client.StartRegistration("cafe\u0301", out _));
        }

        [TestMethod]
        public void RfcDraftProfileRequiresOptInAndInvalidEnumIsRejected()
        {
            Assert.ThrowsException<InvalidOperationException>(() => KSFConfig.Create(KSFConfigType.RfcDraftRecommended));
            Assert.ThrowsException<InvalidOperationException>(() => KSFConfig.CreateRfcDraftRecommended(false));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => KSFConfig.Create((KSFConfigType)99));
        }

        [TestMethod]
        public void RegistrationRequestWithTrailingBytesIsRejected()
        {
            var server = new OpaqueServer();
            Assert.IsTrue(server.CreateSetup(out string? setup));
            Assert.IsTrue(new OpaqueClient().StartRegistration(Password, out StartClientRegistrationResult? start));
            Assert.IsTrue(server.CreateRegistrationResponse(setup!, User, start!.RegistrationRequest, out _));
            Assert.IsFalse(server.CreateRegistrationResponse(setup!, User, start.RegistrationRequest + "AAAA", out _));
        }
  
        [TestMethod]
        public void ServerLoginStateIsNotRevealedByToString()
        {
            var result = new StartServerLoginResult("SECRET-STATE", "response");
            StringAssert.DoesNotMatch(result.ToString()!, new System.Text.RegularExpressions.Regex("SECRET-STATE"));
        }
  
        private static void SealedLogin(string setup, string record, out StartSealedServerLoginResult server, out FinishClientLoginResult client)
        {
            var c = new OpaqueClient();
            var s = new OpaqueServer();
            Assert.IsTrue(c.StartLogin(Password, out StartClientLoginResult? start));
            Assert.IsTrue(s.StartSealedLogin(setup, start!.StartLoginRequest, User, record, out StartSealedServerLoginResult? serverResult, out _));
            Assert.IsTrue(c.FinishLogin(start.ClientLoginState, serverResult!.LoginResponse, Password, out FinishClientLoginResult? clientResult));
            server = serverResult;
            client = clientResult!;
        }

        private static byte[] FromBase64Url(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
        }

        [TestMethod]
        public void SealedLoginAgreesOnSessionKeyAndHidesIt()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);

            Assert.IsTrue(new OpaqueServer().FinishSealedLogin(setup, server.SealedLoginState, client.FinishLoginRequest, out string? key));
            Assert.AreEqual(client.SessionKey, key);

            byte[] blob = FromBase64Url(server.SealedLoginState);
            byte[] sessionKey = FromBase64Url(client.SessionKey);
            Assert.IsFalse(blob.AsSpan().IndexOf(sessionKey.AsSpan(0, 16)) >= 0, "session key must not appear in the sealed state");
        }

        [TestMethod]
        public void SealedStateRejectsTamperingForeignSetupAndLegacyMixing()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            var s = new OpaqueServer();

            Assert.IsFalse(s.FinishSealedLogin(setup, Flip(server.SealedLoginState), client.FinishLoginRequest, out _));
            Assert.IsTrue(s.CreateSetup(out string? otherSetup));
            Assert.IsFalse(s.FinishSealedLogin(otherSetup!, server.SealedLoginState, client.FinishLoginRequest, out _));
            // A sealed state is not a raw state, and a raw state is not accepted as sealed.
            Assert.IsFalse(s.FinishLogin(server.SealedLoginState, client.FinishLoginRequest, out _));
            Assert.IsTrue(new OpaqueClient().StartLogin(Password, out StartClientLoginResult? start));
            Assert.IsTrue(s.StartLogin(setup, start!.StartLoginRequest, User, record, out StartServerLoginResult? legacy, out _));
            Assert.IsFalse(s.FinishSealedLogin(setup, legacy!.ServerLoginState, client.FinishLoginRequest, out _));
        }

        [TestMethod]
        public void SealedStateCanBeConsumedOnlyOnce()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            var s = new OpaqueServer();
            var cache = new LoginStateReplayCache();

            Assert.IsTrue(s.FinishSealedLogin(setup, server.SealedLoginState, client.FinishLoginRequest, cache.TryConsume, out string? key));
            Assert.IsNotNull(key);
            Assert.IsFalse(s.FinishSealedLogin(setup, server.SealedLoginState, client.FinishLoginRequest, cache.TryConsume, out string? replayKey));
            Assert.IsNull(replayKey);
        }

        [TestMethod]
        public void ReencodedSealedStateIsNotAReplayBypass()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);

            Assert.IsFalse(new OpaqueServer().FinishSealedLogin(setup, server.SealedLoginState + "=", client.FinishLoginRequest, _ => true, out _));
        }

        [TestMethod]
        public void ThrowingConsumerNeverReleasesTheKey()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            string? key = "x";

            Assert.ThrowsException<InvalidOperationException>(() =>
                new OpaqueServer().FinishSealedLogin(setup, server.SealedLoginState, client.FinishLoginRequest, _ => throw new InvalidOperationException(), out key));
            Assert.IsNull(key);
        }

        [TestMethod]
        public void BadFinishDoesNotBurnTheState()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            var s = new OpaqueServer();
            var cache = new LoginStateReplayCache();

            Assert.IsFalse(s.FinishSealedLogin(setup, server.SealedLoginState, Flip(client.FinishLoginRequest), cache.TryConsume, out _));
            Assert.IsTrue(s.FinishSealedLogin(setup, server.SealedLoginState, client.FinishLoginRequest, cache.TryConsume, out _));
        }

        [TestMethod]
        public void SealedStateFromAnotherSessionIsRejected()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult serverA, out _);
            SealedLogin(setup, record, out _, out FinishClientLoginResult clientB);

            Assert.IsFalse(new OpaqueServer().FinishSealedLogin(setup, serverA.SealedLoginState, clientB.FinishLoginRequest, out _));
        }

        [TestMethod]
        public void SealedLoginValidatesArguments()
        {
            var s = new OpaqueServer();
            Assert.ThrowsException<StringParamIsEmptyException>(() => s.FinishSealedLogin("", "a", "a", out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => s.FinishSealedLogin("a", "", "a", out _));
            Assert.ThrowsException<StringParamIsEmptyException>(() => s.FinishSealedLogin("a", "a", "", out _));
            Assert.ThrowsException<ArgumentException>(() => s.StartSealedLogin("a", "a", "u\0x", null, out _, out _));
            Assert.IsFalse(s.FinishSealedLogin("a", "a", "a", out _));
        }

        [TestMethod]
        public void ResolverLoadsFromHostDirectoriesAndIgnoresOtherLibraries()
        {
            Assert.AreEqual(IntPtr.Zero, NativeLibraryResolver.Resolve("something-else", typeof(OpaqueServer).Assembly, null));
            Assert.IsTrue(File.Exists(Path.Combine(AppContext.BaseDirectory, NativeLibraryResolver.FileName())));
        }

        [TestMethod]
        public void ResolverNeverFallsBackToTheOperatingSystemSearch()
        {
            string empty = Directory.CreateTempSubdirectory().FullName;
            string broken = Directory.CreateTempSubdirectory().FullName;
            try
            {
                File.WriteAllText(Path.Combine(broken, NativeLibraryResolver.FileName()), "not a library");

                var missing = Assert.ThrowsException<DllNotFoundException>(() => NativeLibraryResolver.Load(NativeLibraryResolver.FileName(), new[] { empty }));
                StringAssert.Contains(missing.Message, empty);
                StringAssert.Contains(missing.Message, System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier);

                var unloadable = Assert.ThrowsException<DllNotFoundException>(() => NativeLibraryResolver.Load(NativeLibraryResolver.FileName(), new[] { empty, broken }));
                StringAssert.Contains(unloadable.Message, "could not be loaded");
                StringAssert.Contains(unloadable.Message, broken);
            }
            finally
            {
                Directory.Delete(empty, true);
                Directory.Delete(broken, true);
            }
        }
    }
}
