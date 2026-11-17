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

            if (!server.StartSealedLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartSealedServerLoginResult? serverLoginResult, out _))
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

            if (!server.FinishSealedLogin(serverSetup, userIdentifier, serverLoginResult.SealedLoginState, finishClientLoginResult.FinishLoginRequest, _ => true, out string? sessionKey))
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

            if (!server.StartSealedLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartSealedServerLoginResult? serverLoginResult, out _))
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

            if (!server.FinishSealedLogin(serverSetup, userIdentifier, serverLoginResult.SealedLoginState, finishClientLoginResult.FinishLoginRequest, _ => true, out string? sessionKey))
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

            if (!server.StartSealedLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartSealedServerLoginResult? serverLoginResult, out _))
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

            if (!server.FinishSealedLogin(serverSetup, userIdentifier, serverLoginResult.SealedLoginState, finishClientLoginResult.FinishLoginRequest, _ => true, out string? sessionKey))
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

            if (!server.StartSealedLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartSealedServerLoginResult? serverLoginResult, out _))
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

            if (!server.StartSealedLogin(serverSetup, clientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                null, null, out StartSealedServerLoginResult? serverLoginResult, out _))
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

            if (!server.StartSealedLogin(serverSetup, startClientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord,
                clientIdentifier, null, out StartSealedServerLoginResult? startServerLoginResult, out _))
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

            if (!server.StartSealedLogin(serverSetup, startClientLoginResult!.StartLoginRequest, userIdentifier, registrationRecord, null,
                serverIdentifier + "-abc", out StartSealedServerLoginResult? startServerLoginResult, out _))
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

            Assert.ThrowsExactly<StringParamIsEmptyException>(() => client.StartRegistration("", out _));

            Assert.ThrowsExactly<StringParamIsEmptyException>(() => client.FinishRegistration("", "Value", "Value", null, null, null, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => client.FinishRegistration("Value", "", "Value", null, null, null, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => client.FinishRegistration("Value", "Value", "", null, null, null, out _));

            Assert.ThrowsExactly<StringParamIsEmptyException>(() => client.StartLogin("", out _));

            Assert.ThrowsExactly<StringParamIsEmptyException>(() => client.FinishLogin("", "Value", "Value", null, null, null, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => client.FinishLogin("Value", "", "Value", null, null, null, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => client.FinishLogin("Value", "Value", "", null, null, null, out _));
        }

        [TestMethod]
        public void CustomKsfRejectsUnsafeParametersBeforeNativeInvocation()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                KSFConfig.Create(KSFConfigType.Custom, -1, 65536, 4));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                KSFConfig.Create(KSFConfigType.Custom, 1, 65535, 4));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                KSFConfig.Create(KSFConfigType.Custom, 1, 1048577, 4));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                KSFConfig.Create(KSFConfigType.Custom, 1, 65536, 17));
        }

        [TestMethod]
        public void ServerMethodsThrowsOnInvalidParams()
        {
            OpaqueServer server = new OpaqueServer();

            Assert.ThrowsExactly<StringParamIsEmptyException>(() => server.GetPublicKey("", out _));

            Assert.ThrowsExactly<StringParamIsEmptyException>(() => server.CreateRegistrationResponse("", "Value", "Value", out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => server.CreateRegistrationResponse("Value", "", "Value", out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => server.CreateRegistrationResponse("Value", "Value", "", out _));

            Assert.ThrowsExactly<StringParamIsEmptyException>(() => server.StartSealedLogin("", "Value", "Value", null, null, null, out _, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => server.StartSealedLogin("Value", "", "Value", null, null, null, out _, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => server.StartSealedLogin("Value", "Value", "", null, null, null, out _, out _));

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

        [TestMethod]
        public void DeploymentFaultsAreNotSwallowedButProtocolFaultsAre()
        {
            Assert.ThrowsExactly<DllNotFoundException>(() => FunctionHelper.TryExecute<string>(() => throw new DllNotFoundException()));
            Assert.ThrowsExactly<EntryPointNotFoundException>(() => FunctionHelper.TryExecute<string>(() => throw new EntryPointNotFoundException(), out _));
            Assert.ThrowsExactly<BadImageFormatException>(() => FunctionHelper.TryExecute<string>(() => throw new BadImageFormatException()));
            Assert.ThrowsExactly<OutOfMemoryException>(() => FunctionHelper.TryExecute<string>(() => throw new OutOfMemoryException(), out _));

            Assert.IsNull(FunctionHelper.TryExecute<string>(() => throw new InvalidOperationException()));
            Assert.IsNull(FunctionHelper.TryExecute<string>(() => throw new InvalidOperationException(), out Exception? e));
            Assert.IsInstanceOfType(e, typeof(InvalidOperationException));
        }

        [TestMethod]
        public void TamperedServerResponseYieldsNoKeysOnClient()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            var c = new OpaqueClient();
            Assert.IsTrue(c.StartLogin(Password, out StartClientLoginResult? start));
            Assert.IsTrue(new OpaqueServer().StartSealedLogin(setup, start!.StartLoginRequest, User, record, out StartSealedServerLoginResult? server, out _));

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
            Assert.IsTrue(server.StartSealedLogin(setup!, start!.StartLoginRequest, "nobody", null, out StartSealedServerLoginResult? response, out _));
            Assert.IsFalse(client.FinishLogin(start.ClientLoginState, response!.LoginResponse, Password, out FinishClientLoginResult? result));
            Assert.IsNull(result);
        }

        [TestMethod]
        public void EachLoginProducesAFreshSessionKey()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out _, out FinishClientLoginResult first);
            SealedLogin(setup, record, out _, out FinishClientLoginResult second);

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
                Assert.IsFalse(server.StartSealedLogin(setup!, garbage, User, null, out _, out _));
                Assert.IsFalse(server.FinishSealedLogin(setup!, User, garbage, garbage, _ => true, out _));
                Assert.IsFalse(client.FinishRegistration(Password, garbage, garbage, out _));
                Assert.IsFalse(client.FinishLogin(garbage, garbage, Password, out _));
            }
        }

        [TestMethod]
        public void OversizedInputsAreRejectedBeforeNativeInvocation()
        {
            OpaqueServer server = new OpaqueServer();
            string huge = new string('A', ParamGuard.MaximumProtocolMessageLength + 1);
            string longId = new string('u', ParamGuard.MaximumIdentifierLength + 1);

            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => server.GetPublicKey(huge, out _));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => server.CreateRegistrationResponse("a", longId, "a", out _));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => server.StartSealedLogin("a", "a", "u", null, longId, null, out _, out _));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new OpaqueClient().StartRegistration(new string('p', ParamGuard.MaximumPasswordLength + 1), out _));
        }
  
        [TestMethod]
        public void NulAndUnpairedSurrogatesAreRejected()
        {
            var client = new OpaqueClient();
            var server = new OpaqueServer();
            foreach (string bad in new[] { "abc\0TAIL", "\0", "pw\uD800", "\uDC00pw" })
            {
                Assert.ThrowsExactly<ArgumentException>(() => client.StartRegistration(bad, out _));
                Assert.ThrowsExactly<ArgumentException>(() => client.StartLogin(bad, out _));
                Assert.ThrowsExactly<ArgumentException>(() => server.CreateRegistrationResponse("a", bad, "a", out _));
                Assert.ThrowsExactly<ArgumentException>(() => server.StartSealedLogin("a", "a", "u", null, bad, null, out _, out _));
            }
        }

        [TestMethod]
        public void LengthLimitIsMeasuredInUtf8Bytes()
        {
            var client = new OpaqueClient();
            // 342 CJK chars = 1026 bytes: used to return a silent false.
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => client.StartRegistration(new string('\u4e2d', 342), out _));
            Assert.IsTrue(client.StartRegistration(new string('\u4e2d', 341), out _));
        }

        [TestMethod]
        public void ValidBoundaryInputsStillAccepted()
        {
            var client = new OpaqueClient();
            Assert.IsTrue(client.StartRegistration(new string('p', 1024), out _));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => client.StartRegistration(new string('p', 1025), out _));
            // Valid surrogate pairs (4 bytes each) and NFD text are legitimate; 256 emoji = 1024 bytes.
            Assert.IsTrue(client.StartRegistration(string.Concat(Enumerable.Repeat("\U0001F600", 256)), out _));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => client.StartRegistration(string.Concat(Enumerable.Repeat("\U0001F600", 257)), out _));
            Assert.IsTrue(client.StartRegistration("cafe\u0301", out _));
        }

        [TestMethod]
        public void RfcDraftProfileRequiresOptInAndInvalidEnumIsRejected()
        {
            Assert.ThrowsExactly<InvalidOperationException>(() => KSFConfig.Create(KSFConfigType.RfcDraftRecommended));
            Assert.ThrowsExactly<InvalidOperationException>(() => KSFConfig.CreateRfcDraftRecommended(false));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KSFConfig.Create((KSFConfigType)99));
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
        public void SealedLoginStateIsNotRevealedByToString()
        {
            var result = new StartSealedServerLoginResult("SECRET-STATE", "response");
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

            Assert.IsTrue(new OpaqueServer().FinishSealedLogin(setup, User, server.SealedLoginState, client.FinishLoginRequest, _ => true, out string? key));
            Assert.AreEqual(client.SessionKey, key);

            byte[] blob = FromBase64Url(server.SealedLoginState);
            byte[] sessionKey = FromBase64Url(client.SessionKey);
            Assert.IsFalse(blob.AsSpan().IndexOf(sessionKey.AsSpan(0, 16)) >= 0, "session key must not appear in the sealed state");
        }

        [TestMethod]
        public void SealedStateRejectsTamperingAndForeignSetup()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            var s = new OpaqueServer();

            Assert.IsFalse(s.FinishSealedLogin(setup, User, Flip(server.SealedLoginState), client.FinishLoginRequest, _ => true, out _));
            Assert.IsTrue(s.CreateSetup(out string? otherSetup));
            Assert.IsFalse(s.FinishSealedLogin(otherSetup!, User, server.SealedLoginState, client.FinishLoginRequest, _ => true, out _));
        }

        [TestMethod]
        public void SealedStateCanBeConsumedOnlyOnce()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            var s = new OpaqueServer();
            var cache = new LoginStateReplayCache();

            Assert.IsTrue(s.FinishSealedLogin(setup, User, server.SealedLoginState, client.FinishLoginRequest, cache.TryConsume, out string? key));
            Assert.IsNotNull(key);
            Assert.IsFalse(s.FinishSealedLogin(setup, User, server.SealedLoginState, client.FinishLoginRequest, cache.TryConsume, out string? replayKey));
            Assert.IsNull(replayKey);
        }

        [TestMethod]
        public void ReencodedSealedStateIsNotAReplayBypass()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);

            Assert.IsFalse(new OpaqueServer().FinishSealedLogin(setup, User, server.SealedLoginState + "=", client.FinishLoginRequest, _ => true, out _));
        }

        [TestMethod]
        public void ThrowingConsumerNeverReleasesTheKey()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            string? key = "x";

            Assert.ThrowsExactly<InvalidOperationException>(() =>
                new OpaqueServer().FinishSealedLogin(setup, User, server.SealedLoginState, client.FinishLoginRequest, _ => throw new InvalidOperationException(), out key));
            Assert.IsNull(key);
        }

        [TestMethod]
        public void BadFinishDoesNotBurnTheState()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            var s = new OpaqueServer();
            var cache = new LoginStateReplayCache();

            Assert.IsFalse(s.FinishSealedLogin(setup, User, server.SealedLoginState, Flip(client.FinishLoginRequest), cache.TryConsume, out _));
            Assert.IsTrue(s.FinishSealedLogin(setup, User, server.SealedLoginState, client.FinishLoginRequest, cache.TryConsume, out _));
        }

        [TestMethod]
        public void SealedStateIsBoundToItsUserIdentifier()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult server, out FinishClientLoginResult client);
            var s = new OpaqueServer();

            // A valid state and finish message of User must not complete a login claimed for another account.
            Assert.IsFalse(s.FinishSealedLogin(setup, "victim", server.SealedLoginState, client.FinishLoginRequest, _ => true, out string? key));
            Assert.IsNull(key);
            Assert.IsTrue(s.FinishSealedLogin(setup, User, server.SealedLoginState, client.FinishLoginRequest, _ => true, out key));
            Assert.AreEqual(client.SessionKey, key);
        }

        [TestMethod]
        public void SealedStateFromAnotherSessionIsRejected()
        {
            SetupAndRegister(User, Password, null, null, null, out string setup, out string record, out _, out _);
            SealedLogin(setup, record, out StartSealedServerLoginResult serverA, out _);
            SealedLogin(setup, record, out _, out FinishClientLoginResult clientB);

            Assert.IsFalse(new OpaqueServer().FinishSealedLogin(setup, User, serverA.SealedLoginState, clientB.FinishLoginRequest, _ => true, out _));
        }

        [TestMethod]
        public void SealedLoginValidatesArguments()
        {
            var s = new OpaqueServer();
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => s.FinishSealedLogin("", User, "a", "a", _ => true, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => s.FinishSealedLogin("a", User, "", "a", _ => true, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => s.FinishSealedLogin("a", User, "a", "", _ => true, out _));
            Assert.ThrowsExactly<StringParamIsEmptyException>(() => s.FinishSealedLogin("a", "", "a", "a", _ => true, out _));
            Assert.ThrowsExactly<ArgumentException>(() => s.StartSealedLogin("a", "a", "u\0x", null, out _, out _));
            Assert.IsFalse(s.FinishSealedLogin("a", User, "a", "a", _ => true, out _));
        }

        [TestMethod]
        public void SealedLoginBindsClientAndServerIdentifiers()
        {
            const string clientId = "client-1", serverId = "server-1";
            SetupAndRegister(User, Password, clientId, serverId, null, out string setup, out string record, out _, out _);
            var c = new OpaqueClient();
            var s = new OpaqueServer();

            // Matching identifiers: both sides agree.
            Assert.IsTrue(c.StartLogin(Password, out StartClientLoginResult? start));
            Assert.IsTrue(s.StartSealedLogin(setup, start!.StartLoginRequest, User, record, clientId, serverId, out StartSealedServerLoginResult? ok, out _));
            Assert.IsTrue(c.FinishLogin(start.ClientLoginState, ok!.LoginResponse, Password, clientId, serverId, null, out FinishClientLoginResult? finished));
            Assert.IsTrue(s.FinishSealedLogin(setup, User, ok.SealedLoginState, finished!.FinishLoginRequest, _ => true, out string? key));
            Assert.AreEqual(finished.SessionKey, key);

            // The server answering under another identity must not yield keys on the client.
            Assert.IsTrue(c.StartLogin(Password, out StartClientLoginResult? start2));
            Assert.IsTrue(s.StartSealedLogin(setup, start2!.StartLoginRequest, User, record, clientId, "server-2", out StartSealedServerLoginResult? bad, out _));
            Assert.IsFalse(c.FinishLogin(start2.ClientLoginState, bad!.LoginResponse, Password, clientId, serverId, null, out FinishClientLoginResult? none));
            Assert.IsNull(none);
        }

        [TestMethod]
        public void ReplayCacheAdmitsEachIdOnceEvenUnderContention()
        {
            var cache = new LoginStateReplayCache();
            Assert.ThrowsExactly<ArgumentException>(() => cache.TryConsume(""));
            Assert.ThrowsExactly<ArgumentNullException>(() => cache.TryConsume(null!));

            Assert.IsTrue(cache.TryConsume("a"));
            Assert.IsTrue(cache.TryConsume("b"));
            Assert.IsFalse(cache.TryConsume("a"));

            int winners = 0;
            Parallel.For(0, 256, new ParallelOptions { MaxDegreeOfParallelism = 32 }, _ =>
            {
                if (cache.TryConsume("contended"))
                {
                    Interlocked.Increment(ref winners);
                }
            });
            Assert.AreEqual(1, winners);
        }

        private sealed class ManualClock : TimeProvider
        {
            public DateTimeOffset Now = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
            public override DateTimeOffset GetUtcNow() => Now;
        }

        [TestMethod]
        public void ReplayCacheKeepsIdsForTheRetentionWindowThenForgetsThem()
        {
            var clock = new ManualClock();
            var cache = new LoginStateReplayCache(clock);

            Assert.IsTrue(cache.TryConsume("a"));
            clock.Now += TimeSpan.FromMinutes(4);
            Assert.IsFalse(cache.TryConsume("a"), "still inside the 5 minute retention, longer than a state's 120 s");
            clock.Now += TimeSpan.FromMinutes(3);
            Assert.IsTrue(cache.TryConsume("a"), "retention elapsed: the id is pruned and memory stays bounded");
            Assert.IsFalse(cache.TryConsume("a"));
        }

        [TestMethod]
        public void ReplayCacheKeepsIdsWhenTheWallClockStepsBackwards()
        {
            var clock = new ManualClock();
            var cache = new LoginStateReplayCache(clock);

            clock.Now += TimeSpan.FromHours(1);
            Assert.IsTrue(cache.TryConsume("a"));
            clock.Now -= TimeSpan.FromHours(1);
            Assert.IsFalse(cache.TryConsume("a"), "a backward step must not drop ids whose state may still be valid");
            Assert.IsTrue(cache.TryConsume("b"));
        }

        [TestMethod]
        public void KsfConfigAcceptsBoundsAndRejectsEverythingOutside()
        {
            KSFConfig min = KSFConfig.Create(KSFConfigType.Custom,
                KSFConfig.MinimumIterations, KSFConfig.MinimumMemoryKiB, KSFConfig.MinimumParallelism);
            Assert.AreEqual(KSFConfigType.Custom, min.Type);
            Assert.AreEqual(KSFConfig.MinimumMemoryKiB, min.Memory);
            Assert.AreEqual(KSFConfigType.Custom, KSFConfig.Create(KSFConfigType.Custom,
                KSFConfig.MaximumIterations, KSFConfig.MaximumCustomMemoryKiB, KSFConfig.MaximumParallelism).Type);
            KSFConfig named = KSFConfig.Create(KSFConfigType.MemoryConstrained);
            Assert.AreEqual(KSFConfigType.MemoryConstrained, named.Type);
            Assert.IsNull(named.Iterations);
            Assert.AreEqual(KSFConfigType.RfcDraftRecommended, KSFConfig.CreateRfcDraftRecommended(true).Type);
            // The native side maps these exact values.
            Assert.AreEqual(0, (int)KSFConfigType.RfcDraftRecommended);
            Assert.AreEqual(1, (int)KSFConfigType.MemoryConstrained);
            Assert.AreEqual(2, (int)KSFConfigType.Custom);

            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KSFConfig.Create(KSFConfigType.Custom, KSFConfig.MaximumIterations + 1, KSFConfig.MinimumMemoryKiB, 1));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KSFConfig.Create(KSFConfigType.Custom, 1, KSFConfig.MaximumCustomMemoryKiB + 1, 1));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KSFConfig.Create(KSFConfigType.Custom, KSFConfig.MinimumIterations - 1, KSFConfig.MinimumMemoryKiB, 1));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KSFConfig.Create(KSFConfigType.Custom, 1, KSFConfig.MinimumMemoryKiB - 1, 1));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KSFConfig.Create(KSFConfigType.Custom, 1, KSFConfig.MinimumMemoryKiB, KSFConfig.MinimumParallelism - 1));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KSFConfig.Create(KSFConfigType.Custom, 1, KSFConfig.MinimumMemoryKiB, KSFConfig.MaximumParallelism + 1));
            Assert.ThrowsExactly<ArgumentException>(() => KSFConfig.Create(KSFConfigType.Custom, 1, KSFConfig.MinimumMemoryKiB, null));
            Assert.ThrowsExactly<InvalidOperationException>(() => KSFConfig.CreateRfcDraftRecommended(false));
        }

        [TestMethod]
        public void ResolverLoadsFromHostDirectoriesAndIgnoresOtherLibraries()
        {
            Assert.AreEqual(IntPtr.Zero, NativeLibraryResolver.Resolve("something-else", typeof(OpaqueServer).Assembly, null));
            Assert.IsTrue(File.Exists(Path.Combine(AppContext.BaseDirectory, NativeLibraryResolver.FileName())));
        }

        [TestMethod]
        public void PInvokeFallbackProbingIsLimitedToTheAssemblyDirectory()
        {
            var attribute = typeof(OpaqueServer).Assembly
                .GetCustomAttributes(typeof(System.Runtime.InteropServices.DefaultDllImportSearchPathsAttribute), false)
                .Cast<System.Runtime.InteropServices.DefaultDllImportSearchPathsAttribute>()
                .SingleOrDefault();
            Assert.IsNotNull(attribute, "CA5392: the assembly must restrict the default P/Invoke search paths");
            Assert.AreEqual(System.Runtime.InteropServices.DllImportSearchPath.AssemblyDirectory, attribute.Paths);
        }

        [TestMethod]
        public void ResolverNeverFallsBackToTheOperatingSystemSearch()
        {
            string empty = Directory.CreateTempSubdirectory().FullName;
            string broken = Directory.CreateTempSubdirectory().FullName;
            try
            {
                File.WriteAllText(Path.Combine(broken, NativeLibraryResolver.FileName()), "not a library");

                var missing = Assert.ThrowsExactly<DllNotFoundException>(() => NativeLibraryResolver.Load(NativeLibraryResolver.FileName(), new[] { empty }));
                StringAssert.Contains(missing.Message, empty);
                StringAssert.Contains(missing.Message, System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier);

                var unloadable = Assert.ThrowsExactly<DllNotFoundException>(() => NativeLibraryResolver.Load(NativeLibraryResolver.FileName(), new[] { empty, broken }));
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
