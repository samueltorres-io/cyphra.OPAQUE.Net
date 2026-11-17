namespace OPAQUE.Net.Types.Results
{
    public class FinishClientRegistrationResult
    {
        public string RegistrationRecord { get; private set; }
        public string ExportKey { get; private set; }
        public string ServerStaticPublicKey { get; private set; }

        public FinishClientRegistrationResult(string registrationRecord, string exportKey, string serverStaticPublicKey)
        {
            RegistrationRecord = registrationRecord;
            ExportKey = exportKey;
            ServerStaticPublicKey = serverStaticPublicKey;
        }

        // Redacted: the properties hold secrets or flow state that must not end up in logs.
        public override string ToString() => nameof(FinishClientRegistrationResult);
    }
}
