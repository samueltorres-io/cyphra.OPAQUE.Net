namespace OPAQUE.Net.Types.Results
{
    public class FinishClientRegistrationResult
    {
        public string RegistrationRecord { get; private set; }
        public string ExportKey { get; private set; }
        public string ServerStaticPublicKey { get; private set; }

        [Obsolete("Use ServerStaticPublicKey. This misspelled member is retained for source compatibility.")]
        public string ServerStaicPublicKey => ServerStaticPublicKey;

        public FinishClientRegistrationResult(string registrationRecord, string exportKey, string serverStaicPublicKey)
        {
            RegistrationRecord = registrationRecord;
            ExportKey = exportKey;
            ServerStaticPublicKey = serverStaicPublicKey;
        }

        // Redacted: the properties hold secrets or flow state that must not end up in logs.
        public override string ToString() => nameof(FinishClientRegistrationResult);
    }
}
