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
    }
}
