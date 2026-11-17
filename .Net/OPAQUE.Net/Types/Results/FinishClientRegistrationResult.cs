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

        public override string ToString() => nameof(FinishClientRegistrationResult);
    }
}
