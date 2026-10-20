using System.Collections.Concurrent;

namespace OPAQUE.Net
{
    /// <summary>
    /// In-memory single-use registry for <see cref="OpaqueServer.FinishSealedLogin(string, string, string, Func{string, bool}, out string?)"/>.
    /// Only correct for a single server instance; with several instances use shared storage instead.
    /// </summary>
    public sealed class LoginStateReplayCache
    {
        // Sealed states live 120 s; keep ids longer to cover clock skew.
        private static readonly TimeSpan Retention = TimeSpan.FromMinutes(5);
        private readonly ConcurrentDictionary<string, DateTime> _seen = new();

        /// <summary>True the first time an id is seen within the retention window, false afterwards.</summary>
        public bool TryConsume(string id)
        {
            DateTime now = DateTime.UtcNow;
            foreach (var old in _seen.Where(kv => now - kv.Value > Retention))
            {
                _seen.TryRemove(old.Key, out _);
            }

            return _seen.TryAdd(id, now);
        }
    }
}
