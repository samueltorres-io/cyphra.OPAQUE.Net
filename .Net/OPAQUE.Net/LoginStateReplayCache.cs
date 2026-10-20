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
        private static readonly long RetentionMs = (long)TimeSpan.FromMinutes(5).TotalMilliseconds;
        private readonly ConcurrentDictionary<string, long> _seen = new();
        private long _nextPrune;

        /// <summary>True the first time an id is seen within the retention window, false afterwards.</summary>
        public bool TryConsume(string id)
        {
            ArgumentException.ThrowIfNullOrEmpty(id);
            long now = Environment.TickCount64; // monotonic: immune to wall-clock changes
            Prune(now);
            return _seen.TryAdd(id, now);
        }

        // Sweeping once per retention/5 keeps TryConsume O(1) amortized instead of scanning every call.
        private void Prune(long now)
        {
            long next = Interlocked.Read(ref _nextPrune);
            if (now < next || Interlocked.CompareExchange(ref _nextPrune, now + RetentionMs / 5, next) != next)
            {
                return;
            }

            foreach (var kv in _seen)
            {
                if (now - kv.Value > RetentionMs)
                {
                    _seen.TryRemove(kv);
                }
            }
        }
    }
}
