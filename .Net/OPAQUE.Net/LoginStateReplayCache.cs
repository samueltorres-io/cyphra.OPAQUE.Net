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
        private readonly TimeProvider _time;
        private long _nextPrune;

        public LoginStateReplayCache() : this(TimeProvider.System) { }

        // Lets tests drive the retention window without waiting for it.
        internal LoginStateReplayCache(TimeProvider time) => _time = time;

        /// <summary>True the first time an id is seen within the retention window, false afterwards.</summary>
        public bool TryConsume(string id)
        {
            ArgumentException.ThrowIfNullOrEmpty(id);
            // Wall clock on purpose: the state's expiry is enforced against the wall clock in the native
            // library, so retention has to follow the same clock (a backward step then keeps ids longer
            // instead of dropping them while the state is still valid).
            long now = _time.GetUtcNow().ToUnixTimeMilliseconds();
            Prune(now);
            return _seen.TryAdd(id, now);
        }

        // Sweeping once per retention/5 keeps TryConsume O(1) amortized instead of scanning every call.
        private void Prune(long now)
        {
            long next = Interlocked.Read(ref _nextPrune);
            long interval = RetentionMs / 5;
            // next - now > interval only after a backward clock step: sweep right away and reschedule.
            if ((now < next && next - now <= interval) || Interlocked.CompareExchange(ref _nextPrune, now + interval, next) != next)
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
