using System.Collections.Concurrent;

namespace OPAQUE.Net
{
    /// <summary>
    /// In-memory single-use registry for <see cref="OpaqueServer.FinishSealedLogin(string, string, string, string, Func{string, bool}, out string?)"/>.
    /// Only correct for a single server instance; with several instances use shared storage instead.
    /// </summary>
    public sealed class LoginStateReplayCache
    {
        private static readonly long RetentionMs = (long)TimeSpan.FromMinutes(5).TotalMilliseconds;
        private readonly ConcurrentDictionary<string, long> _seen = new();
        private readonly TimeProvider _time;
        private long _nextPrune;

        public LoginStateReplayCache() : this(TimeProvider.System) { }

        internal LoginStateReplayCache(TimeProvider time) => _time = time;

        /// <summary>True the first time an id is seen within the retention window, false afterwards.</summary>
        public bool TryConsume(string id)
        {
            ArgumentException.ThrowIfNullOrEmpty(id);
            long now = _time.GetUtcNow().ToUnixTimeMilliseconds();
            Prune(now);
            return _seen.TryAdd(id, now);
        }

        private void Prune(long now)
        {
            long next = Interlocked.Read(ref _nextPrune);
            long interval = RetentionMs / 5;
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
