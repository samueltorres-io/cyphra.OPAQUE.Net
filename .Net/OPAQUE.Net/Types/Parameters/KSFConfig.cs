namespace OPAQUE.Net.Types.Parameters
{
    public class KSFConfig
    {
        public const int MinimumMemoryKiB = 64 * 1024;
        public const int MaximumCustomMemoryKiB = 256 * 1024;
        public const int MinimumIterations = 1;
        public const int MaximumIterations = 10;
        public const int MinimumParallelism = 1;
        public const int MaximumParallelism = 16;
        public KSFConfigType Type { get; private set; } = KSFConfigType.MemoryConstrained;

        /// <summary>Argon2id iterations; set only for <see cref="KSFConfigType.Custom"/>.</summary>
        public int? Iterations { get; private set; }
        /// <summary>Argon2id memory in KiB; set only for <see cref="KSFConfigType.Custom"/>.</summary>
        public int? Memory { get; private set; }
        /// <summary>Argon2id lanes; set only for <see cref="KSFConfigType.Custom"/>.</summary>
        public int? Parallelism { get; private set; }

        protected KSFConfig() { }

        /// <summary>
        /// Creates the RFC draft profile. It can allocate about 2 GiB per operation; callers must
        /// opt in explicitly so untrusted request configuration cannot silently select it.
        /// </summary>
        public static KSFConfig CreateRfcDraftRecommended(bool allowHighMemoryProfile)
        {
            if (!allowHighMemoryProfile)
            {
                throw new InvalidOperationException("The RFC draft KSF profile requires an explicit high-memory opt-in.");
            }

            return new KSFConfig { Type = KSFConfigType.RfcDraftRecommended };
        }

        public static KSFConfig Create(KSFConfigType type, int? iterations = null, int? memory = null, int? parallelism = null)
        {
            if (type == KSFConfigType.RfcDraftRecommended)
            {
                throw new InvalidOperationException("The RFC draft KSF profile requires an explicit high-memory opt-in: use CreateRfcDraftRecommended(true).");
            }

            if (!Enum.IsDefined(type))
            {
                throw new ArgumentOutOfRangeException(nameof(type));
            }

            if (type == KSFConfigType.Custom)
            {
                if (iterations == null || memory == null || parallelism == null)
                {
                    throw new ArgumentException("Custom KSF configuration requires iterations, memory, and parallelism.");
                }

                ArgumentOutOfRangeException.ThrowIfLessThan(iterations.Value, MinimumIterations, nameof(iterations));
                ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations.Value, MaximumIterations, nameof(iterations));
                ArgumentOutOfRangeException.ThrowIfLessThan(memory.Value, MinimumMemoryKiB, nameof(memory));
                ArgumentOutOfRangeException.ThrowIfGreaterThan(memory.Value, MaximumCustomMemoryKiB, nameof(memory));
                ArgumentOutOfRangeException.ThrowIfLessThan(parallelism.Value, MinimumParallelism, nameof(parallelism));
                ArgumentOutOfRangeException.ThrowIfGreaterThan(parallelism.Value, MaximumParallelism, nameof(parallelism));

                return new KSFConfig()
                {
                    Type = type,
                    Iterations = iterations,
                    Memory = memory,
                    Parallelism = parallelism
                };
            }

            return new KSFConfig()
            {
                Type = type
            };
        }
    }

    // The numeric values cross the native boundary: do not reorder.
    public enum KSFConfigType
    {
        RfcDraftRecommended = 0,
        MemoryConstrained = 1,
        Custom = 2
    }
}
