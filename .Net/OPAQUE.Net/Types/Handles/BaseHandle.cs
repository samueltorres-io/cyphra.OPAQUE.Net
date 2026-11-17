using System.Runtime.InteropServices;

namespace OPAQUE.Net.Types.Handles
{
    internal abstract class BaseHandle<T> : SafeHandle
    {
        public override bool IsInvalid => this.handle == IntPtr.Zero;

        protected BaseHandle() : base(IntPtr.Zero, true) { }

        public T? GetAndRelease()
        {
            try
            {
                // NULL is the native side's failure result: never pass it to the getters.
                return IsInvalid ? default : GetValue();
            }
            finally
            {
                Dispose();
            }
        }

        // SafeHandle never calls this for an invalid handle.
        protected override bool ReleaseHandle()
        {
            DoRelease();
            return true;
        }

        abstract protected void DoRelease();
        abstract protected T? GetValue();
    }
}
