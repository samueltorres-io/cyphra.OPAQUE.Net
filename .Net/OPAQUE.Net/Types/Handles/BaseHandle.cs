using System.Runtime.InteropServices;

namespace OPAQUE.Net.Types.Handles
{
    abstract public class BaseHandle<T> : SafeHandle
    {
        public override bool IsInvalid => this.handle == IntPtr.Zero;

        protected BaseHandle() : base(IntPtr.Zero, true) { }

        public T? GetAndRelease()
        {
            try
            {
                return GetValue();
            }
            finally
            {
                Dispose();
            }
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                DoRelease();
            }

            return true;
        }

        abstract protected void DoRelease();
        abstract protected T? GetValue();
    }
}
