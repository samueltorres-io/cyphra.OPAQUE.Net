namespace OPAQUE.Net.Helpers
{
    public static class FunctionHelper
    {
        /// <summary>
        /// Runs a native call and maps protocol-level failure to <c>default</c>.
        /// Deployment faults (native library missing, entry point missing, wrong architecture) are
        /// not protocol failures and are rethrown: swallowing them would make a broken install look
        /// like a wrong password.
        /// </summary>
        public static T? TryExecute<T>(Func<T?> action)
        {
            try { return action.Invoke(); }
            catch (Exception exception) when (!IsDeploymentFault(exception)) { return default; }
        }

        /// <inheritdoc cref="TryExecute{T}(Func{T})"/>
        public static T? TryExecute<T>(Func<T?> action, out Exception? e)
        {
            try
            {
                e = null;
                return action.Invoke();
            }
            catch (Exception exception) when (!IsDeploymentFault(exception))
            {
                e = exception;
                return default;
            }
        }

        private static bool IsDeploymentFault(Exception exception) =>
            exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException;
    }
}
