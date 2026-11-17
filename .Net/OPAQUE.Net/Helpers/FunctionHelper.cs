using System.Runtime.InteropServices;

namespace OPAQUE.Net.Helpers
{
    internal static class FunctionHelper
    {
        public static T? TryExecute<T>(Func<T?> action) => TryExecute(action, out _);

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
            exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException
                or OutOfMemoryException or InsufficientExecutionStackException or MarshalDirectiveException or SEHException;
    }
}
