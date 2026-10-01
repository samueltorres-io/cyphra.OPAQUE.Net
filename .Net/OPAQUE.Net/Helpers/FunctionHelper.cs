namespace OPAQUE.Net.Helpers
{
    public static class FunctionHelper
    {
        public static T? TryExecute<T>(Func<T?> action)
        {
            try { return action.Invoke(); }
            catch (Exception) { return default; }
        }

        public static T? TryExecute<T>(Func<T?> action, out Exception? e)
        {
            try
            {
                e = null;
                return action.Invoke();
            }
            catch (Exception exception)
            {
                e = exception;
                return default;
            }
        }
    }
}
