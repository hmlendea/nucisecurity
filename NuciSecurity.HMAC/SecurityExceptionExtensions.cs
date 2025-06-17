using System.Security;

namespace NuciSecurity.HMAC
{
    public static class SecurityExceptionExtensions
    {
        public static void ThrowIfInvalidHmac<TObject>(this SecurityException _, string expectedToken, TObject obj, string sharedSecretKey) where TObject : class
        {
            if (!HmacEncoder.IsTokenValid(expectedToken, obj, sharedSecretKey))
            {
                throw new SecurityException("The HMAC token is not valid.");
            }
        }
    }
}
