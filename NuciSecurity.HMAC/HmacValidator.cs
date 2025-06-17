using System;
using System.Security;

namespace NuciSecurity.HMAC
{
    public static class HmacValidator
    {
        /// <summary>
        /// Validates if the provided token matches the generated token for the given object and shared secret key.
        /// </summary>
        /// <typeparam name="TObject">The type of the object to validate against.</typeparam>
        /// <param name="expectedToken">The expected HMAC token to validate.</param>
        /// <param name="obj">The object to validate against.</param>
        /// <param name="sharedSecretKey">The shared secret key used for HMAC generation.</param>
        /// <exception cref="SecurityException">Thrown if the token is not valid.</exception>
        public static void Validate<TObject>(string expectedToken, TObject obj, string sharedSecretKey) where TObject : class
        {
            if (!HmacEncoder.IsTokenValid(expectedToken, obj, sharedSecretKey))
            {
                throw new SecurityException("The HMAC token is not valid.");
            }
        }

        /// <summary>
        /// Validates if the provided token matches the generated token for the given object and shared secret key.
        /// </summary>
        /// <typeparam name="TObject">The type of the object to validate against.</typeparam>
        /// <param name="expectedToken">The expected HMAC token to validate.</param>
        /// <param name="obj">The object to validate against.</param>
        /// <param name="sharedSecretKey">The shared secret key used for HMAC generation.</param>
        /// <returns>True if the token is valid, otherwise false.</returns>
        /// <throws cref="ArgumentNullException">Thrown if the object or shared secret key is null.</throws>
        public static bool IsTokenValid<TObject>(string expectedToken, TObject obj, string sharedSecretKey) where TObject : class
        {
            if (string.IsNullOrWhiteSpace(expectedToken))
            {
                return false;
            }

            ArgumentNullException.ThrowIfNull(obj);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(sharedSecretKey);

            return HmacEncoder.GenerateToken(obj, sharedSecretKey).Equals(expectedToken);
        }
    }
}
