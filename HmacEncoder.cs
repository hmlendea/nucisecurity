using System;
using System.Security.Cryptography;
using System.Text;

namespace NuciSecurity.HMAC
{
    public abstract class HmacEncoder<T> : IHmacEncoder<T> where T : class
    {
        public abstract string GenerateToken(T obj, string sharedSecretKey);

        public bool IsTokenValid(string expectedToken, T obj, string sharedSecretKey)
        {
            if (string.IsNullOrWhiteSpace(expectedToken))
            {
                return false;
            }

            ArgumentNullException.ThrowIfNull(obj);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(sharedSecretKey);

            return GenerateToken(obj, sharedSecretKey).Equals(expectedToken);
        }

        protected string ComputeHmacToken(string stringForSigning, string signature)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(stringForSigning);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(signature);

            byte[] secretKey = Encoding.UTF8.GetBytes(signature);

            using HMACSHA512 hmac = new(secretKey);
            hmac.Initialize();

            byte[] bytes = Encoding.UTF8.GetBytes(stringForSigning);
            byte[] rawHmac = hmac.ComputeHash(bytes);

            return Convert.ToBase64String(rawHmac);
        }
    }
}
