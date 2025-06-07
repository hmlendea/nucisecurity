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

            return GenerateToken(obj, sharedSecretKey).Equals(expectedToken);
        }

        protected string ComputeHmacToken(string stringForSigning, string signature)
        {
            if (string.IsNullOrWhiteSpace(signature))
            {
                throw new ArgumentNullException("The signature cannot be null");
            }

            byte[] secretKey = Encoding.UTF8.GetBytes(signature);

            using HMACSHA512 hmac = new(secretKey);
            hmac.Initialize();

            byte[] bytes = Encoding.UTF8.GetBytes(stringForSigning);
            byte[] rawHmac = hmac.ComputeHash(bytes);

            return Convert.ToBase64String(rawHmac);
        }
    }
}
