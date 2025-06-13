using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace NuciSecurity.HMAC
{
    public class HmacEncoder
    {
        public static string GenerateToken<TObject>(TObject obj, string sharedSecretKey) where TObject : class
        {
            ArgumentNullException.ThrowIfNull(obj);

            StringBuilder stringBuilder = new();

            foreach (PropertyInfo property in obj.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                stringBuilder.Append(property.GetValue(obj)?.ToString() ?? string.Empty);
            }

            return ComputeHmacToken(stringBuilder.ToString(), sharedSecretKey);
        }

        public static bool IsTokenValid<TObject>(string expectedToken, TObject obj, string sharedSecretKey) where TObject : class
        {
            if (string.IsNullOrWhiteSpace(expectedToken))
            {
                return false;
            }

            ArgumentNullException.ThrowIfNull(obj);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(sharedSecretKey);

            return GenerateToken(obj, sharedSecretKey).Equals(expectedToken);
        }

        static string ComputeHmacToken(string stringForSigning, string sharedSecretKey)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(stringForSigning);
            ArgumentNullException.ThrowIfNullOrWhiteSpace(sharedSecretKey);

            using HMACSHA512 hmac = new(Encoding.UTF8.GetBytes(sharedSecretKey));
            hmac.Initialize();

            byte[] rawHmac = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringForSigning));

            return Convert.ToBase64String(rawHmac);
        }
    }
}
