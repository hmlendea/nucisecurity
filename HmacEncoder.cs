using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using NuciExtensions;

namespace NuciSecurity.HMAC
{
    public class HmacEncoder
    {
        private static string StaticSalt => $"{nameof(NuciSecurity)}.{nameof(HMAC)}.{nameof(StaticSalt)}.8fc5307e-c10b-40d0-b710-de79e7954358";
        private static string FieldSeparator => "|#FieldSeparator#|";
        private static string EmptyValue => "|#EmptyValue#|";
        private static string PrefixFormat => "|#Length:{0}#|";
        private static int DefaultOrder => int.MaxValue;

        public static string GenerateToken<TObject>(TObject obj, string sharedSecretKey) where TObject : class
        {
            ArgumentNullException.ThrowIfNull(obj);

            StringBuilder stringBuilder = new();

            var propertiesToCompute = obj.GetType()
                .GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.GetCustomAttribute<HmacIgnoreAttribute>() is null)
                .Select(p => new
                {
                    Property = p,
                    OrderAttr = p.GetCustomAttribute<HmacOrderAttribute>()
                })
                .OrderBy(x => x.OrderAttr?.Order ?? DefaultOrder)
                .ThenBy(x => x.Property.Name)
                .Select(x => x.Property);

            foreach (PropertyInfo property in propertiesToCompute)
            {
                var propertyValue = property.GetValue(obj);
                int propertyOrder = property.GetCustomAttribute<HmacOrderAttribute>()?.Order ?? DefaultOrder;

                string value = propertyValue switch
                {
                    DateTime dt => dt.ToString("O"),
                    _ => propertyValue?.ToString() ?? EmptyValue
                };


                if ((propertyOrder % 2).Equals(0))
                {
                    value = value.Reverse();
                }

                stringBuilder.Append(string.Format(PrefixFormat, value.Length) + value + FieldSeparator);
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

            string saltedString = $"{StaticSalt}.{stringForSigning}";

            byte[] rawHmac = hmac.ComputeHash(Encoding.UTF8.GetBytes(saltedString));

            return Convert.ToBase64String(rawHmac);
        }
    }
}
