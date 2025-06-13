using System;
using System.Collections;
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
        private static string PrefixFormat => "|#Length:{0};Checksum:{1}#|";
        private static int DefaultOrder => int.MaxValue;

        public static string GenerateToken<TObject>(TObject obj, string sharedSecretKey) where TObject : class
        {
            ArgumentNullException.ThrowIfNull(obj);

            string stringForSigning = GetStringForSigning(obj);
            string prefix = string.Format(PrefixFormat, stringForSigning.Length, stringForSigning.GetHashCode());

            return ComputeHmacToken(prefix + stringForSigning.Reverse(), sharedSecretKey);
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

        static string GetStringForSigning<TObject>(TObject obj) where TObject : class
        {
            if (obj is null)
            {
                return EmptyValue + FieldSeparator;
            }

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
                string value;

                if (propertyValue is IEnumerable enumerable && propertyValue is not string)
                {
                    Type elementType = property.PropertyType.IsGenericType
                        ? property.PropertyType.GetGenericArguments()[0]
                        : property.PropertyType.GetElementType();

                    if (elementType is not null && elementType.IsClass && elementType != typeof(string))
                    {
                        StringBuilder nestedBuilder = new();

                        foreach (var item in enumerable)
                        {
                            nestedBuilder.Append(item is null ? EmptyValue : GetStringForSigning(item) + FieldSeparator);
                        }

                        value = nestedBuilder.ToString();
                    }
                    else
                    {
                        var flatValues = enumerable
                            .Cast<object?>()
                            .Select(item => item?.ToString() ?? EmptyValue);

                        value = string.Join(FieldSeparator, flatValues);
                    }
                }
                else
                {
                    value = propertyValue switch
                    {
                        DateTime dt => dt.ToString("O"),
                        _ => propertyValue?.ToString() ?? EmptyValue
                    };
                }

                stringBuilder.Append(value + FieldSeparator);
            }

            return stringBuilder.ToString();
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
