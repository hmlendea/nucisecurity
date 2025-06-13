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

        /// <summary>
        /// Generates a HMAC token for the given object using the specified shared secret key.
        /// </summary>
        /// <typeparam name="TObject">The type of the object to generate the token for.</typeparam>
        /// <param name="obj">The object to generate the token for.</param>
        /// <param name="sharedSecretKey">The shared secret key used for HMAC generation.</param>
        /// <returns>An HMAC token as a Base64 encoded string.</returns>
        /// <throws cref="ArgumentNullException">Thrown if the object or shared secret key is null.</throws>
        public static string GenerateToken<TObject>(TObject obj, string sharedSecretKey) where TObject : class
        {
            ArgumentNullException.ThrowIfNull(obj);

            string stringForSigning = GetStringForSigning(obj);
            string prefix = string.Format(
                PrefixFormat,
                stringForSigning.Length,
                GetMd5Hash(stringForSigning));

            return ComputeHmacToken(prefix + stringForSigning.Reverse(), sharedSecretKey).InvertCase();
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
            byte[] bytesToSign = Encoding.UTF8.GetBytes(PadStringToAvoidBase64Equals(saltedString));

            return Convert.ToBase64String(hmac.ComputeHash(bytesToSign));
        }

        static string PadStringToAvoidBase64Equals(string input, char padChar = '~')
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            int padLength = (3 - (bytes.Length % 3)) % 3;

            return input + new string(padChar, padLength);
        }

        static string GetMd5Hash(string input)
        {
            byte[] hashBytes = MD5.HashData(Encoding.UTF8.GetBytes(input));

            StringBuilder sb = new();

            foreach (byte b in hashBytes)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }
    }
}
