namespace NuciSecurity.HMAC
{
    public interface IHmacEncoder<T> where T : class
    {
        string GenerateToken(T obj, string sharedSecretKey);

        bool IsTokenValid(string expectedToken, T obj, string sharedSecretKey);
    }
}
