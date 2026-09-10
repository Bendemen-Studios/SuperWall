using System.Security.Cryptography;
using System.Text;

namespace SuperWall.Agent;

public static class PinSecurity
{
    public static (string Hash, string Salt) CreateHash(string pin)
    {
        var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var hash = Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(pin), Convert.FromBase64String(salt), 120_000, HashAlgorithmName.SHA256, 32));
        return (hash, salt);
    }

    public static bool Verify(string pin, string hash, string salt)
    {
        try
        {
            var candidate = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(pin), Convert.FromBase64String(salt), 120_000, HashAlgorithmName.SHA256, 32);
            var expected = Convert.FromBase64String(hash);
            return CryptographicOperations.FixedTimeEquals(candidate, expected);
        }
        catch { return false; }
    }
}
