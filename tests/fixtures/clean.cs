using System;
using System.Security.Cryptography;

public class SafeService
{
    private readonly string _name;

    public SafeService(string name)
    {
        _name = name;
    }

    public string GetName()
    {
        return _name;
    }

    public byte[] SecureHash(byte[] data)
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }

    public int SecureRandom()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        rng.GetBytes(bytes);
        return BitConverter.ToInt32(bytes, 0);
    }
}
