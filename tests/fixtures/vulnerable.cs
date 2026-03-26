using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

public class VulnerableService
{
    // SQL injection via string concatenation
    public void GetUser(string userId)
    {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId);
    }

    // Command injection via Process.Start with user input
    public void RunCommand(string input)
    {
        Process.Start(input);
    }

    // Hardcoded secret
    private string password = "SuperSecret123!";

    // Weak crypto
    public byte[] Hash(byte[] data)
    {
        var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    // Path traversal with user input
    public string ReadFile(string input)
    {
        return File.ReadAllText(input);
    }

    // Insecure random
    public int GetRandom()
    {
        return new Random().Next();
    }

    // Unsafe deserialization
    public object Deserialize(Stream stream)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }

    // XSS via Response.Write with user input
    public void WriteResponse(string userInput)
    {
        // Response.Write(Request.QueryString["name"]);
    }
}
