using System.Security.Cryptography;
using System.Text;
using QRCoder;

namespace SecurityAuditDashboard.Web.Services;

/// <summary>
/// Service for Two-Factor Authentication using TOTP (Time-based One-Time Password)
/// Demonstrates: Cryptography, Base32 encoding, QR code generation
/// </summary>
public interface ITwoFactorService
{
    string GenerateSecretKey();
    string GenerateQrCodeUri(string email, string secretKey);
    string GenerateQrCodeAsBase64(string email, string secretKey);
    bool ValidateCode(string secretKey, string code);
}

public class TwoFactorService : ITwoFactorService
{
    private const int SecretKeyLength = 20;
    private const int CodeDigits = 6;
    private const int TimeStep = 30; // seconds
    private const string Issuer = "SecurityAuditDashboard";

    /// <summary>
    /// Generates a random secret key for TOTP
    /// </summary>
    public string GenerateSecretKey()
    {
        var key = new byte[SecretKeyLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return Base32Encode(key);
    }

    /// <summary>
    /// Generates the otpauth URI for authenticator apps
    /// </summary>
    public string GenerateQrCodeUri(string email, string secretKey)
    {
        return $"otpauth://totp/{Issuer}:{Uri.EscapeDataString(email)}?secret={secretKey}&issuer={Issuer}&digits={CodeDigits}";
    }

    /// <summary>
    /// Generates a QR code as a base64 encoded PNG image
    /// </summary>
    public string GenerateQrCodeAsBase64(string email, string secretKey)
    {
        var uri = GenerateQrCodeUri(email, secretKey);
        
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var pngBytes = qrCode.GetGraphic(5);
        
        return $"data:image/png;base64,{Convert.ToBase64String(pngBytes)}";
    }

    /// <summary>
    /// Validates a TOTP code against the secret key
    /// </summary>
    public bool ValidateCode(string secretKey, string code)
    {
        if (string.IsNullOrEmpty(code) || code.Length != CodeDigits)
            return false;

        var secretBytes = Base32Decode(secretKey);
        var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / TimeStep;

        // Check current time window and one before/after for clock drift
        for (int i = -1; i <= 1; i++)
        {
            var computedCode = ComputeTotp(secretBytes, currentTime + i);
            if (computedCode == code)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Computes TOTP code using HMAC-SHA1
    /// </summary>
    private string ComputeTotp(byte[] secret, long counter)
    {
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);

        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counterBytes);

        // Dynamic truncation
        var offset = hash[^1] & 0x0F;
        var binaryCode = (hash[offset] & 0x7F) << 24
                       | (hash[offset + 1] & 0xFF) << 16
                       | (hash[offset + 2] & 0xFF) << 8
                       | (hash[offset + 3] & 0xFF);

        var otp = binaryCode % (int)Math.Pow(10, CodeDigits);
        return otp.ToString().PadLeft(CodeDigits, '0');
    }

    /// <summary>
    /// Base32 encode bytes to string
    /// </summary>
    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var result = new StringBuilder((data.Length + 4) / 5 * 8);
        
        int buffer = 0, bitsLeft = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                result.Append(alphabet[(buffer >> (bitsLeft - 5)) & 0x1F]);
                bitsLeft -= 5;
            }
        }
        
        if (bitsLeft > 0)
            result.Append(alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        
        return result.ToString();
    }

    /// <summary>
    /// Base32 decode string to bytes
    /// </summary>
    private static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        input = input.ToUpperInvariant().TrimEnd('=');
        
        var output = new List<byte>();
        int buffer = 0, bitsLeft = 0;
        
        foreach (var c in input)
        {
            var value = alphabet.IndexOf(c);
            if (value < 0) continue;
            
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            
            if (bitsLeft >= 8)
            {
                output.Add((byte)(buffer >> (bitsLeft - 8)));
                bitsLeft -= 8;
            }
        }
        
        return output.ToArray();
    }
}
