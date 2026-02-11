using System.Security.Cryptography;
using System.Text;

namespace ModernWebGoat.Endpoints;

public static class A02_CryptographicFailures
{
    public static void MapA02CryptographicFailuresEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/crypto").WithTags("A02 - Cryptographic Failures");

        // VULNERABILITY A02: Weak encryption — DES with hardcoded key
        group.MapGet("/encrypt", (string? data, IConfiguration config) =>
        {
            if (string.IsNullOrEmpty(data))
                return Results.BadRequest(new { error = "Provide data via ?data=" });

            var key = Encoding.UTF8.GetBytes(config["Encryption:DesKey"]!);  // 8 bytes
            var iv = Encoding.UTF8.GetBytes(config["Encryption:DesIV"]!);    // 8 bytes

            // VULNERABLE: DES is broken — 56-bit effective key, retired since 2005
#pragma warning disable SYSLIB0021 // DES is obsolete
            using var des = DES.Create();
#pragma warning restore SYSLIB0021
            des.Key = key;
            des.IV = iv;

            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
            {
                var plainBytes = Encoding.UTF8.GetBytes(data);
                cs.Write(plainBytes, 0, plainBytes.Length);
            }

            var encrypted = Convert.ToBase64String(ms.ToArray());

            return Results.Ok(new
            {
                algorithm = "DES (Data Encryption Standard)",
                keySize = "56-bit effective",
                key = config["Encryption:DesKey"],
                iv = config["Encryption:DesIV"],
                plaintext = data,
                ciphertext = encrypted,
                vulnerability = "DES is broken and should never be used. Key is hardcoded in config."
            });
        });

        // VULNERABILITY A02: Decrypt with same hardcoded DES key
        group.MapGet("/decrypt", (string? data, IConfiguration config) =>
        {
            if (string.IsNullOrEmpty(data))
                return Results.BadRequest(new { error = "Provide base64 ciphertext via ?data=" });

            try
            {
                var key = Encoding.UTF8.GetBytes(config["Encryption:DesKey"]!);
                var iv = Encoding.UTF8.GetBytes(config["Encryption:DesIV"]!);

#pragma warning disable SYSLIB0021
                using var des = DES.Create();
#pragma warning restore SYSLIB0021
                des.Key = key;
                des.IV = iv;

                var cipherBytes = Convert.FromBase64String(data);
                using var ms = new MemoryStream(cipherBytes);
                using var cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read);
                using var reader = new StreamReader(cs);
                var decrypted = reader.ReadToEnd();

                return Results.Ok(new { plaintext = decrypted });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        // VULNERABILITY A02: Hardcoded secrets exposed via API
        group.MapGet("/secrets", (IConfiguration config) =>
        {
            return Results.Ok(new
            {
                jwt = new
                {
                    key = config["Jwt:Key"],
                    issuer = config["Jwt:Issuer"],
                    audience = config["Jwt:Audience"]
                },
                apiKeys = new
                {
                    thirdPartyService = config["ApiKeys:ThirdPartyService"],
                    paymentGateway = config["ApiKeys:PaymentGateway"],
                    internalSecret = config["ApiKeys:InternalSecret"]
                },
                encryption = new
                {
                    desKey = config["Encryption:DesKey"],
                    desIV = config["Encryption:DesIV"]
                },
                vulnerability = "All secrets are hardcoded in appsettings.json and checked into source control"
            });
        });

        // VULNERABILITY A02: MD5 hash demo
        group.MapGet("/hash", (string? data) =>
        {
            if (string.IsNullOrEmpty(data))
                return Results.BadRequest(new { error = "Provide data via ?data=" });

            var md5 = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(data))).ToLower();
            var sha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(data))).ToLower();

            return Results.Ok(new
            {
                input = data,
                md5,
                sha1,
                vulnerability = "MD5 and SHA1 are broken for password hashing — no salt, fast to brute force"
            });
        });
    }
}
