using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace CipherVault.Transport;

internal sealed record IdentityFrame(int Protocol, string Event, int ProcessId, string Role, int CertificateBytes, int PrivateKeyBytes);
internal static class LocalIdentityIssuer
{
    internal static async Task Write(string role, CancellationToken cancellation)
    {
        if (!Console.IsOutputRedirected || role is not ("host" or "client")) throw new InvalidOperationException();
        using ECDsa issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string purpose = role == "host" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2";
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        DateTimeOffset until = now.AddDays(role == "host" ? 365 : 90);
        CertificateRequest issuerRequest = new($"CN=cipher-vault-issuer-{Guid.NewGuid():D}", issuerKey, HashAlgorithmName.SHA256);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        issuerRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(issuerRequest.PublicKey, false));
        issuerRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(purpose) }, true));
        using X509Certificate2 issuer = issuerRequest.CreateSelfSigned(now.AddMinutes(-1), until);
        CertificateRequest request = new(role == "host" ? "CN=cipher-vault.local" : "CN=cipher-vault-client", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(purpose) }, true));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        if (role == "host")
        {
            SubjectAlternativeNameBuilder names = new(); names.AddDnsName("cipher-vault.local");
            request.CertificateExtensions.Add(names.Build());
        }
        using X509Certificate2 certificate = request.Create(issuer, now.AddMinutes(-1), until, RandomNumberGenerator.GetBytes(16));
        byte[] der = key.ExportPkcs8PrivateKey();
        byte[]? privatePem = null;
        try
        {
            privatePem = PemEncoding.WriteUtf8("PRIVATE KEY"u8, der);
            byte[] publicPem = [.. PemEncoding.WriteUtf8("CERTIFICATE"u8, certificate.RawData), (byte)'\n', .. PemEncoding.WriteUtf8("CERTIFICATE"u8, issuer.RawData)];
            byte[] header = JsonSerializer.SerializeToUtf8Bytes(new IdentityFrame(1, "identity", Environment.ProcessId, role, publicPem.Length, privatePem.Length), WireJson.Default.IdentityFrame);
            byte[] length = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, (uint)header.Length);
            cancellation.ThrowIfCancellationRequested();
            await Program.Output.WriteAsync(length, cancellation); await Program.Output.WriteAsync(header, cancellation);
            await Program.Output.WriteAsync(publicPem, cancellation); await Program.Output.WriteAsync(privatePem, cancellation);
            await Program.Output.FlushAsync(cancellation);
        }
        finally { CryptographicOperations.ZeroMemory(der); if (privatePem is not null) CryptographicOperations.ZeroMemory(privatePem); }
    }
}
