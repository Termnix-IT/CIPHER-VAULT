using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CipherVault.Transport;

internal sealed record Control(int Protocol, string Event, int ProcessId, int PeerProcessId, bool CurrentUser);
[JsonSerializable(typeof(Control))]
[JsonSerializable(typeof(IdentityFrame))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal partial class WireJson : JsonSerializerContext { }

internal static class Program
{
    internal static readonly byte[] Preamble = "CVLT0001"u8.ToArray();
    internal static readonly Stream Output = Console.OpenStandardOutput();
    internal static async Task Control(string kind, int peer = 0)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new Control(1, kind, Environment.ProcessId, peer, peer > 0), WireJson.Default.Control);
        byte[] length = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, (uint)payload.Length);
        await Output.WriteAsync(length); await Output.WriteAsync(payload); await Output.FlushAsync();
    }
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--version") { await Control("version"); return 0; }
        if (args.Length != 2 || args[0] is not ("serve" or "connect" or "identity") ||
            (args[0] == "identity" && args[1] is not ("host" or "client"))) return 64;
        using CancellationTokenSource lifetime = new();
        using PosixSignalRegistration? termination = OperatingSystem.IsWindows() ? null :
            PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; lifetime.Cancel(); });
        try
        {
            if (args[0] == "identity") await LocalIdentityIssuer.Write(args[1], lifetime.Token);
            else if (OperatingSystem.IsWindows()) await WindowsTransport.Run(args[0], args[1], lifetime.Token);
            else if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()) await UnixTransport.Run(args[0], args[1], lifetime.Token);
            else throw new PlatformNotSupportedException();
            return 0;
        }
        catch (OperationCanceledException) { return 0; }
        catch { Console.Error.WriteLine("LOCAL_TRANSPORT_UNAVAILABLE"); return 70; }
    }
    internal static async Task Negotiate(Stream peer, bool server, CancellationToken cancellation)
    {
        byte[] received = new byte[Preamble.Length];
        if (!server) await peer.WriteAsync(Preamble, cancellation);
        await peer.ReadExactlyAsync(received, cancellation);
        if (!received.AsSpan().SequenceEqual(Preamble)) throw new InvalidDataException();
        if (server) await peer.WriteAsync(Preamble, cancellation);
        await peer.FlushAsync(cancellation);
    }
    // This only transports bytes. OS peer checks do not enroll or authorize an application client.
    internal static async Task Relay(Stream peer, int peerId, CancellationToken cancellation)
    {
        await Control("peer", peerId);
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        using Stream input = Console.OpenStandardInput();
        Task incoming = peer.CopyToAsync(Output, 16384, stop.Token);
        Task outgoing = input.CopyToAsync(peer, 16384, stop.Token);
        Task completed = await Task.WhenAny(incoming, outgoing);
        try { await completed; }
        finally
        {
            stop.Cancel(); peer.Dispose();
            _ = incoming.ContinueWith(task => _ = task.Exception, TaskContinuationOptions.OnlyOnFaulted);
            _ = outgoing.ContinueWith(task => _ = task.Exception, TaskContinuationOptions.OnlyOnFaulted);
        }
    }
}
