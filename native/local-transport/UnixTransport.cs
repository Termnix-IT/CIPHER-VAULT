using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace CipherVault.Transport;

[UnsupportedOSPlatform("windows")]
internal static class UnixTransport
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Info { public ulong Device; public ulong Inode; public uint User; public uint Mode; public uint Kind; }
    [DllImport("transportos", EntryPoint = "cv_path_info")]
    private static extern int PathInfo([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out Info info);
    [DllImport("transportos", EntryPoint = "cv_user")]
    private static extern uint User();
    [DllImport("transportos", EntryPoint = "cv_listen")]
    private static extern int Listen([MarshalAs(UnmanagedType.LPUTF8Str)] string path);
    [DllImport("transportos", EntryPoint = "cv_peer")]
    private static extern int Peer(int handle, out int pid, out uint user);
    private static Info Inspect(string path, uint kind, uint mode)
    {
        if (PathInfo(path, out Info info) != 0 || info.User != User() || info.Kind != kind || (info.Mode & 0xfff) != mode) throw new InvalidDataException();
        return info;
    }
    private static void Directory(string endpoint)
    {
        if (!Path.IsPathFullyQualified(endpoint) || endpoint != Path.GetFullPath(endpoint) || endpoint.Contains('\0') || System.Text.Encoding.UTF8.GetByteCount(endpoint) >= 100 || User() == 0) throw new InvalidDataException();
        string parent = Path.GetDirectoryName(endpoint) ?? throw new InvalidDataException(); Inspect(parent, 1, 0x1c0 /*0700*/);
        for (DirectoryInfo? current = new(parent); current is not null; current = current.Parent)
            if (current.LinkTarget is not null) throw new InvalidDataException();
    }
    internal static async Task Run(string mode, string endpoint, CancellationToken cancellation)
    {
        Directory(endpoint); Info? owned = null;
        using CancellationTokenSource handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellation); handshake.CancelAfter(30000);
        try
        {
            Socket peer;
            if (mode == "serve")
            {
                if (PathInfo(endpoint, out _) == 0) throw new InvalidDataException();
                int fd = Listen(endpoint); if (fd < 0) throw new IOException();
                // Bind natively so Socket.Dispose never unlinks a path that another process has replaced.
                using Socket server = new(new SafeSocketHandle((IntPtr)fd, true));
                owned = Inspect(endpoint, 2, 0x180 /*0600*/); await Program.Control("ready");
                peer = await server.AcceptAsync(handshake.Token);
            }
            else
            {
                Info original = Inspect(endpoint, 2, 0x180); peer = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await peer.ConnectAsync(new UnixDomainSocketEndPoint(endpoint), handshake.Token);
                    Info current = Inspect(endpoint, 2, 0x180);
                    if (original.Device != current.Device || original.Inode != current.Inode) throw new InvalidDataException();
                }
                catch { peer.Dispose(); throw; }
            }
            using (peer)
            {
                if (Peer(peer.Handle.ToInt32(), out int pid, out uint user) != 0 || pid <= 0 || user != User()) throw new InvalidDataException();
                using NetworkStream stream = new(peer, false);
                await Program.Negotiate(stream, mode == "serve", handshake.Token);
                await Program.Relay(stream, pid, cancellation);
            }
        }
        finally
        {
            if (owned is Info original && PathInfo(endpoint, out Info current) == 0 && current.Kind == 2 &&
                current.User == original.User && current.Device == original.Device && current.Inode == original.Inode) File.Delete(endpoint);
        }
    }
}
