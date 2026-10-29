using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace CipherVault.Transport;

[SupportedOSPlatform("windows")]
internal static class WindowsTransport
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Attributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipeW(string name, uint open, uint mode, uint count, uint output, uint input, uint timeout, ref Attributes attributes);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafePipeHandle handle, int kind, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle handle, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle handle, out uint pid);
    private static SecurityIdentifier User() { using WindowsIdentity identity = WindowsIdentity.GetCurrent(); return identity.User ?? throw new InvalidOperationException(); }
    private static void CheckAcl(SafePipeHandle handle)
    {
        uint error = GetSecurityInfo(handle, 6, 5, out _, out _, out _, out _, out IntPtr descriptor);
        if (error != 0) throw new Win32Exception((int)error);
        try
        {
            byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            RawSecurityDescriptor security = new(bytes, 0); SecurityIdentifier user = User();
            if (security.Owner is null || !user.Equals(security.Owner) || security.DiscretionaryAcl is null || security.DiscretionaryAcl.Count != 1 ||
                (security.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0) throw new InvalidDataException();
            if (security.DiscretionaryAcl[0] is not CommonAce ace || ace.AceQualifier != AceQualifier.AccessAllowed ||
                !user.Equals(ace.SecurityIdentifier) || ace.AceFlags != AceFlags.None) throw new InvalidDataException();
        }
        finally { LocalFree(descriptor); }
    }
    private static NamedPipeServerStream Create(string endpoint)
    {
        string sid = User().Value;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:" + sid + "D:P(A;;GA;;;" + sid + ")", 1, out IntPtr descriptor, out _)) throw new Win32Exception();
        try
        {
            Attributes attributes = new() { Length = Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
            SafePipeHandle handle = CreateNamedPipeW(endpoint, 0x40080003, 8, 1, 16384, 16384, 10000, ref attributes);
            if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
            try { CheckAcl(handle); return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle); }
            catch { handle.Dispose(); throw; }
        }
        finally { LocalFree(descriptor); }
    }
    internal static async Task Run(string mode, string endpoint, CancellationToken cancellation)
    {
        const string prefix = @"\\.\pipe\cipher-vault-";
        if (!endpoint.StartsWith(prefix, StringComparison.Ordinal) || !Guid.TryParseExact(endpoint[prefix.Length..], "D", out _)) throw new InvalidDataException();
        using CancellationTokenSource handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellation); handshake.CancelAfter(30000);
        if (mode == "serve")
        {
            using NamedPipeServerStream server = Create(endpoint);
            await Program.Control("ready"); await server.WaitForConnectionAsync(handshake.Token);
            if (!GetNamedPipeClientProcessId(server.SafePipeHandle, out uint pid) || pid == 0 || pid > int.MaxValue) throw new Win32Exception();
            await Program.Negotiate(server, true, handshake.Token);
            SecurityIdentifier user = User(); bool sameUser = false;
            server.RunAsClient(() => sameUser = user.Equals(User()));
            if (!sameUser) throw new InvalidDataException();
            await Program.Relay(server, (int)pid, cancellation);
        }
        else
        {
            // CurrentUserOnly compares the token owner rather than User on .NET 10
            // (dotnet/runtime#123903). CheckAcl below verifies the exact user SID,
            // protected one-user DACL and owner before exchanging any peer bytes.
            using NamedPipeClientStream client = new(".", endpoint[@"\\.\pipe\".Length..], PipeDirection.InOut,
                PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
            await client.ConnectAsync(handshake.Token); CheckAcl(client.SafePipeHandle);
            if (!GetNamedPipeServerProcessId(client.SafePipeHandle, out uint pid) || pid == 0 || pid > int.MaxValue) throw new Win32Exception();
            await Program.Negotiate(client, false, handshake.Token);
            await Program.Relay(client, (int)pid, cancellation);
        }
    }
}
