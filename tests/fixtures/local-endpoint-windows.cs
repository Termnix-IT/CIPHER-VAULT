// Development-only OS probe. Never linked into the application or used with vault data.
using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class LocalEndpointProbe
{
    [StructLayout(LayoutKind.Sequential)]
    struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafePipeHandle CreateNamedPipeW(string name, uint openMode, uint pipeMode, uint instances, uint output, uint input, uint timeout, ref SecurityAttributes attributes);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityInfo(SafePipeHandle handle, int kind, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetNamedPipeClientProcessId(SafePipeHandle handle, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetNamedPipeServerProcessId(SafePipeHandle handle, out uint pid);

    public sealed class AclResult
    {
        public bool ownerMatchesUser;
        public bool onlyUserAllowed;
        public bool broadReadAllowAce;
    }
    public sealed class PeerResult
    {
        public bool accepted;
        public bool peerMatches;
        public AclResult acl;
    }
    static SecurityIdentifier User()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) return identity.User;
    }
    static AclResult InspectAcl(SafePipeHandle handle)
    {
        IntPtr owner, group, dacl, sacl, descriptor;
        uint error = GetSecurityInfo(handle, 6 /* SE_KERNEL_OBJECT */, 5 /* OWNER | DACL */, out owner, out group, out dacl, out sacl, out descriptor);
        if (error != 0) throw new Win32Exception((int)error);
        try
        {
            byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            RawSecurityDescriptor security = new RawSecurityDescriptor(bytes, 0); SecurityIdentifier user = User();
            AclResult result = new AclResult { ownerMatchesUser = user.Equals(security.Owner), onlyUserAllowed = security.DiscretionaryAcl != null && security.DiscretionaryAcl.Count > 0 };
            if (security.DiscretionaryAcl == null) { result.broadReadAllowAce = true; return result; }
            foreach (GenericAce entry in security.DiscretionaryAcl)
            {
                CommonAce ace = entry as CommonAce;
                if (ace == null || ace.AceQualifier != AceQualifier.AccessAllowed || !user.Equals(ace.SecurityIdentifier)) result.onlyUserAllowed = false;
                if (ace != null && ace.AceQualifier == AceQualifier.AccessAllowed && (unchecked((uint)ace.AccessMask) & 0x90000001u) != 0 &&
                    (ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.WorldSid) || ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.AnonymousSid) || ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.AuthenticatedUserSid))) result.broadReadAllowAce = true;
            }
            return result;
        }
        finally { LocalFree(descriptor); }
    }
    public static PeerResult Inspect(string name, uint expected)
    {
        using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
        {
            pipe.Connect(5000); uint peer;
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out peer)) throw new Win32Exception();
            return new PeerResult { accepted = peer == expected, peerMatches = peer == expected, acl = InspectAcl(pipe.SafePipeHandle) };
        }
    }
    static NamedPipeServerStream Create(string name)
    {
        string sid = User().Value; IntPtr descriptor; uint size;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:" + sid + "D:P(A;;GA;;;" + sid + ")", 1, out descriptor, out size)) throw new Win32Exception();
        try
        {
            SecurityAttributes attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor, Inherit = 0 };
            // Explicit user DACL, first instance, overlapped I/O, and rejection of remote clients.
            SafePipeHandle handle = CreateNamedPipeW(@"\\.\pipe\" + name, 0x40080003, 8, 1, 512, 512, 5000, ref attributes);
            if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
            try { return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle); }
            catch { handle.Dispose(); throw; }
        }
        finally { LocalFree(descriptor); }
    }
    public static void Serve(string name, uint expected, int count)
    {
        using (NamedPipeServerStream pipe = Create(name))
        {
            AclResult acl = InspectAcl(pipe.SafePipeHandle);
            if (!acl.ownerMatchesUser || !acl.onlyUserAllowed || acl.broadReadAllowAce) throw new InvalidOperationException("ACL check failed");
            Console.WriteLine("{\"ready\":true}"); Console.Out.Flush();
            for (int index = 0; index < count; index++)
            {
                using (CancellationTokenSource deadline = new CancellationTokenSource(10000))
                {
                    pipe.WaitForConnectionAsync(deadline.Token).GetAwaiter().GetResult();
                    try
                    {
                        uint peer; if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out peer)) throw new Win32Exception();
                        byte[] request = new byte[4]; int offset = 0;
                        while (offset < 4) { int read = pipe.ReadAsync(request, offset, 4 - offset, deadline.Token).GetAwaiter().GetResult(); if (read == 0) throw new EndOfStreamException(); offset += read; }
                        bool sameUser = false; SecurityIdentifier user = User();
                        pipe.RunAsClient(() => { sameUser = user.Equals(User()); });
                        uint claimed = ((uint)request[0] << 24) | ((uint)request[1] << 16) | ((uint)request[2] << 8) | request[3];
                        string result = "{\"accepted\":" + Bool(peer == expected && sameUser) + ",\"peerMatches\":" + Bool(peer == expected) + ",\"userMatches\":" + Bool(sameUser) + ",\"claimedMatches\":" + Bool(claimed == expected) + "}\n";
                        byte[] response = Encoding.UTF8.GetBytes(result); pipe.WriteAsync(response, 0, response.Length, deadline.Token).GetAwaiter().GetResult();
                        // DisconnectNamedPipe discards unread output. Let the reader close after its complete response.
                        byte[] terminal = new byte[1];
                        if (pipe.ReadAsync(terminal, 0, 1, deadline.Token).GetAwaiter().GetResult() != 0) throw new InvalidDataException();
                    }
                    catch (EndOfStreamException) { /* A disconnected client has no operation to run. */ }
                    catch (IOException) { /* A reset client has no operation to run. */ }
                    finally { if (pipe.IsConnected) pipe.Disconnect(); }
                }
            }
        }
    }
    static string Bool(bool value) { return value ? "true" : "false"; }
}
