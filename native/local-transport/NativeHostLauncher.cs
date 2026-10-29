using System.Diagnostics;
using System.Buffers.Binary;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CipherVault.Transport;

// Browser-facing stdio launcher. It does not load credentials or Vault data.
internal static partial class NativeHostLauncher
{
    [GeneratedRegex("^chrome-extension://[a-p]{32}/$", RegexOptions.CultureInvariant)]
    private static partial Regex Origin();
    internal static async Task<int> Run(string[] args)
    {
        Process? child = null;
        using CancellationTokenSource lifetime = new(TimeSpan.FromSeconds(130));
        try
        {
            if (args.Length < 1 || args.Length > (OperatingSystem.IsWindows() ? 2 : 1) || !Origin().IsMatch(args[0]) ||
                (args.Length == 2 && (!args[1].StartsWith("--parent-window=", StringComparison.Ordinal) ||
                    args[1].Length > 36 || !ulong.TryParse(args[1].AsSpan(16), NumberStyles.None, CultureInfo.InvariantCulture, out _)))) throw new InvalidDataException();
            string executable = Environment.ProcessPath ?? throw new InvalidDataException();
            string directory = Path.GetDirectoryName(executable) ?? throw new InvalidDataException();
            string file = Path.Combine(directory, "host-config.json");
            FileInfo metadata = new(file);
            if ((metadata.Attributes & FileAttributes.ReparsePoint) != 0 || metadata.Length is < 2 or > 16384) throw new InvalidDataException();
            byte[] bytes = new byte[16385]; int count = 0;
            using (FileStream source = new(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                int read;
                while (count < bytes.Length && (read = await source.ReadAsync(bytes.AsMemory(count), lifetime.Token)) != 0) count += read;
                if (count != metadata.Length || count > 16384) throw new InvalidDataException();
            }
            using JsonDocument document = JsonDocument.Parse(bytes.AsMemory(0, count));
            JsonElement config = document.RootElement;
            if (config.ValueKind != JsonValueKind.Object ||
                !config.EnumerateObject().Select(item => item.Name).Order(StringComparer.Ordinal).SequenceEqual(new[] { "applicationEntry", "applicationExecutable", "browser", "extensionOrigin", "version" }) ||
                config.GetProperty("version").GetInt32() != 1 || config.GetProperty("browser").GetString() is not ("chrome" or "edge") ||
                config.GetProperty("extensionOrigin").GetString() != args[0]) throw new InvalidDataException();
            string application = ConfigPath(config.GetProperty("applicationExecutable").GetString());
            JsonElement entry = config.GetProperty("applicationEntry");
            string? applicationEntry = entry.ValueKind == JsonValueKind.Null ? null : ConfigPath(entry.GetString());
            ProcessStartInfo start = new(application) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(application)!,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string key in start.Environment.Keys.ToArray())
                if (key.StartsWith("PASSWORD_MANAGER_", StringComparison.OrdinalIgnoreCase) || key.StartsWith("ELECTRON_", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("NODE_OPTIONS", StringComparison.OrdinalIgnoreCase) || key.Equals("NODE_PATH", StringComparison.OrdinalIgnoreCase) || key.Equals("SSLKEYLOGFILE", StringComparison.OrdinalIgnoreCase)) start.Environment.Remove(key);
            if (applicationEntry is not null) start.ArgumentList.Add(applicationEntry);
            start.ArgumentList.Add("--cipher-vault-native-host=" + file);
            start.ArgumentList.Add("--cipher-vault-caller-origin=" + args[0]);
            start.ArgumentList.Add("--user-data-dir=" + Path.Combine(directory, "client-profile"));
            start.ArgumentList.Add("--disable-logging");
            using Stream input = Console.OpenStandardInput();
            byte[] header = new byte[4]; await input.ReadExactlyAsync(header, lifetime.Token);
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(header);
            if (length is < 2 or > 65536) throw new InvalidDataException();
            byte[] payload = new byte[length]; await input.ReadExactlyAsync(payload, lifetime.Token);
            start.Environment["ELECTRON_NO_ATTACH_CONSOLE"] = "1";
            using JsonDocument request = JsonDocument.Parse(payload);
            JsonElement command = request.RootElement;
            if (command.ValueKind != JsonValueKind.Object ||
                !command.EnumerateObject().Select(item => item.Name).Order(StringComparer.Ordinal).SequenceEqual(new[] { "id", "operation", "version" }) ||
                command.GetProperty("version").GetInt32() != 1 || !Guid.TryParseExact(command.GetProperty("id").GetString(), "D", out _) ||
                command.GetProperty("operation").GetString() is not ("get-state" or "prepare-pairing" or "import-connection" or "check-connection" or "reset-pairing")) throw new InvalidDataException();
            child = Process.Start(start) ?? throw new InvalidDataException();
            Task<byte[]> incoming = ReadReply(child.StandardOutput.BaseStream, applicationEntry is not null, command.GetProperty("id").GetString()!, lifetime.Token);
            await child.StandardInput.BaseStream.WriteAsync(header, lifetime.Token);
            await child.StandardInput.BaseStream.WriteAsync(payload, lifetime.Token);
            await child.StandardInput.BaseStream.FlushAsync(lifetime.Token);
            child.StandardInput.Close();
            Task outgoing = input.ReadAsync(new byte[1], lifetime.Token).AsTask();
            Task errors = child.StandardError.BaseStream.CopyToAsync(Stream.Null, 16384, lifetime.Token);
            Task exited = child.WaitForExitAsync(lifetime.Token);
            Task completed = await Task.WhenAny(incoming, outgoing, exited);
            await completed;
            if (completed == outgoing) throw new InvalidDataException(); // EOF or a second frame cancels the owned command.
            await exited; byte[] reply = await incoming; await errors;
            if (child.ExitCode is not (0 or 1)) throw new InvalidDataException();
            await Program.Output.WriteAsync(reply, lifetime.Token); await Program.Output.FlushAsync(lifetime.Token);
            return child.ExitCode == 0 ? 0 : 70;
        }
        catch { Console.Error.WriteLine("BROWSER_CONNECTION_UNAVAILABLE"); return 70; }
        finally
        {
            lifetime.Cancel();
            if (child is not null) { try { if (!child.HasExited) child.Kill(entireProcessTree: true); } catch { } child.Dispose(); }
        }
    }
    private static string ConfigPath(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 4096 || !Path.IsPathFullyQualified(value) || value != Path.GetFullPath(value) ||
            value.StartsWith("\\\\", StringComparison.Ordinal) || value.StartsWith("//", StringComparison.Ordinal) || value.Any(char.IsControl) ||
            !File.Exists(value) || (File.GetAttributes(value) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
        return value;
    }
    private static async Task<byte[]> ReadReply(Stream stream, bool development, string id, CancellationToken cancellation)
    {
        byte[] header = new byte[4]; await stream.ReadExactlyAsync(header, cancellation);
        // Electron's Windows development executable emits one startup CRLF. No arbitrary log,
        // prefix scanning, extra frame or trailing data is ever forwarded to the browser.
        if (OperatingSystem.IsWindows() && development && header[0] == 13 && header[1] == 10)
        { header[0] = header[2]; header[1] = header[3]; await stream.ReadExactlyAsync(header.AsMemory(2, 2), cancellation); }
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length is < 2 or > 65536) throw new InvalidDataException();
        byte[] payload = new byte[length]; await stream.ReadExactlyAsync(payload, cancellation);
        using JsonDocument document = JsonDocument.Parse(payload);
        JsonElement value = document.RootElement;
        if (value.ValueKind != JsonValueKind.Object || value.GetProperty("version").GetInt32() != 1 || value.GetProperty("id").GetString() != id) throw new InvalidDataException();
        bool ok = value.GetProperty("ok").GetBoolean();
        string[] keys = value.EnumerateObject().Select(item => item.Name).Order(StringComparer.Ordinal).ToArray();
        if (ok)
        {
            if (!keys.SequenceEqual(new[] { "id", "ok", "result", "version" })) throw new InvalidDataException();
            JsonElement result = value.GetProperty("result");
            if (result.ValueKind != JsonValueKind.Object || result.GetProperty("state").GetString() is not ("unpaired" or "request-ready" or "configured")) throw new InvalidDataException();
            string[] fields = result.EnumerateObject().Select(item => item.Name).ToArray();
            if (fields.Distinct(StringComparer.Ordinal).Count() != fields.Length || fields.Length is < 3 or > 4 ||
                fields.Any(field => field is not ("state" or "displayName" or "fingerprint256" or "checked" or "cancelled"))) throw new InvalidDataException();
            if (result.GetProperty("state").GetString() == "unpaired")
            {
                if (result.GetProperty("displayName").ValueKind != JsonValueKind.Null || result.GetProperty("fingerprint256").ValueKind != JsonValueKind.Null) throw new InvalidDataException();
            }
            else
            {
                string fingerprint = result.GetProperty("fingerprint256").GetString() ?? throw new InvalidDataException();
                if (fingerprint.Length != 95 || fingerprint.Where((character, index) => index % 3 == 2 ? character != ':' : !char.IsAsciiHexDigitUpper(character)).Any()) throw new InvalidDataException();
                string suffix = " ブラウザ連携 · " + fingerprint.Replace(":", "", StringComparison.Ordinal)[..8];
                if (result.GetProperty("displayName").GetString() != "Chrome" + suffix && result.GetProperty("displayName").GetString() != "Edge" + suffix) throw new InvalidDataException();
            }
            if ((result.TryGetProperty("checked", out JsonElement checkedValue) && checkedValue.ValueKind != JsonValueKind.True) ||
                (result.TryGetProperty("cancelled", out JsonElement cancelled) && cancelled.ValueKind != JsonValueKind.True)) throw new InvalidDataException();
        }
        else if (!keys.SequenceEqual(new[] { "error", "id", "ok", "version" }) || value.GetProperty("error").GetString() != "UNAVAILABLE") throw new InvalidDataException();
        if (await stream.ReadAsync(new byte[1], cancellation) != 0) throw new InvalidDataException();
        byte[] frame = new byte[header.Length + payload.Length]; header.CopyTo(frame, 0); payload.CopyTo(frame, 4); return frame;
    }
}
