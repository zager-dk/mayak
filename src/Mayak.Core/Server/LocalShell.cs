using System.Diagnostics;
using System.Text;

namespace Mayak.Core.Server;

/// <summary>Команды выполняются прямо на этом сервере (агент Маяка работает от root).</summary>
public sealed class LocalShell : IShell
{
    private readonly string _tempDir;

    public LocalShell(string tempDir = "/var/lib/mayak/tmp")
    {
        _tempDir = tempDir;
    }

    public string Sudo { get; private set; } = "";
    public bool IsRoot { get; private set; }
    public string? ServerFingerprint => null;
    public string? JumpFingerprint => null;

    public void Connect()
    {
        IsRoot = Run("id -u", TimeSpan.FromSeconds(10)).Output.Trim() == "0";
        Sudo = IsRoot ? "" : "sudo -n ";
        Directory.CreateDirectory(_tempDir);
        File.SetUnixFileMode(_tempDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    public bool IsAlive() => true;

    public CommandResult Run(string command, TimeSpan? timeout = null)
    {
        var psi = new ProcessStartInfo("bash")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(command);
        using var p = Process.Start(psi) ?? throw new MayakException("Не удалось запустить bash");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeout ?? TimeSpan.FromMinutes(2)))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* уже завершился */ }
            throw new MayakException($"Команда не завершилась за {(timeout ?? TimeSpan.FromMinutes(2)).TotalMinutes:0} мин.");
        }
        return new CommandResult(p.ExitCode, stdout.Result, stderr.Result);
    }

    public string RunChecked(string command, string what, TimeSpan? timeout = null)
    {
        var r = Run(command, timeout);
        if (!r.Ok)
            throw new MayakException($"{what}: ошибка (код {r.ExitCode}).\n{SshConnection.Tail(r.Combined)}");
        return r.Output;
    }

    public string UploadTemp(string content, string suffix = "")
    {
        Directory.CreateDirectory(_tempDir);
        var path = Path.Combine(_tempDir, Guid.NewGuid().ToString("N") + suffix);
        File.WriteAllText(path, content.Replace("\r\n", "\n"), new UTF8Encoding(false));
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }

    public void WriteHostFile(string content, string remotePath, string mode = "644")
    {
        var tmp = UploadTemp(content);
        var dir = remotePath[..Math.Max(1, remotePath.LastIndexOf('/'))];
        RunChecked($"{Sudo}mkdir -p {SshConnection.Q(dir)} && {Sudo}cp {SshConnection.Q(tmp)} {SshConnection.Q(remotePath)} && {Sudo}chmod {mode} {SshConnection.Q(remotePath)}; rc=$?; rm -f {SshConnection.Q(tmp)}; exit $rc",
            $"Запись {remotePath}");
    }

    public CommandResult RunScript(string script, TimeSpan timeout)
    {
        var tmp = UploadTemp(script, ".sh");
        try
        {
            return Run($"bash {SshConnection.Q(tmp)}", timeout);
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* ignore */ }
        }
    }

    public void Dispose() { }
}
