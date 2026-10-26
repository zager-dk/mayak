using System.Security.Cryptography;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace Mayak.Core.Server;

/// <summary>Данные для входа на сервер по SSH.</summary>
public sealed class SshCredentials
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 22;
    public string User { get; set; } = "root";
    public string? Password { get; set; }
    public string? PrivateKeyPath { get; set; }
    public string? PrivateKeyPassphrase { get; set; }

    /// <summary>SHA256-отпечаток ключа сервера, сохранённый при первом подключении (TOFU).</summary>
    public string? KnownHostFingerprint { get; set; }
}

public sealed record CommandResult(int ExitCode, string Output, string Error)
{
    public bool Ok => ExitCode == 0;
    public string Combined => string.IsNullOrWhiteSpace(Error) ? Output : (Output + "\n" + Error).Trim();
}

public class MayakException : Exception
{
    public MayakException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Обёртка над SSH.NET: команды, загрузка файлов, sudo.</summary>
public sealed class SshConnection : IDisposable
{
    private readonly SshCredentials _creds;
    private SshClient? _ssh;
    private SftpClient? _sftp;

    /// <summary>Отпечаток ключа сервера, который увидели при подключении.</summary>
    public string? ServerFingerprint { get; private set; }

    /// <summary>Пусто для root, «sudo -n » для остальных.</summary>
    public string Sudo { get; private set; } = "";

    public bool IsRoot { get; private set; }

    public SshConnection(SshCredentials creds) => _creds = creds;

    public void Connect()
    {
        var info = CreateConnectionInfo();
        _ssh = new SshClient(info);
        _ssh.HostKeyReceived += OnHostKey;
        _ssh.KeepAliveInterval = TimeSpan.FromSeconds(20);
        try
        {
            _ssh.Connect();
        }
        catch (SshAuthenticationException ex)
        {
            throw new MayakException("Сервер не принял логин, пароль или ключ.", ex);
        }
        catch (Exception ex) when (_hostKeyMismatch)
        {
            throw new MayakException("Отпечаток ключа сервера изменился. Если вы переустанавливали систему на сервере — нажмите «Сбросить отпечаток» в настройках сервера. Иначе возможна подмена сервера.", ex);
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            throw new MayakException($"Не удалось подключиться к {_creds.Host}:{_creds.Port} — {ex.Message}", ex);
        }
        catch (SshOperationTimeoutException ex)
        {
            throw new MayakException($"Сервер {_creds.Host}:{_creds.Port} не ответил вовремя.", ex);
        }

        var who = Run("whoami", TimeSpan.FromSeconds(20)).Output.Trim();
        IsRoot = who == "root";
        Sudo = IsRoot ? "" : "sudo -n ";
        if (!IsRoot)
        {
            var check = Run("sudo -n true", TimeSpan.FromSeconds(20));
            if (!check.Ok)
                throw new MayakException($"Пользователь «{who}» не может выполнять sudo без пароля. Подключайтесь под root или добавьте в sudoers строку «{who} ALL=(ALL) NOPASSWD:ALL».");
        }

        // Убираем временные файлы, оставшиеся от прерванных операций
        Run("find ~ -maxdepth 1 -name '.mayak_*' -mmin +30 -delete 2>/dev/null", TimeSpan.FromSeconds(20));
    }

    private bool _hostKeyMismatch;

    private void OnHostKey(object? sender, HostKeyEventArgs e)
    {
        var fp = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
        ServerFingerprint = fp;
        if (string.IsNullOrEmpty(_creds.KnownHostFingerprint) || _creds.KnownHostFingerprint == fp)
        {
            e.CanTrust = true;
        }
        else
        {
            _hostKeyMismatch = true;
            e.CanTrust = false;
        }
    }

    private ConnectionInfo CreateConnectionInfo()
    {
        var methods = new List<AuthenticationMethod>();
        if (!string.IsNullOrWhiteSpace(_creds.PrivateKeyPath))
        {
            if (!File.Exists(_creds.PrivateKeyPath))
                throw new MayakException($"Файл ключа не найден: {_creds.PrivateKeyPath}");
            var key = string.IsNullOrEmpty(_creds.PrivateKeyPassphrase)
                ? new PrivateKeyFile(_creds.PrivateKeyPath)
                : new PrivateKeyFile(_creds.PrivateKeyPath, _creds.PrivateKeyPassphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(_creds.User, key));
        }
        if (!string.IsNullOrEmpty(_creds.Password))
        {
            methods.Add(new PasswordAuthenticationMethod(_creds.User, _creds.Password));
            var kbd = new KeyboardInteractiveAuthenticationMethod(_creds.User);
            kbd.AuthenticationPrompt += (_, args) =>
            {
                foreach (var prompt in args.Prompts) prompt.Response = _creds.Password;
            };
            methods.Add(kbd);
        }
        if (methods.Count == 0)
            throw new MayakException("Укажите пароль или файл SSH-ключа.");

        return new ConnectionInfo(_creds.Host, _creds.Port, _creds.User, methods.ToArray())
        {
            Timeout = TimeSpan.FromSeconds(20),
            Encoding = Encoding.UTF8,
        };
    }

    private SshClient Ssh => _ssh is { IsConnected: true } ? _ssh : throw new MayakException("Нет подключения к серверу.");

    /// <summary>Выполняет команду. Код возврата, stdout, stderr.</summary>
    public CommandResult Run(string command, TimeSpan? timeout = null)
    {
        using var cmd = Ssh.CreateCommand(command);
        cmd.CommandTimeout = timeout ?? TimeSpan.FromMinutes(2);
        string output;
        try
        {
            output = cmd.Execute();
        }
        catch (SshOperationTimeoutException ex)
        {
            throw new MayakException($"Команда не завершилась за {cmd.CommandTimeout.TotalMinutes:0} мин.", ex);
        }
        object? status = cmd.ExitStatus;
        int code = status is int i ? i : -1;
        return new CommandResult(code, output ?? "", cmd.Error ?? "");
    }

    /// <summary>Выполняет и бросает исключение при ненулевом коде.</summary>
    public string RunChecked(string command, string what, TimeSpan? timeout = null)
    {
        var r = Run(command, timeout);
        if (!r.Ok)
            throw new MayakException($"{what}: ошибка (код {r.ExitCode}).\n{Tail(r.Combined)}");
        return r.Output;
    }

    private SftpClient Sftp
    {
        get
        {
            if (_sftp is { IsConnected: true }) return _sftp;
            _sftp?.Dispose();
            _sftp = new SftpClient(CreateConnectionInfo());
            _sftp.HostKeyReceived += (_, e) =>
            {
                var fp = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
                e.CanTrust = fp == ServerFingerprint;
            };
            _sftp.Connect();
            return _sftp;
        }
    }

    /// <summary>Загружает файл во временную папку домашнего каталога с правами 600 и возвращает абсолютный путь.</summary>
    public string UploadTemp(string content, string suffix = "")
    {
        var sftp = Sftp;
        var dir = sftp.WorkingDirectory.TrimEnd('/');
        var path = $"{dir}/.mayak_{Guid.NewGuid():N}{suffix}";
        using (var ms = new MemoryStream(new UTF8Encoding(false).GetBytes(content.Replace("\r\n", "\n"))))
        {
            sftp.UploadFile(ms, path, canOverride: true);
        }
        sftp.ChangePermissions(path, 600); // SSH.NET ждёт восьмеричные цифры: 600 = rw-------
        return path;
    }

    /// <summary>Загружает текст в файл на хосте (через временный файл и sudo).</summary>
    public void WriteHostFile(string content, string remotePath, string mode = "644")
    {
        var tmp = UploadTemp(content);
        var dir = remotePath[..Math.Max(1, remotePath.LastIndexOf('/'))];
        RunChecked($"{Sudo}mkdir -p {Q(dir)} && {Sudo}cp {Q(tmp)} {Q(remotePath)} && {Sudo}chmod {mode} {Q(remotePath)}; rc=$?; rm -f {Q(tmp)}; exit $rc",
            $"Запись {remotePath}");
    }

    /// <summary>Загружает и выполняет bash-скрипт.</summary>
    public CommandResult RunScript(string script, TimeSpan timeout)
    {
        var tmp = UploadTemp(script, ".sh");
        try
        {
            return Run($"bash {Q(tmp)}", timeout);
        }
        finally
        {
            Run($"rm -f {Q(tmp)}");
        }
    }

    /// <summary>Строку в одинарные кавычки для sh.</summary>
    public static string Q(string s) => "'" + s.Replace("'", "'\"'\"'") + "'";

    public static string Tail(string text, int lines = 15)
    {
        var arr = text.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        return string.Join("\n", arr.Skip(Math.Max(0, arr.Length - lines)));
    }

    public void Dispose()
    {
        try { _sftp?.Disconnect(); } catch { /* ignore */ }
        _sftp?.Dispose();
        try { _ssh?.Disconnect(); } catch { /* ignore */ }
        _ssh?.Dispose();
    }
}
