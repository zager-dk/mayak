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

    /// <summary>
    /// Промежуточный сервер: Маяк подключается к нему, а оттуда SSH-туннелем к этому серверу
    /// (как ssh -J). Шифрование сквозное — промежуточный сервер видит только зашифрованный поток.
    /// </summary>
    public SshCredentials? Jump { get; set; }
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

/// <summary>
/// Где выполняются команды сервера: по SSH с компьютера администратора (Маяк для Windows)
/// или прямо на сервере (агент). Логика установки и управления одна и та же.
/// </summary>
public interface IShell : IDisposable
{
    /// <summary>Пусто для root, «sudo -n » для остальных.</summary>
    string Sudo { get; }
    bool IsRoot { get; }
    string? ServerFingerprint { get; }
    string? JumpFingerprint { get; }
    void Connect();
    bool IsAlive();
    CommandResult Run(string command, TimeSpan? timeout = null);
    string RunChecked(string command, string what, TimeSpan? timeout = null);
    string UploadTemp(string content, string suffix = "");
    void WriteHostFile(string content, string remotePath, string mode = "644");
    CommandResult RunScript(string script, TimeSpan timeout);
}

/// <summary>Обёртка над SSH.NET: команды, загрузка файлов, sudo.</summary>
public sealed class SshConnection : IShell
{
    private readonly SshCredentials _creds;
    private SshClient? _ssh;
    private SftpClient? _sftp;
    private SshClient? _jump;
    private ForwardedPortLocal? _forward;
    private string? _forwardError;
    private string _connectHost;
    private int _connectPort;

    /// <summary>Отпечаток ключа сервера, который увидели при подключении.</summary>
    public string? ServerFingerprint { get; private set; }

    /// <summary>Отпечаток ключа промежуточного сервера (если подключались через него).</summary>
    public string? JumpFingerprint { get; private set; }

    /// <summary>Пусто для root, «sudo -n » для остальных.</summary>
    public string Sudo { get; private set; } = "";

    public bool IsRoot { get; private set; }

    public SshConnection(SshCredentials creds)
    {
        _creds = creds;
        _connectHost = creds.Host;
        _connectPort = creds.Port;
    }

    public void Connect()
    {
        if (_creds.Jump != null) OpenJump(_creds.Jump);
        var info = CreateConnectionInfo(_creds, _connectHost, _connectPort);
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
        catch (Exception ex) when (_creds.Jump is { } j && ex is not MayakException)
        {
            // Канал открывается на промежуточном сервере: ошибка там почти всегда значит, что он не видит этот сервер.
            throw new MayakException(
                $"Промежуточный сервер {j.Host} не смог соединиться с {_creds.Host}:{_creds.Port}" +
                (string.IsNullOrEmpty(_forwardError) ? "." : $" ({_forwardError}).") +
                $"\n\nПроверьте в консоли промежуточного сервера:\ntimeout 5 bash -c \"</dev/tcp/{_creds.Host}/{_creds.Port}\" && echo OK || echo FAIL\n\n" +
                "FAIL — IP этого сервера блокируется и из дата-центра промежуточного сервера.", ex);
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
        Run("find ~ -maxdepth 1 -name '.mayak_*' -type f -mmin +30 -delete 2>/dev/null; find ~/.mayak_tmp -type f -mmin +30 -delete 2>/dev/null; true", TimeSpan.FromSeconds(20));
    }

    private bool _hostKeyMismatch;

    /// <summary>Подключается к промежуточному серверу и открывает локальный порт, ведущий к целевому SSH.</summary>
    private void OpenJump(SshCredentials j)
    {
        bool mismatch = false;
        _jump = new SshClient(CreateConnectionInfo(j, j.Host, j.Port));
        _jump.HostKeyReceived += (_, e) =>
        {
            var fp = Fingerprint(e.HostKey);
            JumpFingerprint = fp;
            e.CanTrust = string.IsNullOrEmpty(j.KnownHostFingerprint) || j.KnownHostFingerprint == fp;
            mismatch = !e.CanTrust;
        };
        _jump.KeepAliveInterval = TimeSpan.FromSeconds(20);
        try
        {
            _jump.Connect();
        }
        catch (SshAuthenticationException ex)
        {
            throw new MayakException($"Промежуточный сервер {j.Host} не принял логин, пароль или ключ.", ex);
        }
        catch (Exception ex) when (mismatch)
        {
            throw new MayakException($"Отпечаток ключа промежуточного сервера {j.Host} изменился. Если система на нём переустанавливалась — сбросьте отпечаток в его настройках.", ex);
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or SshOperationTimeoutException or SshConnectionException)
        {
            throw new MayakException($"Не удалось подключиться к промежуточному серверу {j.Host}:{j.Port} — {ex.Message}", ex);
        }

        _forward = new ForwardedPortLocal("127.0.0.1", 0, _creds.Host, (uint)_creds.Port);
        _forward.Exception += (_, e) => _forwardError = e.Exception.Message;
        _jump.AddForwardedPort(_forward);
        _forward.Start();
        _connectHost = "127.0.0.1";
        _connectPort = (int)_forward.BoundPort;
    }

    private static string Fingerprint(byte[] hostKey) => "SHA256:" + Convert.ToBase64String(SHA256.HashData(hostKey)).TrimEnd('=');

    private void OnHostKey(object? sender, HostKeyEventArgs e)
    {
        var fp = Fingerprint(e.HostKey);
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

    private static ConnectionInfo CreateConnectionInfo(SshCredentials c, string host, int port)
    {
        var methods = new List<AuthenticationMethod>();
        if (!string.IsNullOrWhiteSpace(c.PrivateKeyPath))
        {
            if (!File.Exists(c.PrivateKeyPath))
                throw new MayakException($"Файл ключа не найден: {c.PrivateKeyPath}");
            var key = string.IsNullOrEmpty(c.PrivateKeyPassphrase)
                ? new PrivateKeyFile(c.PrivateKeyPath)
                : new PrivateKeyFile(c.PrivateKeyPath, c.PrivateKeyPassphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(c.User, key));
        }
        if (!string.IsNullOrEmpty(c.Password))
        {
            methods.Add(new PasswordAuthenticationMethod(c.User, c.Password));
            var kbd = new KeyboardInteractiveAuthenticationMethod(c.User);
            kbd.AuthenticationPrompt += (_, args) =>
            {
                foreach (var prompt in args.Prompts) prompt.Response = c.Password;
            };
            methods.Add(kbd);
        }
        if (methods.Count == 0)
            throw new MayakException($"Укажите пароль или файл SSH-ключа для {c.Host}.");

        return new ConnectionInfo(host, port, c.User, methods.ToArray())
        {
            Timeout = TimeSpan.FromSeconds(20),
            Encoding = Encoding.UTF8,
        };
    }

    private SshClient Ssh => _ssh is { IsConnected: true } && (_jump == null || _jump.IsConnected) ? _ssh : throw new MayakException("Связь с сервером по SSH потеряна. Нажмите «Обновить» — Маяк подключится заново.");

    /// <summary>Жива ли SSH-сессия (быстрая команда; после смены сети TCP-сессия часто «висит»).</summary>
    public bool IsAlive()
    {
        if (_ssh is not { IsConnected: true }) return false;
        if (_jump is { IsConnected: false }) return false;
        try
        {
            return Run("true", TimeSpan.FromSeconds(8)).Ok;
        }
        catch (Exception)
        {
            return false;
        }
    }

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
            _sftp = new SftpClient(CreateConnectionInfo(_creds, _connectHost, _connectPort));
            _sftp.HostKeyReceived += (_, e) => e.CanTrust = Fingerprint(e.HostKey) == ServerFingerprint;
            _sftp.Connect();
            return _sftp;
        }
    }

    private string? _tempDir;

    /// <summary>
    /// Загружает текст во временный файл в закрытой папке ~/.mayak_tmp (права 700) и возвращает абсолютный путь.
    /// Права выставляются командой mkdir, а не через SFTP: так не зависим от особенностей SFTP-сервера.
    /// </summary>
    public string UploadTemp(string content, string suffix = "")
    {
        var sftp = Sftp;
        if (_tempDir == null)
        {
            var home = sftp.WorkingDirectory.TrimEnd('/');
            var dir = $"{home}/.mayak_tmp";
            RunChecked($"mkdir -p {Q(dir)} && chmod 700 {Q(dir)}", "Создание временной папки");
            _tempDir = dir;
        }
        var path = $"{_tempDir}/{Guid.NewGuid():N}{suffix}";
        using (var ms = new MemoryStream(new UTF8Encoding(false).GetBytes(content.Replace("\r\n", "\n"))))
        {
            sftp.UploadFile(ms, path, canOverride: true);
        }
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
        try { _forward?.Stop(); } catch { /* ignore */ }
        try { _jump?.Disconnect(); } catch { /* ignore */ }
        _jump?.Dispose();
    }
}
