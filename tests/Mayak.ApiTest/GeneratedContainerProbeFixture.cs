using System.Diagnostics;
using Mayak.Core.Server;

// Executes only the actual container command emitted by InspectConnected.
// PATH contains this disposable fixture's sh/sudo/docker/podman stubs only.
sealed class GeneratedContainerProbeFixture : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "mayak-container-probe-" + Guid.NewGuid().ToString("N"));
    private readonly string shell = Environment.GetEnvironmentVariable("MAYAK_TEST_BASH") ??
        (OperatingSystem.IsWindows() ? @"C:\Program Files\Git\bin\bash.exe" : "/bin/sh");
    public CommandResult? Result { get; private set; }
    public string? Command { get; private set; }
    public bool SudoUsed => File.Exists(Path.Combine(directory, "sudo-used"));

    public GeneratedContainerProbeFixture(string mode)
    {
        Directory.CreateDirectory(directory);
        Write("sh", "#!/bin/sh\nexec /bin/sh \"$@\"\n");
        Write("sudo", "#!/bin/sh\n[ \"$1\" = -n ] || exit 76\nshift\nprintf 'sudo\\n' >> \"$FIXTURE_SUDO_LOG\"\n" +
            (mode == "sudo-denied" ? "exit 79\n" : "exec \"$@\"\n"));
        if (mode is "empty-tools" or "occupied" or "docker-denied")
            Write("docker", "#!/bin/sh\n[ \"$1\" = ps ] && [ \"$2\" = -aq ] || exit 75\n" +
                (mode == "docker-denied" ? "exit 77\n" : mode == "occupied" ? "printf 'fixture-container-id\\n'\n" : "exit 0\n"));
        if (mode is "empty-tools" or "podman-denied")
            Write("podman", "#!/bin/sh\n[ \"$1\" = ps ] && [ \"$2\" = -aq ] || exit 75\n" +
                (mode == "podman-denied" ? "exit 78\n" : "exit 0\n"));
    }

    private void Write(string name, string text)
    {
        var path = Path.Combine(directory, name);
        File.WriteAllText(path, text, new System.Text.UTF8Encoding(false));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private static string ShellPath(string path) => OperatingSystem.IsWindows()
        ? "/" + char.ToLowerInvariant(path[0]) + path[2..].Replace('\\', '/') : path;

    public CommandResult Run(string command)
    {
        if (!command.Contains("for r in docker podman", StringComparison.Ordinal))
            throw new InvalidOperationException("Fixture only permits the container read-only command");
        Command = command;
        var start = new ProcessStartInfo(shell)
        {
            UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = directory,
        };
        if (OperatingSystem.IsWindows())
        {
            start.ArgumentList.Add("--noprofile");
            start.ArgumentList.Add("--norc");
        }
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(command);
        start.Environment["PATH"] = ShellPath(directory);
        start.Environment["FIXTURE_SUDO_LOG"] = ShellPath(Path.Combine(directory, "sudo-used"));
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Fixture shell failed to start");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(10000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException("Generated container probe fixture timed out");
        }
        Result = new CommandResult(process.ExitCode, output.GetAwaiter().GetResult(), error.GetAwaiter().GetResult());
        return Result;
    }

    public void Dispose() => Directory.Delete(directory, recursive: true);
}
