using Mayak.Core.Models;
using Mayak.Core.Server;

namespace MayakVPN.ViewModels;

public sealed class UserItem : ObservableObject
{
    public VpnUser Model { get; }
    private readonly ServerSnapshot _snap;

    public UserItem(VpnUser model, ServerSnapshot snap)
    {
        Model = model;
        _snap = snap;
    }

    public string Name => Model.Name;
    public string Note => Model.Note;
    public bool Enabled => Model.Enabled;

    public int OnlineCount => Model.Devices.Count(d => _snap.StatsFor(d)?.IsOnline == true);

    public string Subtitle
    {
        get
        {
            if (!Model.Enabled) return "доступ приостановлен";
            var n = Model.Devices.Count;
            var dev = Format.Plural(n, "устройство", "устройства", "устройств");
            return OnlineCount > 0 ? $"{n} {dev} · в сети: {OnlineCount}" : $"{n} {dev}";
        }
    }

    public bool IsOnline => Model.Enabled && OnlineCount > 0;

    public void Refresh()
    {
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Note));
        OnPropertyChanged(nameof(Enabled));
        OnPropertyChanged(nameof(Subtitle));
        OnPropertyChanged(nameof(IsOnline));
    }
}

public sealed class DeviceItem : ObservableObject
{
    public VpnDevice Model { get; }
    public VpnUser Owner { get; }
    private readonly ServerSnapshot _snap;

    public DeviceItem(VpnDevice model, VpnUser owner, ServerSnapshot snap)
    {
        Model = model;
        Owner = owner;
        _snap = snap;
    }

    private PeerStats? Stats => _snap.StatsFor(Model);

    public string Name => Model.Name;
    public string Kind => Model.Kind.Title();
    public string Ip => Model.Ip;
    public string FileFormat => Model.Kind.DefaultFormat() == ConfigFormat.AwgConf ? ".conf" : ".vpn";
    public bool CanExport => Model.CanExport;

    public string Protocols => _snap.Xray != null && !string.IsNullOrEmpty(Model.XrayId) ? "AWG + Xray" : "AWG";

    public string Limit
    {
        get
        {
            if (Model.DownMbps <= 0 && Model.UpMbps <= 0) return "без ограничений";
            string D(int v) => v <= 0 ? "∞" : v.ToString();
            return Model.DownMbps == Model.UpMbps
                ? $"{D(Model.DownMbps)} Мбит/с"
                : $"↓{D(Model.DownMbps)} / ↑{D(Model.UpMbps)} Мбит/с";
        }
    }

    public string Status
    {
        get
        {
            if (!Owner.Enabled || !Model.Enabled) return "приостановлено";
            if (_snap.IsMissingOnServer(Model)) return "удалено вне Маяка";
            var s = Stats;
            if (s?.LatestHandshake == null) return "ещё не подключалось";
            if (s.IsOnline) return "в сети";
            return "был(о) " + Format.Ago(s.LatestHandshake.Value);
        }
    }

    public string StatusKind
    {
        get
        {
            if (!Owner.Enabled || !Model.Enabled) return "off";
            if (_snap.IsMissingOnServer(Model)) return "warn";
            return Stats?.IsOnline == true ? "on" : "idle";
        }
    }

    /// <summary>tx сервера = скачано клиентом, rx = отдано клиентом.</summary>
    public string Traffic
    {
        get
        {
            var s = Stats;
            if (s == null || (s.RxBytes == 0 && s.TxBytes == 0)) return "—";
            return $"↓ {Format.Bytes(s.TxBytes)}  ↑ {Format.Bytes(s.RxBytes)}";
        }
    }

    public string Created => Model.CreatedAt.ToLocalTime().ToString("dd.MM.yyyy");
}

public sealed class ForeignItem
{
    public ForeignPeer Model { get; }
    private readonly PeerStats? _stats;

    public ForeignItem(ForeignPeer model, PeerStats? stats)
    {
        Model = model;
        _stats = stats;
    }

    public string Name => Model.Name;
    public string Ip => Model.Ip;
    public string Key => Model.PublicKey.Length > 12 ? Model.PublicKey[..12] + "…" : Model.PublicKey;
    public string Status => _stats?.LatestHandshake is { } t
        ? (_stats.IsOnline ? "в сети" : "был(о) " + Format.Ago(t))
        : "не подключалось";
}

public static class Format
{
    public static string Plural(int n, string one, string few, string many)
    {
        n = Math.Abs(n) % 100;
        if (n is >= 11 and <= 14) return many;
        return (n % 10) switch
        {
            1 => one,
            2 or 3 or 4 => few,
            _ => many,
        };
    }

    public static string Bytes(long b)
    {
        string[] units = { "Б", "КБ", "МБ", "ГБ", "ТБ" };
        double v = b;
        int i = 0;
        while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
        return i == 0 ? $"{v:0} {units[i]}" : $"{v:0.#} {units[i]}";
    }

    public static string Ago(DateTime utc)
    {
        var d = DateTime.UtcNow - utc;
        if (d.TotalMinutes < 60) return $"{(int)Math.Max(1, d.TotalMinutes)} мин назад";
        if (d.TotalHours < 24) return $"{(int)d.TotalHours} ч назад";
        if (d.TotalDays < 30) return $"{(int)d.TotalDays} дн назад";
        return utc.ToLocalTime().ToString("dd.MM.yyyy");
    }
}

public sealed class CheckLineItem
{
    public Mayak.Core.Probe.CheckLine Model { get; }
    public CheckLineItem(Mayak.Core.Probe.CheckLine model) => Model = model;

    public string Protocol => Model.Protocol;
    public string Summary => Model.Summary;
    public string Details => Model.Details;
    public string Icon => Model.Status switch
    {
        Mayak.Core.Probe.CheckStatus.Ok => "✔",
        Mayak.Core.Probe.CheckStatus.Warn => "!",
        Mayak.Core.Probe.CheckStatus.Fail => "✖",
        _ => "–",
    };
    public string StatusKind => Model.Status switch
    {
        Mayak.Core.Probe.CheckStatus.Ok => "on",
        Mayak.Core.Probe.CheckStatus.Warn => "warn",
        Mayak.Core.Probe.CheckStatus.Fail => "off",
        _ => "idle",
    };
}

public sealed class CheckHistoryItem
{
    public Mayak.Core.Probe.CheckReport Model { get; }
    public CheckHistoryItem(Mayak.Core.Probe.CheckReport model) => Model = model;

    public string When => Model.At.ToString("dd.MM HH:mm");
    public string Network => string.IsNullOrWhiteSpace(Model.NetworkLabel) ? Model.ClientAddress : $"{Model.NetworkLabel} ({Model.ClientAddress})";
    public string Results => string.Join("   ", Model.Lines.Select(l => $"{Short(l.Protocol)}: {Mark(l.Status)}"));

    private static string Short(string protocol) => protocol.StartsWith("AmneziaWG") ? "AWG" : protocol.StartsWith("VLESS") || protocol.StartsWith("Xray") ? "Xray" : protocol;

    private static string Mark(Mayak.Core.Probe.CheckStatus s) => s switch
    {
        Mayak.Core.Probe.CheckStatus.Ok => "✔ работает",
        Mayak.Core.Probe.CheckStatus.Warn => "! частично",
        Mayak.Core.Probe.CheckStatus.Fail => "✖ нет",
        _ => "—",
    };
}
