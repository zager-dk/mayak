using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Mayak.Core.Models;
using Mayak.Core.Probe;
using Mayak.Core.Server;
using MayakVPN.Services;

namespace MayakVPN.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly IUi _ui;
    private readonly AppSettings _settings;
    private readonly DispatcherTimer _autoRefresh;
    private MayakServer? _server;
    private Guid? _connectedProfileId;

    public MainViewModel(IUi ui)
    {
        _ui = ui;
        _settings = ProfileStore.Load();
        Servers = new ObservableCollection<ServerProfile>(_settings.Servers);
        MigrateProfiles();
        Foreign.CollectionChanged += (_, _) => OnPropertyChanged(nameof(ForeignBannerText));

        AddServerCommand = new RelayCommand(AddServer, () => !IsBusy);
        EditServerCommand = new RelayCommand(EditServer, () => !IsBusy && SelectedServer != null);
        RemoveServerCommand = new RelayCommand(RemoveServer, () => !IsBusy && SelectedServer != null);
        RefreshCommand = new RelayCommand(() => _ = ReloadAsync(), () => !IsBusy && SelectedServer != null);

        InstallCommand = new RelayCommand(() => _ = InstallAsync(), () => !IsBusy && SelectedServer != null);
        StartCommand = new RelayCommand(() => _ = RunAsync("Запуск контейнера…", s => s.StartContainer(), reload: true), () => !IsBusy && State == ServerState.Stopped);
        RestartCommand = new RelayCommand(() => _ = RunAsync("Перезапуск…", s => s.RestartContainer(), reload: true), () => !IsBusy && IsInstalled);
        UninstallCommand = new RelayCommand(() => _ = UninstallAsync(), () => !IsBusy && IsInstalled);
        SaveSettingsCommand = new RelayCommand(() => _ = SaveSettingsAsync(), () => !IsBusy && Snapshot != null);

        AddUserCommand = new RelayCommand(() => _ = AddUserAsync(), () => !IsBusy && Snapshot != null);
        EditUserCommand = new RelayCommand(() => _ = EditUserAsync(), () => !IsBusy && SelectedUser != null);
        ToggleUserCommand = new RelayCommand(() => _ = ToggleUserAsync(), () => !IsBusy && SelectedUser != null);
        DeleteUserCommand = new RelayCommand(() => _ = DeleteUserAsync(), () => !IsBusy && SelectedUser != null);

        AddDeviceCommand = new RelayCommand(() => _ = AddDeviceAsync(), () => !IsBusy && SelectedUser != null);
        EditDeviceCommand = new RelayCommand(() => _ = EditDeviceAsync(), () => !IsBusy && SelectedDevice != null);
        ToggleDeviceCommand = new RelayCommand(() => _ = ToggleDeviceAsync(), () => !IsBusy && SelectedDevice != null);
        DeleteDeviceCommand = new RelayCommand(() => _ = DeleteDeviceAsync(), () => !IsBusy && SelectedDevice != null);
        ShareDeviceCommand = new RelayCommand(ShareDevice, () => SelectedDevice?.CanExport == true && Snapshot != null);

        RevokeForeignCommand = new RelayCommand(() => _ = RevokeForeignAsync(), () => !IsBusy && SelectedForeign != null);
        AdoptForeignCommand = new RelayCommand(() => _ = AdoptForeignAsync(), () => !IsBusy && SelectedForeign != null && Users.Count > 0);

        SetupRelayCommand = new RelayCommand(() => _ = SetupRelayAsync(), () => !IsBusy && Snapshot != null);
        RemoveRelayCommand = new RelayCommand(() => _ = RemoveRelayAsync(), () => !IsBusy && SelectedServer?.RelayProfileId != null);
        InstallXrayCommand = new RelayCommand(() => _ = InstallXrayAsync(), () => !IsBusy && Snapshot != null);
        UninstallXrayCommand = new RelayCommand(() => _ = UninstallXrayAsync(), () => !IsBusy && Snapshot?.Xray != null);
        RunCheckCommand = new RelayCommand(() => _ = RunCheckAsync(), () => !IsBusy && !CheckRunning && (Snapshot != null || OfflineKit != null));
        CancelCheckCommand = new RelayCommand(() => _checkCts?.Cancel(), () => CheckRunning);

        CheckAddressCommand = new RelayCommand(() => _ui.ShowAddressCheck(SelectedServer?.IsRelay == false ? SelectedServer.Host : null));
        ToggleForeignCommand = new RelayCommand(() => ShowForeign = !ShowForeign);
        OpenExportFolderCommand = new RelayCommand(OpenExportFolder);
        ChangeExportFolderCommand = new RelayCommand(ChangeExportFolder);
        ClearLogCommand = new RelayCommand(() => LogLines.Clear());

        _autoRefresh = new DispatcherTimer { Interval = TimeSpan.FromSeconds(60) };
        _autoRefresh.Tick += (_, _) =>
        {
            if (!IsBusy && Snapshot != null && Application.Current.Windows.Count == 1)
                _ = ReloadAsync(quiet: true);
        };
        _autoRefresh.Start();

        var last = Servers.FirstOrDefault(s => s.Id == _settings.LastServerId) ?? Servers.FirstOrDefault();
        if (last != null) SelectedServer = last;
    }

    // ───────────── Свойства ─────────────

    public ObservableCollection<ServerProfile> Servers { get; }
    public ObservableCollection<UserItem> Users { get; } = new();
    public ObservableCollection<DeviceItem> Devices { get; } = new();
    public ObservableCollection<ForeignItem> Foreign { get; } = new();
    public ObservableCollection<string> LogLines { get; } = new();
    public ObservableCollection<string> Warnings { get; } = new();

    private ServerProfile? _selectedServer;
    public ServerProfile? SelectedServer
    {
        get => _selectedServer;
        set
        {
            if (!Set(ref _selectedServer, value)) return;
            DisconnectServer();
            ClearData();
            if (value != null)
            {
                _settings.LastServerId = value.Id;
                SaveSettingsFile();
                LoadCheckHistory();
                OfflineKit = value.IsRelay ? null : CheckKitStore.Load(value.Id);
                _ = ReloadAsync();
            }
            OnPropertyChanged(nameof(HasServer));
            OnPropertyChanged(nameof(IsRelayProfile));
            OnPropertyChanged(nameof(RelayText));
        }
    }

    public bool IsRelayProfile => SelectedServer?.IsRelay == true;

    public string RelayText
    {
        get
        {
            var p = SelectedServer;
            if (p == null) return "";
            var jump = JumpOf(p);
            var jumpText = jump == null ? "" : $" Маяк подключается к серверу через «{jump.Name}» (SSH-туннель).";
            if (p.RelayProfileId == null) return "Не настроен — пользователи подключаются к серверу напрямую." + jumpText;
            var relay = Servers.FirstOrDefault(s => s.Id == p.RelayProfileId);
            return $"Пользователи входят через «{relay?.Name ?? p.RelayHost}» ({p.RelayHost})." + jumpText;
        }
    }

    private string _relayStatusText = "";
    public string RelayStatusText { get => _relayStatusText; private set => Set(ref _relayStatusText, value); }

    public bool HasServer => SelectedServer != null;

    private CheckKit? _offlineKit;
    /// <summary>Сохранённые на компьютере данные для «Проверки» без SSH.</summary>
    private CheckKit? OfflineKit
    {
        get => _offlineKit;
        set
        {
            _offlineKit = value;
            OnPropertyChanged(nameof(ShowTabs));
            OnPropertyChanged(nameof(OfflineCheckText));
            CommandManager.InvalidateRequerySuggested();
        }
    }

    /// <summary>Вкладки видны и без SSH, если есть сохранённые данные для «Проверки».</summary>
    public bool ShowTabs => IsInstalled || (State == null && !IsRelayProfile && OfflineKit != null);

    private int _tabIndex;
    public int TabIndex { get => _tabIndex; set => Set(ref _tabIndex, value); }
    private const int CheckTab = 1;

    /// <summary>Подсказка на «Проверке», когда SSH недоступен.</summary>
    public string OfflineCheckText => Snapshot == null && OfflineKit != null
        ? $"Нет связи с сервером по SSH — проверка пойдёт по данным, сохранённым {OfflineKit.SavedUtc.ToLocalTime():dd.MM HH:mm}."
        : "";

    private bool _showForeign;
    public bool ShowForeign
    {
        get => _showForeign;
        set { Set(ref _showForeign, value); OnPropertyChanged(nameof(ForeignToggleText)); }
    }
    public string ForeignToggleText => ShowForeign ? "Скрыть" : "Показать";
    public string ForeignBannerText => Foreign.Count == 0 ? "" :
        $"На сервере {Foreign.Count} {Format.Plural(Foreign.Count, "подключение", "подключения", "подключений")} из приложения AmneziaVPN — не привязаны к пользователям.";

    public string UserTitle => SelectedUser?.Name ?? "Выберите пользователя";
    public bool HasSelectedUser => SelectedUser != null;

    /// <summary>Проверка адреса: с этого компьютера и со всех входных серверов из списка.</summary>
    public async Task<Mayak.Core.Probe.AddressCheckReport> CheckAddressAsync(string host, IProgress<string> progress, CancellationToken ct)
    {
        var relays = Servers.Where(s => s.IsRelay).Select(r => (Profile: r, Creds: CredsFor(r))).ToList();
        progress.Report(relays.Count == 0 ? "Проверяю с этого компьютера…" : $"Проверяю с этого компьютера и с {string.Join(", ", relays.Select(r => "«" + r.Profile.Name + "»"))}…");
        var local = AddressCheck.FromThisComputerAsync(host, AddressCheck.DefaultPorts, ct);
        var remote = relays.Select(r => Task.Run(() =>
        {
            try
            {
                using var relay = new RelayServer(r.Creds);
                relay.Connect();
                RememberFingerprint(r.Profile, relay.Fingerprint);
                return relay.CheckAddress(r.Profile.Name, host, AddressCheck.DefaultPorts);
            }
            catch (Exception ex)
            {
                return new VantageResult { Name = r.Profile.Name, Failure = "нет связи со входом по SSH: " + FirstLine(ex.Message) };
            }
        }, ct)).ToList();
        var localResult = await local;
        var remoteResults = await Task.WhenAll(remote);
        var report = AddressCheck.Build(host, localResult, remoteResults);
        AppendLog($"Проверка адреса {host}: {report.VerdictTitle}");
        return report;
    }

    private ServerSnapshot? _snapshot;
    public ServerSnapshot? Snapshot
    {
        get => _snapshot;
        private set
        {
            Set(ref _snapshot, value);
            OnPropertyChanged(nameof(IsInstalled));
            OnPropertyChanged(nameof(EndpointText));
            OnPropertyChanged(nameof(ProtocolText));
            OnPropertyChanged(nameof(SummaryText));
            OnPropertyChanged(nameof(XrayStateText));
            OnPropertyChanged(nameof(XrayEndpointText));
            OnPropertyChanged(nameof(XrayButtonText));
            OnPropertyChanged(nameof(HasXray));
            OnPropertyChanged(nameof(OfflineCheckText));
        }
    }

    public bool HasXray => Snapshot?.Xray != null;

    public string XrayStateText => Snapshot == null ? "—" : Snapshot.Xray != null ? "Работает" : Snapshot.XrayState switch
    {
        ServerState.Stopped => "Остановлен",
        ServerState.Running => "Запущен, но не настроен",
        _ => "Не установлен",
    };

    public string XrayEndpointText => Snapshot?.Xray is { } x ? $"{x.Title} · TCP {x.Port} · маскировка под {x.Sni}" : "—";

    public string XrayButtonText => Snapshot?.Xray != null ? "Переустановить Xray…" : "Установить Xray…";

    private ServerState? _state;
    public ServerState? State
    {
        get => _state;
        private set
        {
            Set(ref _state, value);
            OnPropertyChanged(nameof(IsInstalled));
            OnPropertyChanged(nameof(ShowTabs));
            OnPropertyChanged(nameof(StateText));
            OnPropertyChanged(nameof(InstallButtonText));
            OnPropertyChanged(nameof(NeedsInstall));
        }
    }

    public bool IsInstalled => State is ServerState.Running or ServerState.Stopped;
    public bool NeedsInstall => State is ServerState.Clean or ServerState.DockerOnly;

    public string StateText => IsRelayProfile ? "Входной сервер (каскад)" : State switch
    {
        ServerState.Running => "Работает",
        ServerState.Stopped => "Остановлен",
        ServerState.DockerOnly => "VPN не установлен",
        ServerState.Clean => "Чистый сервер — VPN не установлен",
        _ => "Нет подключения",
    };

    public string InstallButtonText => IsInstalled ? "Переустановить VPN…" : "Установить VPN…";

    public string EndpointText => Snapshot == null ? "—" : $"{Snapshot.Endpoint.Host} : {Snapshot.Endpoint.Port} (UDP)";

    public string ProtocolText => Snapshot == null ? "—" : $"AmneziaWG {Snapshot.Endpoint.Parameters.ProtocolVersionString}";

    public string SummaryText
    {
        get
        {
            if (Snapshot == null) return "";
            var users = Snapshot.Db.Users.Count;
            var devices = Snapshot.Db.AllDevices.Count();
            var online = Snapshot.Db.AllDevices.Count(d => Snapshot.StatsFor(d)?.IsOnline == true);
            return $"{users} {Format.Plural(users, "пользователь", "пользователя", "пользователей")} · " +
                   $"{devices} {Format.Plural(devices, "устройство", "устройства", "устройств")} · в сети: {online}";
        }
    }

    private UserItem? _selectedUser;
    public UserItem? SelectedUser
    {
        get => _selectedUser;
        set
        {
            if (Set(ref _selectedUser, value)) RebuildDevices();
            OnPropertyChanged(nameof(ToggleUserText));
            OnPropertyChanged(nameof(UserTitle));
            OnPropertyChanged(nameof(HasSelectedUser));
            OnPropertyChanged(nameof(DevicesHeader));
        }
    }

    public string ToggleUserText => SelectedUser?.Enabled == false ? "Включить доступ" : "Приостановить";

    public string DevicesHeader => SelectedUser == null ? "Устройства" : $"Устройства: {SelectedUser.Name}";

    public string ToggleDeviceText =>
        SelectedDevice != null && (!SelectedDevice.Model.Enabled || (Snapshot?.IsMissingOnServer(SelectedDevice.Model) ?? false))
            ? "Включить" : "Приостановить";

    private DeviceItem? _selectedDevice;
    public DeviceItem? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            Set(ref _selectedDevice, value);
            OnPropertyChanged(nameof(ToggleDeviceText));
        }
    }

    private ForeignItem? _selectedForeign;
    public ForeignItem? SelectedForeign
    {
        get => _selectedForeign;
        set => Set(ref _selectedForeign, value);
    }

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            Set(ref _isBusy, value);
            if (!value) BusyText = "";
            CommandManager.InvalidateRequerySuggested();
        }
    }

    private string _busyText = "";
    public string BusyText { get => _busyText; private set => Set(ref _busyText, value); }

    private string _statusText = "Добавьте сервер, чтобы начать.";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }

    public string ExportFolder => _settings.ExportFolder ?? ProfileStore.DefaultExportFolder;

    // Настройки сервера (вкладка «Сервер»)
    private string _setTitle = "", _setHost = "", _setDns1 = "", _setDns2 = "";
    private int _setDown, _setUp;
    private bool _applyDefaultsToAll;
    public string SetTitle { get => _setTitle; set => Set(ref _setTitle, value); }
    public string SetEndpointHost { get => _setHost; set => Set(ref _setHost, value); }
    public string SetDns1 { get => _setDns1; set => Set(ref _setDns1, value); }
    public string SetDns2 { get => _setDns2; set => Set(ref _setDns2, value); }
    public int SetDefaultDown { get => _setDown; set => Set(ref _setDown, value); }
    public int SetDefaultUp { get => _setUp; set => Set(ref _setUp, value); }
    public bool ApplyDefaultsToAll { get => _applyDefaultsToAll; set => Set(ref _applyDefaultsToAll, value); }

    // ───────────── Команды ─────────────

    public RelayCommand AddServerCommand { get; }
    public RelayCommand EditServerCommand { get; }
    public RelayCommand RemoveServerCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public RelayCommand InstallCommand { get; }
    public RelayCommand StartCommand { get; }
    public RelayCommand RestartCommand { get; }
    public RelayCommand UninstallCommand { get; }
    public RelayCommand SaveSettingsCommand { get; }
    public RelayCommand AddUserCommand { get; }
    public RelayCommand EditUserCommand { get; }
    public RelayCommand ToggleUserCommand { get; }
    public RelayCommand DeleteUserCommand { get; }
    public RelayCommand AddDeviceCommand { get; }
    public RelayCommand EditDeviceCommand { get; }
    public RelayCommand ToggleDeviceCommand { get; }
    public RelayCommand DeleteDeviceCommand { get; }
    public RelayCommand ShareDeviceCommand { get; }
    public RelayCommand RevokeForeignCommand { get; }
    public RelayCommand AdoptForeignCommand { get; }
    public RelayCommand SetupRelayCommand { get; }
    public RelayCommand RemoveRelayCommand { get; }
    public RelayCommand InstallXrayCommand { get; }
    public RelayCommand UninstallXrayCommand { get; }
    public RelayCommand RunCheckCommand { get; }
    public RelayCommand CancelCheckCommand { get; }
    public RelayCommand CheckAddressCommand { get; }
    public RelayCommand ToggleForeignCommand { get; }
    public RelayCommand OpenExportFolderCommand { get; }
    public RelayCommand ChangeExportFolderCommand { get; }
    public RelayCommand ClearLogCommand { get; }

    // ───────────── Серверы ─────────────

    /// <summary>1.2.0 управлял через вход пробросом порта 22022; теперь — SSH-туннелем через вход.</summary>
    private void MigrateProfiles()
    {
        bool changed = false;
        foreach (var p in Servers.Where(p => p.ManageViaRelay && p.RelayProfileId != null))
        {
            p.JumpProfileId ??= p.RelayProfileId;
            p.ManageViaRelay = false;
            changed = true;
        }
        foreach (var p in Servers.Where(p => p.JumpProfileId != null && Servers.All(j => j.Id != p.JumpProfileId)))
        {
            p.JumpProfileId = null;
            changed = true;
        }
        if (changed) SaveSettingsFile();
    }

    /// <summary>Данные для SSH с учётом промежуточного сервера.</summary>
    private SshCredentials CredsFor(ServerProfile profile, bool direct = false)
    {
        var c = profile.ToCredentials();
        if (!direct && JumpOf(profile) is { } jump) c.Jump = jump.ToCredentials();
        return c;
    }

    private ServerProfile? JumpOf(ServerProfile profile) =>
        profile.JumpProfileId is Guid id && id != profile.Id ? Servers.FirstOrDefault(s => s.Id == id) : null;

    private void AddServer()
    {
        var profile = _ui.EditServer(null, Servers.ToList());
        if (profile == null) return;
        Servers.Add(profile);
        _settings.Servers.Add(profile);
        SaveSettingsFile();
        SelectedServer = profile;
    }

    private void EditServer()
    {
        var current = SelectedServer;
        if (current == null) return;
        if (_ui.EditServer(current, Servers.ToList()) == null) return;
        int idx = Servers.IndexOf(current);
        SelectedServer = null;
        Servers.RemoveAt(idx);
        Servers.Insert(idx, current);
        SaveSettingsFile();
        SelectedServer = current;
    }

    private void RemoveServer()
    {
        if (SelectedServer == null) return;
        var dependents = Servers.Where(s => s.JumpProfileId == SelectedServer.Id).ToList();
        var note = dependents.Count == 0 ? "" :
            $"\n\nЧерез него Маяк подключается к: {string.Join(", ", dependents.Select(d => "«" + d.Name + "»"))} — они станут подключаться напрямую.";
        if (!_ui.Confirm($"Убрать «{SelectedServer.Name}» из списка?\n\nНа самом сервере ничего не изменится: VPN продолжит работать, пользователи останутся.{note}", "Убрать сервер"))
            return;
        var p = SelectedServer;
        foreach (var d in dependents) d.JumpProfileId = null;
        CheckKitStore.Delete(p.Id);
        SelectedServer = null;
        Servers.Remove(p);
        _settings.Servers.Remove(p);
        SaveSettingsFile();
        SelectedServer = Servers.FirstOrDefault();
    }

    private void SaveSettingsFile()
    {
        _settings.Servers = Servers.ToList();
        ProfileStore.Save(_settings);
    }

    // ───────────── Загрузка ─────────────

    public async Task ReloadAsync(bool quiet = false)
    {
        if (SelectedServer == null || IsBusy) return;
        var profile = SelectedServer;
        if (profile.IsRelay)
        {
            await ReloadRelayAsync(profile, quiet);
            return;
        }
        IsBusy = true;
        BusyText = quiet ? "" : "Чтение данных с сервера…";
        try
        {
            var (state, snap) = await Task.Run(() =>
            {
                var server = EnsureConnected(profile);
                var st = server.GetState();
                ServerSnapshot? sn = st == ServerState.Running ? server.Load() : null;
                if (sn != null) PrepareOfflineCheck(server, sn, profile);
                return (st, sn);
            });
            if (profile != SelectedServer) return;
            State = state;
            ApplySnapshot(snap);
            if (snap != null) OfflineKit = CheckKitStore.Load(profile.Id);
            StatusText = state == ServerState.Running
                ? $"Обновлено {DateTime.Now:HH:mm:ss}"
                : StateText;
        }
        catch (Exception ex)
        {
            DisconnectServer();
            if (Snapshot == null)
            {
                State = null;
                if (OfflineKit != null)
                {
                    // Данные для проверки сохранены раньше — сразу открываем «Проверку».
                    AppendLog("Нет связи с сервером по SSH: " + FirstLine(ex.Message));
                    TabIndex = CheckTab;
                }
                else if (!quiet) ShowError(ex);
            }
            else
            {
                // Данные остаются на экране: «Проверка» работает и без SSH.
                AppendLog("Нет связи с сервером по SSH: " + FirstLine(ex.Message));
            }
            StatusText = "Нет связи с сервером по SSH (" + FirstLine(ex.Message) + "). Показаны последние данные; «Проверка» работает и без SSH.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Создаёт проверочную учётку при первом же подключении и сохраняет данные для «Проверки» на компьютере,
    /// чтобы потом проверять протоколы без SSH (например, без стороннего VPN), даже после перезапуска Маяка.
    /// </summary>
    private void PrepareOfflineCheck(MayakServer server, ServerSnapshot snap, ServerProfile profile)
    {
        try
        {
            var p = snap.Db.Probe;
            if (p == null || string.IsNullOrEmpty(p.AwgPrivateKey) || (snap.Xray != null && string.IsNullOrEmpty(p.XrayId)))
                server.EnsureProbe(snap);
            if (CheckKit.From(snap) is { } kit) CheckKitStore.Save(profile.Id, kit);
        }
        catch (Exception ex)
        {
            AppendLog("Не удалось подготовить проверку без SSH: " + FirstLine(ex.Message));
        }
    }

    private MayakServer EnsureConnected(ServerProfile profile, bool direct = false)
    {
        if (_server != null && _connectedProfileId == profile.Id)
        {
            // После смены сети (включили/выключили VPN) старая сессия мертва — переподключаемся.
            if (_server.IsAlive()) return _server;
            AppendLog("SSH-сессия оборвалась (сменилась сеть?), подключаюсь заново…");
        }
        DisconnectServer();
        var server = new MayakServer(CredsFor(profile, direct));
        server.Log += AppendLog;
        server.Connect();
        if (!direct && JumpOf(profile) is { } jump) RememberFingerprint(jump, server.JumpFingerprint);
        if (string.IsNullOrEmpty(profile.Fingerprint) && server.Fingerprint != null)
        {
            profile.Fingerprint = server.Fingerprint;
            Application.Current.Dispatcher.Invoke(SaveSettingsFile);
            AppendLog($"Отпечаток сервера сохранён: {server.Fingerprint}");
        }
        _server = server;
        _connectedProfileId = profile.Id;
        return server;
    }

    private void DisconnectServer()
    {
        var s = _server;
        _server = null;
        _connectedProfileId = null;
        if (s != null)
        {
            s.Log -= AppendLog;
            Task.Run(s.Dispose);
        }
    }

    private void ClearData()
    {
        OfflineKit = null;
        TabIndex = 0;
        Snapshot = null;
        State = null;
        Users.Clear();
        Devices.Clear();
        Foreign.Clear();
        Warnings.Clear();
        StatusText = SelectedServer == null ? "Добавьте сервер, чтобы начать." : "";
    }

    private void ApplySnapshot(ServerSnapshot? snap)
    {
        var selUser = SelectedUser?.Model.Id;
        var selDevice = SelectedDevice?.Model.Id;
        var selForeign = SelectedForeign?.Model.PublicKey;

        Snapshot = snap;
        Users.Clear();
        Foreign.Clear();
        Warnings.Clear();
        if (snap == null)
        {
            Devices.Clear();
            return;
        }

        foreach (var u in snap.Db.Users.OrderBy(u => u.Name, StringComparer.CurrentCultureIgnoreCase))
            Users.Add(new UserItem(u, snap));
        foreach (var f in snap.Foreign)
            Foreign.Add(new ForeignItem(f, snap.Stats.TryGetValue(f.PublicKey, out var st) ? st : null));
        foreach (var w in snap.Warnings)
            Warnings.Add(w);

        SetTitle = snap.Db.ServerTitle;
        SetEndpointHost = snap.Db.EndpointHost;
        SetDns1 = snap.Db.Dns1;
        SetDns2 = snap.Db.Dns2;
        SetDefaultDown = snap.Db.DefaultDownMbps;
        SetDefaultUp = snap.Db.DefaultUpMbps;
        ApplyDefaultsToAll = false;

        _selectedUser = Users.FirstOrDefault(u => u.Model.Id == selUser) ?? Users.FirstOrDefault();
        OnPropertyChanged(nameof(SelectedUser));
        OnPropertyChanged(nameof(ToggleUserText));
        OnPropertyChanged(nameof(UserTitle));
        OnPropertyChanged(nameof(HasSelectedUser));
        OnPropertyChanged(nameof(ForeignBannerText));
        if (Foreign.Count == 0) ShowForeign = false;
        OnPropertyChanged(nameof(DevicesHeader));
        RebuildDevices();
        SelectedDevice = Devices.FirstOrDefault(d => d.Model.Id == selDevice);
        SelectedForeign = Foreign.FirstOrDefault(f => f.Model.PublicKey == selForeign);
        OnPropertyChanged(nameof(SummaryText));
    }

    private void RebuildDevices()
    {
        Devices.Clear();
        if (SelectedUser == null || Snapshot == null) return;
        foreach (var d in SelectedUser.Model.Devices)
            Devices.Add(new DeviceItem(d, SelectedUser.Model, Snapshot));
        SelectedDevice = Devices.FirstOrDefault();
    }

    /// <summary>Выполняет действие на сервере в фоне, потом перерисовывает данные из снимка.</summary>
    private async Task<bool> RunAsync(string busyText, Action<MayakServer> action, bool reload = false)
    {
        if (SelectedServer == null || IsBusy) return false;
        var profile = SelectedServer;
        IsBusy = true;
        BusyText = busyText;
        bool ok = false;
        try
        {
            await Task.Run(() => action(EnsureConnected(profile)));
            ok = true;
        }
        catch (Exception ex)
        {
            if (ex is not MayakException) DisconnectServer();
            ShowError(ex);
        }
        finally
        {
            IsBusy = false;
        }

        if (reload) await ReloadAsync(quiet: !ok);
        else if (Snapshot != null) ApplySnapshot(Snapshot);
        return ok;
    }

    // ───────────── Установка ─────────────

    private async Task InstallAsync()
    {
        if (SelectedServer == null) return;
        bool reinstall = IsInstalled;
        if (reinstall && !_ui.Confirm(
                "Переустановка удалит текущий VPN-сервер: все выданные ключи перестанут работать, пользователям придётся выдать файлы заново.\n\nПродолжить?",
                "Переустановка", danger: true))
            return;

        var opt = _ui.AskInstall(reinstall, SelectedServer.Host);
        if (opt == null) return;

        AppendLog($"=== Установка VPN на {SelectedServer.Host} ===");
        string? xrayError = null;
        var ok = await RunAsync("Установка VPN на сервер…", s =>
        {
            s.Install(opt, reinstall, step => Ui(() => BusyText = step + "…"));
            if (opt.InstallXray)
            {
                try
                {
                    var snap = s.Load();
                    s.InstallXray(snap, opt.Xray, reinstall: true, step => Ui(() => BusyText = "Xray: " + step + "…"));
                }
                catch (Exception ex)
                {
                    xrayError = ex.Message;
                }
            }
        }, reload: true);
        if (ok)
        {
            var ports = $"UDP {opt.Port} (AmneziaWG)" + (opt.InstallXray && xrayError == null ? $" и TCP {opt.Xray.Port} (Xray)" : "");
            var xrayNote = xrayError == null ? "" : $"\n\nXray установить не удалось: {xrayError}\nAmneziaWG работает; Xray можно поставить позже на вкладке «Сервер».";
            if (SelectedServer?.RelayProfileId != null)
                xrayNote += "\n\nНа этом сервере был настроен вход (каскад): порты изменились — нажмите «Настроить вход…» ещё раз.";
            _ui.Info($"VPN установлен.\n\nПорты: {ports}. Если у хостинга есть внешний файрвол (панель управления), откройте в нём эти порты.{xrayNote}\n\nТеперь добавьте пользователей и их устройства.");
        }
    }

    private async Task UninstallAsync()
    {
        if (!_ui.Confirm("Удалить VPN с сервера полностью?\n\nВсе подключения перестанут работать. Сервер останется в списке, VPN можно будет установить заново.", "Удаление VPN", danger: true))
            return;
        await RunAsync("Удаление VPN…", s => s.Uninstall(), reload: true);
    }

    private async Task SaveSettingsAsync()
    {
        var snap = Snapshot;
        if (snap == null) return;
        snap.Db.ServerTitle = string.IsNullOrWhiteSpace(SetTitle) ? "Маяк VPN" : SetTitle.Trim();
        snap.Db.EndpointHost = SetEndpointHost.Trim();
        snap.Db.Dns1 = string.IsNullOrWhiteSpace(SetDns1) ? "1.1.1.1" : SetDns1.Trim();
        snap.Db.Dns2 = SetDns2.Trim();
        snap.Db.DefaultDownMbps = Math.Max(0, SetDefaultDown);
        snap.Db.DefaultUpMbps = Math.Max(0, SetDefaultUp);
        if (ApplyDefaultsToAll)
        {
            foreach (var d in snap.Db.AllDevices)
            {
                d.DownMbps = snap.Db.DefaultDownMbps;
                d.UpMbps = snap.Db.DefaultUpMbps;
            }
        }
        await RunAsync("Сохранение настроек…", s => s.Save(snap), reload: true);
        AppendLog("Новые DNS и адрес сервера попадут в файлы, которые вы выдадите после этого изменения.");
    }

    private async Task InstallXrayAsync()
    {
        var snap = Snapshot;
        if (snap == null) return;
        bool reinstall = snap.Xray != null || snap.XrayState != ServerState.DockerOnly;
        var opt = _ui.AskXrayInstall(reinstall, snap.Xray);
        if (opt == null) return;
        var ok = await RunAsync("Установка Xray…", s => s.InstallXray(snap, opt, reinstall, step => Ui(() => BusyText = step + "…")), reload: true);
        if (ok)
            _ui.Info($"Xray установлен (TCP-порт {opt.Port}).\n\nОткройте этот порт в файрволе хостинга, если он есть. Чтобы у пользователей появился второй протокол, выдайте им файлы .vpn заново (кнопка «Выдать файл / QR»).");
    }

    private async Task UninstallXrayAsync()
    {
        var snap = Snapshot;
        if (snap == null) return;
        if (!_ui.Confirm("Удалить Xray с сервера? AmneziaWG продолжит работать.", "Удаление Xray", danger: true)) return;
        await RunAsync("Удаление Xray…", s => s.UninstallXray(snap), reload: true);
    }

    // ───────────── Вход (каскад) ─────────────

    private async Task ReloadRelayAsync(ServerProfile relayProfile, bool quiet)
    {
        IsBusy = true;
        BusyText = quiet ? "" : "Проверка входного сервера…";
        try
        {
            var status = await Task.Run(() =>
            {
                using var relay = new RelayServer(CredsFor(relayProfile));
                relay.Connect();
                RememberFingerprint(relayProfile, relay.Fingerprint);
                return relay.GetStatus();
            });
            var main = Servers.FirstOrDefault(p => p.Id == relayProfile.RelayForProfileId);
            RelayStatusText = !status.Installed
                ? "Пересылка не настроена. Откройте основной сервер → вкладка «Сервер» → «Настроить вход…»."
                : $"Пересылает на {status.TargetHost}{(main != null ? $" («{main.Name}»)" : "")}.\n" +
                  $"Порты: {status.Forwards.Replace(" ", ", ")}.\n" +
                  $"Служба: {(status.ServiceActive ? "работает" : "не запущена")}, правил пересылки: {status.RuleCount}.";
            StatusText = $"Обновлено {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            RelayStatusText = "Нет связи со входным сервером: " + FirstLine(ex.Message);
            if (!quiet) ShowError(ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void RememberFingerprint(ServerProfile profile, string? fingerprint)
    {
        if (!string.IsNullOrEmpty(profile.Fingerprint) || fingerprint == null) return;
        profile.Fingerprint = fingerprint;
        Ui(SaveSettingsFile);
    }

    private async Task SetupRelayAsync()
    {
        var main = SelectedServer;
        var snap = Snapshot;
        if (main == null || snap == null) return;
        var setup = _ui.AskRelay(main, Servers.Where(p => p.Id != main.Id && p.RelayProfileId == null));
        if (setup == null) return;

        var relayProfile = setup.Relay;
        if (setup.IsNew)
        {
            Servers.Add(relayProfile);
            SaveSettingsFile();
        }
        relayProfile.Role = "relay";
        relayProfile.RelayForProfileId = main.Id;

        // Вход раньше служил другому серверу (например, заблокированному) — отвязываем тот.
        foreach (var old in Servers.Where(s => s.Id != main.Id && s.RelayProfileId == relayProfile.Id))
        {
            old.RelayProfileId = null;
            old.RelayHost = null;
            AppendLog($"Вход «{relayProfile.Name}» теперь служит «{main.Name}»; у «{old.Name}» каскад отключён в Маяке.");
        }

        IReadOnlyList<int> unreachable = Array.Empty<int>();
        IsBusy = true;
        BusyText = "Настройка входного сервера…";
        try
        {
            await Task.Run(() =>
            {
                using var relay = new RelayServer(CredsFor(relayProfile));
                relay.Log += AppendLog;
                relay.Connect();
                RememberFingerprint(relayProfile, relay.Fingerprint);
                unreachable = relay.Install(new RelayOptions
                {
                    TargetHost = main.Host.Trim(),
                    AwgPort = snap.Endpoint.Port,
                    XrayPort = snap.Xray?.Port,
                    SshForwardPort = 0,
                    TargetSshPort = main.Port,
                    CheckTcp = { main.Port },
                }, st => Ui(() => BusyText = st + "…"));
            });
        }
        catch (Exception ex)
        {
            IsBusy = false;
            ShowError(ex);
            return;
        }

        main.RelayProfileId = relayProfile.Id;
        main.RelayHost = relayProfile.Host.Trim();
        main.ManageViaRelay = false;
        if (setup.ManageViaRelay && !unreachable.Contains(main.Port)) main.JumpProfileId = relayProfile.Id;
        else if (main.JumpProfileId == relayProfile.Id) main.JumpProfileId = null;
        SaveSettingsFile();

        // Адрес в файлах подключения — адрес входа.
        string? saveError = null;
        BusyText = "Сохранение адреса входа на основном сервере…";
        try
        {
            await Task.Run(() =>
            {
                DisconnectServer();
                MayakServer s;
                try
                {
                    s = EnsureConnected(main);
                }
                catch when (main.JumpProfileId != null)
                {
                    // Через посредника не вышло — пробуем напрямую (например, через сторонний VPN).
                    s = EnsureConnected(main, direct: true);
                }
                snap.Db.EndpointHost = main.RelayHost!;
                s.Save(snap);
            });
        }
        catch (Exception ex)
        {
            saveError = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
        SaveSettingsFile();
        OnPropertyChanged(nameof(RelayText));
        RefreshServerItem(main);
        await ReloadAsync(quiet: true);

        var msg = $"Вход «{relayProfile.Name}» настроен: пользователи подключаются к {main.RelayHost}, трафик идёт на {main.Host}.";
        if (unreachable.Count > 0)
            msg += $"\n\nВНИМАНИЕ: с входного сервера недоступны TCP-порты основного ({string.Join(", ", unreachable)}). " +
                   "Похоже, IP основного сервера блокируется и в дата-центре входа — тогда каскад не поможет, нужен другой основной сервер.";
        if (saveError != null)
            msg += $"\n\nНе удалось записать адрес входа на основной сервер: {saveError}\nВключите сторонний VPN и нажмите «Настроить вход…» ещё раз.";
        else
            msg += "\n\nТеперь выдайте пользователям файлы заново — в них адрес входа. Затем запустите «Проверку» без стороннего VPN.";
        _ui.Info(msg);
    }

    private async Task RemoveRelayAsync()
    {
        var main = SelectedServer;
        var snap = Snapshot;
        if (main?.RelayProfileId == null) return;
        if (!_ui.Confirm("Отключить вход? Пользователи снова будут подключаться к основному серверу напрямую — файлы придётся выдать заново.", "Отключение входа", danger: true))
            return;
        var relayProfile = Servers.FirstOrDefault(p => p.Id == main.RelayProfileId);
        IsBusy = true;
        BusyText = "Отключение входа…";
        string? error = null;
        try
        {
            await Task.Run(() =>
            {
                if (snap != null)
                {
                    var s = EnsureConnected(main);
                    snap.Db.EndpointHost = "";
                    s.Save(snap);
                }
                if (relayProfile != null)
                {
                    using var relay = new RelayServer(CredsFor(relayProfile));
                    relay.Log += AppendLog;
                    relay.Connect();
                    relay.Remove();
                }
            });
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
        main.RelayProfileId = null;
        main.RelayHost = null;
        main.ManageViaRelay = false;
        if (relayProfile != null) relayProfile.RelayForProfileId = null;
        DisconnectServer();
        SaveSettingsFile();
        OnPropertyChanged(nameof(RelayText));
        RefreshServerItem(main);
        if (error != null) _ui.Error("Вход отключён в Маяке, но не всё удалось на серверах: " + error);
        await ReloadAsync(quiet: true);
    }

    /// <summary>Перерисовать подпись сервера в списке (ServerProfile не уведомляет об изменениях).</summary>
    private void RefreshServerItem(ServerProfile p)
    {
        int idx = Servers.IndexOf(p);
        if (idx < 0) return;
        _selectedServer = null;
        Servers.RemoveAt(idx);
        Servers.Insert(idx, p);
        _selectedServer = p;
        OnPropertyChanged(nameof(SelectedServer));
    }

    // ───────────── Проверка протоколов ─────────────

    public ObservableCollection<CheckLineItem> CheckLines { get; } = new();
    public ObservableCollection<CheckHistoryItem> CheckHistory { get; } = new();

    private CancellationTokenSource? _checkCts;
    private bool _checkRunning;
    public bool CheckRunning
    {
        get => _checkRunning;
        private set { Set(ref _checkRunning, value); CommandManager.InvalidateRequerySuggested(); }
    }

    private string _checkProgress = "";
    public string CheckProgress { get => _checkProgress; private set => Set(ref _checkProgress, value); }

    private string _checkClientAddress = "";
    public string CheckClientAddress { get => _checkClientAddress; private set => Set(ref _checkClientAddress, value); }

    private string _checkRecommendation = "";
    public string CheckRecommendation { get => _checkRecommendation; private set => Set(ref _checkRecommendation, value); }

    private string _checkNetworkLabel = "";
    /// <summary>Подпись сети для истории: «Дом, Ростелеком», «МТС, мобильный».</summary>
    public string CheckNetworkLabel { get => _checkNetworkLabel; set => Set(ref _checkNetworkLabel, value); }

    private async Task RunCheckAsync()
    {
        var profile = SelectedServer;
        if (profile == null) return;
        var snap = Snapshot;
        bool offline = snap == null;
        if (snap == null)
        {
            // SSH недоступен — проверяем по данным, сохранённым при прошлом подключении.
            if (OfflineKit == null) return;
            snap = OfflineKit.ToSnapshot();
        }

        ProbeIdentity? probe = snap.Db.Probe;
        string address = "";
        XraySelfTestResult? selfTest = null;
        bool sshOk = false;
        IsBusy = true;
        BusyText = "Подготовка проверки на сервере…";
        try
        {
            if (offline) throw new MayakException("SSH недоступен, проверка по сохранённым данным");
            await Task.Run(() =>
            {
                var s = EnsureConnected(profile);
                probe = s.EnsureProbe(snap);
                if (CheckKit.From(snap) is { } kit) CheckKitStore.Save(profile.Id, kit);
                address = s.GetClientAddress();
                if (snap.Xray != null)
                {
                    Ui(() => BusyText = "Самопроверка Xray на сервере…");
                    try { selfTest = s.SelfTestXray(snap, probe); }
                    catch (Exception ex) { selfTest = new XraySelfTestResult(false, "Самопроверка на сервере не выполнена: " + ex.Message); }
                }
            });
            sshOk = true;
        }
        catch (Exception ex)
        {
            if (!offline) DisconnectServer();
            AppendLog("SSH к серверу недоступен из этой сети: " + ex.Message);
        }
        finally
        {
            IsBusy = false;
        }

        if (!sshOk)
        {
            if (probe == null || string.IsNullOrEmpty(probe.AwgPrivateKey))
            {
                _ui.Error("Нет связи с сервером по SSH, а проверочная учётка ещё не создана.\n\nПодключитесь к серверу один раз (например, через другой VPN) — Маяк создаст её сам. После этого проверку можно запускать без SSH из любой сети, в том числе после перезапуска Маяка.");
                return;
            }
            address = "не определён (SSH недоступен)";
        }
        else if (string.IsNullOrEmpty(address) && JumpOf(profile) != null)
        {
            address = "не определён (Маяк подключён через посредника)";
        }

        CheckClientAddress = address;
        CheckLines.Clear();
        CheckRecommendation = "";
        CheckRunning = true;
        _checkCts = new CancellationTokenSource();
        var progress = new Progress<string>(m => CheckProgress = m);
        try
        {
            var probeId = probe!;
            var report = await Task.Run(() => ProtocolCheck.RunAsync(snap, probeId, address,
                (p, ct) => XrayBinary.EnsureAsync(CheckHistoryStore.ToolsFolder, p, ct), progress, _checkCts.Token,
                RelayReachPort(profile), selfTest));
            report.NetworkLabel = CheckNetworkLabel.Trim();
            foreach (var line in report.Lines) CheckLines.Add(new CheckLineItem(line));
            CheckRecommendation = report.Recommendation;
            CheckHistoryStore.Add(profile.Id, report);
            CheckHistory.Insert(0, new CheckHistoryItem(report));
            AppendLog("Проверка: " + string.Join("; ", report.Lines.Select(l => $"{l.Protocol} — {l.Summary}")));
        }
        catch (OperationCanceledException)
        {
            CheckRecommendation = "Проверка остановлена.";
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            CheckRunning = false;
            CheckProgress = "";
            _checkCts.Dispose();
            _checkCts = null;
        }
    }

    /// <summary>Для «Связи с сервером»: при каскаде проверяем SSH-порт входа (его адрес стоит в конфигах).</summary>
    private int RelayReachPort(ServerProfile profile) =>
        profile.RelayProfileId is Guid id && Servers.FirstOrDefault(p => p.Id == id) is { } relay ? relay.Port : profile.Port;

    private void LoadCheckHistory()
    {
        CheckHistory.Clear();
        CheckLines.Clear();
        CheckRecommendation = "";
        CheckClientAddress = "";
        if (SelectedServer == null) return;
        foreach (var r in CheckHistoryStore.Load(SelectedServer.Id)) CheckHistory.Add(new CheckHistoryItem(r));
    }

    // ───────────── Пользователи ─────────────

    private async Task AddUserAsync()
    {
        var snap = Snapshot;
        if (snap == null) return;
        var r = _ui.EditUser("Новый пользователь", null);
        if (r == null) return;
        if (snap.Db.Users.Any(u => string.Equals(u.Name, r.Name, StringComparison.CurrentCultureIgnoreCase)))
        {
            _ui.Error($"Пользователь «{r.Name}» уже есть.");
            return;
        }
        var user = new VpnUser { Name = r.Name, Note = r.Note };
        snap.Db.Users.Add(user);
        var ok = await RunAsync("Сохранение…", s => s.Save(snap));
        if (!ok) { snap.Db.Users.Remove(user); ApplySnapshot(snap); return; }
        SelectedUser = Users.FirstOrDefault(u => u.Model == user);

        if (_ui.Confirm($"Пользователь «{user.Name}» создан. Добавить ему устройство?", "Устройство"))
            await AddDeviceAsync();
    }

    private async Task EditUserAsync()
    {
        var snap = Snapshot;
        var item = SelectedUser;
        if (snap == null || item == null) return;
        var r = _ui.EditUser("Пользователь", item.Model);
        if (r == null) return;
        item.Model.Name = r.Name;
        item.Model.Note = r.Note;
        await RunAsync("Сохранение…", s => s.Save(snap));
    }

    private async Task ToggleUserAsync()
    {
        var snap = Snapshot;
        var item = SelectedUser;
        if (snap == null || item == null) return;
        bool enable = !item.Model.Enabled;
        if (!enable && !_ui.Confirm($"Приостановить доступ для «{item.Name}» на всех устройствах?\n\nКлючи сохранятся, доступ можно вернуть одной кнопкой.", "Приостановить"))
            return;
        await RunAsync(enable ? "Включение доступа…" : "Приостановка доступа…", s => s.SetUserEnabled(snap, item.Model, enable));
    }

    private async Task DeleteUserAsync()
    {
        var snap = Snapshot;
        var item = SelectedUser;
        if (snap == null || item == null) return;
        if (!_ui.Confirm($"Удалить пользователя «{item.Name}» и отозвать доступ на всех его устройствах ({item.Model.Devices.Count})?\n\nЭто нельзя отменить.", "Удаление пользователя", danger: true))
            return;
        await RunAsync("Удаление…", s => s.RemoveUser(snap, item.Model));
    }

    // ───────────── Устройства ─────────────

    private async Task AddDeviceAsync()
    {
        var snap = Snapshot;
        var item = SelectedUser;
        if (snap == null || item == null) return;
        var r = _ui.EditDevice("Новое устройство", null, item.Name, snap.Db.DefaultDownMbps, snap.Db.DefaultUpMbps);
        if (r == null) return;

        VpnDevice? created = null;
        var ok = await RunAsync("Выдача доступа…", s => created = s.AddDevice(snap, item.Model, r.Name, r.Kind, r.DownMbps, r.UpMbps));
        if (ok && created != null)
        {
            SelectedDevice = Devices.FirstOrDefault(d => d.Model == created);
            _ui.ShowShare(snap, item.Model, created, ExportFolder);
        }
    }

    private async Task EditDeviceAsync()
    {
        var snap = Snapshot;
        var item = SelectedDevice;
        if (snap == null || item == null) return;
        var r = _ui.EditDevice("Устройство", item.Model, item.Owner.Name, snap.Db.DefaultDownMbps, snap.Db.DefaultUpMbps);
        if (r == null) return;
        item.Model.Name = r.Name;
        item.Model.Kind = r.Kind;
        item.Model.DownMbps = r.DownMbps;
        item.Model.UpMbps = r.UpMbps;
        await RunAsync("Сохранение и применение лимитов…", s => s.Save(snap));
    }

    private async Task ToggleDeviceAsync()
    {
        var snap = Snapshot;
        var item = SelectedDevice;
        if (snap == null || item == null) return;
        bool enable = !item.Model.Enabled || snap.IsMissingOnServer(item.Model);
        await RunAsync(enable ? "Включение…" : "Приостановка…", s => s.SetDeviceEnabled(snap, item.Owner, item.Model, enable));
    }

    private async Task DeleteDeviceAsync()
    {
        var snap = Snapshot;
        var item = SelectedDevice;
        if (snap == null || item == null) return;
        if (!_ui.Confirm($"Удалить устройство «{item.Name}» пользователя «{item.Owner.Name}»?\n\nДоступ на нём сразу пропадёт.", "Удаление устройства", danger: true))
            return;
        await RunAsync("Отзыв доступа…", s => s.RemoveDevice(snap, item.Owner, item.Model));
    }

    private void ShareDevice()
    {
        var snap = Snapshot;
        var item = SelectedDevice;
        if (snap == null || item == null) return;
        _ui.ShowShare(snap, item.Owner, item.Model, ExportFolder);
    }

    // ───────────── Чужие подключения ─────────────

    private async Task RevokeForeignAsync()
    {
        var snap = Snapshot;
        var item = SelectedForeign;
        if (snap == null || item == null) return;
        if (!_ui.Confirm($"Отозвать подключение «{item.Name}» ({item.Ip})?", "Отзыв", danger: true)) return;
        await RunAsync("Отзыв…", s => s.RevokeForeign(snap, item.Model));
    }

    private async Task AdoptForeignAsync()
    {
        var snap = Snapshot;
        var item = SelectedForeign;
        if (snap == null || item == null) return;
        var r = _ui.AskAdopt(item.Model, snap.Db.Users);
        if (r == null) return;
        await RunAsync("Привязка…", s => s.AdoptForeign(snap, item.Model, r.Value.User, r.Value.Kind));
    }

    // ───────────── Прочее ─────────────

    private void OpenExportFolder()
    {
        Directory.CreateDirectory(ExportFolder);
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{ExportFolder}\"") { UseShellExecute = true });
    }

    private void ChangeExportFolder()
    {
        var folder = _ui.PickFolder(ExportFolder);
        if (folder == null) return;
        _settings.ExportFolder = folder;
        SaveSettingsFile();
        OnPropertyChanged(nameof(ExportFolder));
    }

    private void AppendLog(string line) => Ui(() =>
    {
        LogLines.Add($"{DateTime.Now:HH:mm:ss}  {line}");
        while (LogLines.Count > 500) LogLines.RemoveAt(0);
    });

    private void ShowError(Exception ex)
    {
        AppendLog("Ошибка: " + ex.Message);
        if (ex is not MayakException) AppendLog(ex.ToString());
        _ui.Error(ex is MayakException ? ex.Message : $"{ex.Message}\n\n({ex.GetType().Name})");
    }

    private static string FirstLine(string s) => s.Split('\n')[0];

    private static void Ui(Action a)
    {
        var d = Application.Current?.Dispatcher;
        if (d == null || d.CheckAccess()) a();
        else d.BeginInvoke(a);
    }
}
