using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Mayak.Core.Models;
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
                _ = ReloadAsync();
            }
            OnPropertyChanged(nameof(HasServer));
        }
    }

    public bool HasServer => SelectedServer != null;

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
        }
    }

    private ServerState? _state;
    public ServerState? State
    {
        get => _state;
        private set
        {
            Set(ref _state, value);
            OnPropertyChanged(nameof(IsInstalled));
            OnPropertyChanged(nameof(StateText));
            OnPropertyChanged(nameof(InstallButtonText));
            OnPropertyChanged(nameof(NeedsInstall));
        }
    }

    public bool IsInstalled => State is ServerState.Running or ServerState.Stopped;
    public bool NeedsInstall => State is ServerState.Clean or ServerState.DockerOnly;

    public string StateText => State switch
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
    public RelayCommand OpenExportFolderCommand { get; }
    public RelayCommand ChangeExportFolderCommand { get; }
    public RelayCommand ClearLogCommand { get; }

    // ───────────── Серверы ─────────────

    private void AddServer()
    {
        var profile = _ui.EditServer(null);
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
        if (_ui.EditServer(current) == null) return;
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
        if (!_ui.Confirm($"Убрать «{SelectedServer.Name}» из списка?\n\nНа самом сервере ничего не изменится: VPN продолжит работать, пользователи останутся.", "Убрать сервер"))
            return;
        var p = SelectedServer;
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
        IsBusy = true;
        BusyText = quiet ? "" : "Чтение данных с сервера…";
        try
        {
            var (state, snap) = await Task.Run(() =>
            {
                var server = EnsureConnected(profile);
                var st = server.GetState();
                ServerSnapshot? sn = st == ServerState.Running ? server.Load() : null;
                return (st, sn);
            });
            if (profile != SelectedServer) return;
            State = state;
            ApplySnapshot(snap);
            StatusText = state == ServerState.Running
                ? $"Обновлено {DateTime.Now:HH:mm:ss}"
                : StateText;
        }
        catch (Exception ex)
        {
            DisconnectServer();
            State = null;
            if (!quiet) ShowError(ex);
            StatusText = "Нет связи с сервером: " + FirstLine(ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private MayakServer EnsureConnected(ServerProfile profile)
    {
        if (_server != null && _connectedProfileId == profile.Id) return _server;
        DisconnectServer();
        var server = new MayakServer(profile.ToCredentials());
        server.Log += AppendLog;
        server.Connect();
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
        var ok = await RunAsync("Установка VPN на сервер…", s => s.Install(opt, reinstall, step => Ui(() => BusyText = step + "…")), reload: true);
        if (ok)
            _ui.Info($"VPN установлен.\n\nПорт: UDP {opt.Port}. Если у хостинга есть внешний файрвол (панель управления), откройте в нём этот порт.\n\nТеперь добавьте пользователей и их устройства.");
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
