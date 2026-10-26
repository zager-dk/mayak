using System.Collections.Specialized;
using System.Windows;
using System.Windows.Input;
using Mayak.Core.Models;
using Mayak.Core.Server;
using MayakVPN.Services;
using MayakVPN.ViewModels;
using MayakVPN.Views;

namespace MayakVPN;

public partial class MainWindow : Window, IUi
{
    private readonly MainViewModel _vm;

    public MainWindow()
    {
        InitializeComponent();
        var version = typeof(MainWindow).Assembly.GetName().Version;
        Title = $"Маяк VPN {version?.ToString(3)}";
        _vm = new MainViewModel(this);
        DataContext = _vm;
        ((INotifyCollectionChanged)_vm.LogLines).CollectionChanged += (_, _) =>
        {
            if (LogList.Items.Count > 0) LogList.ScrollIntoView(LogList.Items[^1]);
        };
    }

    private void DevicesGrid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (_vm.ShareDeviceCommand.CanExecute(null)) _vm.ShareDeviceCommand.Execute(null);
    }

    // ───────────── IUi ─────────────

    public ServerProfile? EditServer(ServerProfile? existing)
    {
        var dlg = new ServerDialog(existing) { Owner = this };
        return dlg.ShowDialog() == true ? dlg.Result : null;
    }

    public InstallOptions? AskInstall(bool reinstall, string host)
    {
        var dlg = new InstallDialog(reinstall, host) { Owner = this };
        return dlg.ShowDialog() == true ? dlg.Result : null;
    }

    public XrayInstallOptions? AskXrayInstall(bool reinstall, XrayEndpoint? current)
    {
        var dlg = new XrayDialog(reinstall, current) { Owner = this };
        return dlg.ShowDialog() == true ? dlg.Result : null;
    }

    public UserEditResult? EditUser(string title, VpnUser? existing)
    {
        var dlg = new UserDialog(title, existing) { Owner = this };
        return dlg.ShowDialog() == true ? dlg.Result : null;
    }

    public DeviceEditResult? EditDevice(string title, VpnDevice? existing, string userName, int defaultDown, int defaultUp)
    {
        var dlg = new DeviceDialog(title, existing, userName, defaultDown, defaultUp) { Owner = this };
        return dlg.ShowDialog() == true ? dlg.Result : null;
    }

    public void ShowShare(ServerSnapshot snap, VpnUser user, VpnDevice device, string exportFolder)
    {
        var w = new ShareWindow(snap, user, device, exportFolder) { Owner = this };
        w.ShowDialog();
    }

    public (VpnUser User, DeviceKind Kind)? AskAdopt(ForeignPeer peer, IReadOnlyList<VpnUser> users)
    {
        var dlg = new AdoptDialog(peer, users) { Owner = this };
        return dlg.ShowDialog() == true && dlg.SelectedUser != null ? (dlg.SelectedUser, dlg.SelectedKind) : null;
    }

    public bool Confirm(string text, string title, bool danger = false) =>
        MessageBox.Show(this, text, title, MessageBoxButton.YesNo, danger ? MessageBoxImage.Warning : MessageBoxImage.Question) == MessageBoxResult.Yes;

    public void Error(string text) =>
        MessageBox.Show(this, text, "Маяк VPN — ошибка", MessageBoxButton.OK, MessageBoxImage.Error);

    public void Info(string text) =>
        MessageBox.Show(this, text, "Маяк VPN", MessageBoxButton.OK, MessageBoxImage.Information);

    public string? PickFolder(string current)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Папка для файлов подключения", InitialDirectory = current };
        return dlg.ShowDialog(this) == true ? dlg.FolderName : null;
    }
}
