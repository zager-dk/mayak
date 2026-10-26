using System.Net;
using System.Windows;
using Mayak.Core.Awg;
using Mayak.Core.Server;

namespace MayakVPN.Views;

public partial class InstallDialog : Window
{
    public InstallOptions? Result { get; private set; }

    public InstallDialog(bool reinstall, string host)
    {
        InitializeComponent();
        HostText.Text = $"Сервер: {host}";
        PortBox.Text = InstallOptions.RandomPort().ToString();
        SniBox.ItemsSource = XraySites.Suggestions;
        SniBox.Text = Mayak.Core.Models.XrayDefaults.DefaultSni;
        if (reinstall)
        {
            Header.Text = "Переустановка VPN";
            ReinstallWarning.Visibility = Visibility.Visible;
            OkButton.Content = "Переустановить";
        }
    }

    private void XrayToggled(object sender, RoutedEventArgs e)
    {
        if (XrayPanel != null) XrayPanel.IsEnabled = XrayCheck.IsChecked == true;
    }

    private void NewPort(object sender, RoutedEventArgs e) => PortBox.Text = InstallOptions.RandomPort().ToString();

    private void Ok(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(PortBox.Text.Trim(), out var port) || port is < 1024 or > 65535)
        {
            Warn("Порт должен быть числом от 1024 до 65535.");
            return;
        }
        if (!IPAddress.TryParse(Dns1Box.Text.Trim(), out _))
        {
            Warn("Первый DNS должен быть IP-адресом, например 1.1.1.1.");
            return;
        }
        if (Dns2Box.Text.Trim().Length > 0 && !IPAddress.TryParse(Dns2Box.Text.Trim(), out _))
        {
            Warn("Второй DNS должен быть IP-адресом или пустым.");
            return;
        }
        if (!int.TryParse(DownBox.Text.Trim(), out var down) || down < 0 || !int.TryParse(UpBox.Text.Trim(), out var up) || up < 0)
        {
            Warn("Лимиты скорости — целые числа, 0 означает «без ограничений».");
            return;
        }

        int xrayPort = 443;
        var sni = SniBox.Text.Trim();
        if (XrayCheck.IsChecked == true)
        {
            if (!int.TryParse(XrayPortBox.Text.Trim(), out xrayPort) || xrayPort is < 1 or > 65535)
            {
                Warn("Порт Xray должен быть числом от 1 до 65535.");
                return;
            }
            if (!XraySites.IsValidHost(sni))
            {
                Warn("Укажите домен сайта для маскировки, например www.googletagmanager.com.");
                return;
            }
        }

        Result = new InstallOptions
        {
            InstallXray = XrayCheck.IsChecked == true,
            Xray = new XrayInstallOptions { Port = xrayPort, Sni = sni },
            Port = port,
            Version = V3.IsChecked == true ? AwgProtocolVersion.V3 : AwgProtocolVersion.V2,
            Dns1 = Dns1Box.Text.Trim(),
            Dns2 = Dns2Box.Text.Trim(),
            Title = string.IsNullOrWhiteSpace(TitleBox.Text) ? "Маяк VPN" : TitleBox.Text.Trim(),
            DefaultDownMbps = down,
            DefaultUpMbps = up,
        };
        DialogResult = true;
    }

    private void Warn(string text) => MessageBox.Show(this, text, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
}
