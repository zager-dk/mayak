using System.Windows;
using Mayak.Core.Models;
using Mayak.Core.Server;

namespace MayakVPN.Views;

public partial class XrayDialog : Window
{
    public XrayInstallOptions? Result { get; private set; }

    public XrayDialog(bool reinstall, XrayEndpoint? current)
    {
        InitializeComponent();
        SniBox.ItemsSource = XraySites.Suggestions;
        SniBox.Text = current?.Sni ?? XrayDefaults.DefaultSni;
        PortBox.Text = (current?.Port ?? XrayDefaults.DefaultPort).ToString();
        if (reinstall)
        {
            Header.Text = "Переустановка Xray";
            ReinstallWarning.Visibility = Visibility.Visible;
            OkButton.Content = "Переустановить";
        }
    }

    private void Ok(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(PortBox.Text.Trim(), out var port) || port is < 1 or > 65535)
        {
            MessageBox.Show(this, "Порт должен быть числом от 1 до 65535.", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var sni = SniBox.Text.Trim();
        if (!XraySites.IsValidHost(sni))
        {
            MessageBox.Show(this, "Укажите домен сайта, например www.googletagmanager.com.", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        Result = new XrayInstallOptions { Port = port, Sni = sni };
        DialogResult = true;
    }
}
