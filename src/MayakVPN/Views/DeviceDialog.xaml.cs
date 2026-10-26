using System.Windows;
using System.Windows.Controls;
using Mayak.Core.Models;
using MayakVPN.ViewModels;

namespace MayakVPN.Views;

public sealed record KindOption(DeviceKind Kind, string Title);

public partial class DeviceDialog : Window
{
    private bool _nameTouched;
    private bool _settingName;
    private readonly int _defaultDown;
    private readonly int _defaultUp;

    public DeviceEditResult? Result { get; private set; }

    public static IReadOnlyList<KindOption> Kinds { get; } =
        Enum.GetValues<DeviceKind>().Select(k => new KindOption(k, k.Title())).ToList();

    public DeviceDialog(string title, VpnDevice? existing, string userName, int defaultDown, int defaultUp)
    {
        InitializeComponent();
        Header.Text = title;
        UserText.Text = $"Пользователь: {userName}";
        _defaultDown = defaultDown;
        _defaultUp = defaultUp;
        KindBox.ItemsSource = Kinds;

        if (existing != null)
        {
            _nameTouched = true;
            KindBox.SelectedItem = Kinds.First(k => k.Kind == existing.Kind);
            SetName(existing.Name);
            DownBox.Text = existing.DownMbps.ToString();
            UpBox.Text = existing.UpMbps.ToString();
            Unlimited.IsChecked = existing.DownMbps <= 0 && existing.UpMbps <= 0;
        }
        else
        {
            OkButton.Content = "Выдать доступ";
            KindBox.SelectedItem = Kinds.First(k => k.Kind == DeviceKind.IPhone);
            DownBox.Text = defaultDown.ToString();
            UpBox.Text = defaultUp.ToString();
            Unlimited.IsChecked = defaultDown <= 0 && defaultUp <= 0;
        }
        Loaded += (_, _) => KindBox.Focus();
    }

    private DeviceKind SelectedKind => (KindBox.SelectedItem as KindOption)?.Kind ?? DeviceKind.Other;

    private void KindChanged(object sender, SelectionChangedEventArgs e)
    {
        var kind = SelectedKind;
        FormatHint.Text = kind.DefaultFormat() == ConfigFormat.AwgConf
            ? "Файл .conf — импорт в приложение AmneziaWG или AmneziaVPN (App Store)."
            : "Файл .vpn — импорт в приложение AmneziaVPN.";
        if (!_nameTouched) SetName(kind.Title());
    }

    private void SetName(string name)
    {
        _settingName = true;
        NameBox.Text = name;
        _settingName = false;
    }

    private void NameEdited(object sender, TextChangedEventArgs e)
    {
        if (!_settingName) _nameTouched = true;
    }

    private void UnlimitedChanged(object sender, RoutedEventArgs e)
    {
        if (DownBox == null || UpBox == null) return;
        bool unlimited = Unlimited.IsChecked == true;
        DownBox.IsEnabled = UpBox.IsEnabled = !unlimited;
        if (!unlimited && DownBox.Text == "0" && UpBox.Text == "0")
        {
            DownBox.Text = (_defaultDown > 0 ? _defaultDown : 35).ToString();
            UpBox.Text = (_defaultUp > 0 ? _defaultUp : 35).ToString();
        }
    }

    private void Ok(object sender, RoutedEventArgs e)
    {
        var name = NameBox.Text.Trim();
        if (name.Length == 0)
        {
            Warn("Введите название устройства.");
            return;
        }

        int down = 0, up = 0;
        if (Unlimited.IsChecked != true)
        {
            if (!int.TryParse(DownBox.Text.Trim(), out down) || down < 0 || down > 10000 ||
                !int.TryParse(UpBox.Text.Trim(), out up) || up < 0 || up > 10000)
            {
                Warn("Скорость — целое число от 0 до 10000 Мбит/с.");
                return;
            }
        }

        Result = new DeviceEditResult(name, SelectedKind, down, up);
        DialogResult = true;
    }

    private void Warn(string text) => MessageBox.Show(this, text, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
}
