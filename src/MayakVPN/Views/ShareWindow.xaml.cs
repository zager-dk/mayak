using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Media.Imaging;
using Mayak.Core.Export;
using Mayak.Core.Models;
using Mayak.Core.Server;

namespace MayakVPN.Views;

public partial class ShareWindow : Window
{
    private readonly ServerSnapshot _snap;
    private readonly VpnUser _user;
    private readonly VpnDevice _device;
    private readonly string _vpnKey;
    private readonly string _confText;
    private readonly IReadOnlyList<string> _amneziaQr;
    private IReadOnlyList<string> _currentQr = Array.Empty<string>();
    private int _qrIndex;
    private string? _savedFile;

    public ShareWindow(ServerSnapshot snap, VpnUser user, VpnDevice device, string exportFolder)
    {
        InitializeComponent();
        _snap = snap;
        _user = user;
        _device = device;

        var db = snap.Db;
        var title = $"{db.ServerTitle} · {user.Name}";
        _vpnKey = ClientConfigFactory.BuildVpnKey(snap.Endpoint, device, db.Dns1, db.Dns2, title);
        _confText = ClientConfigFactory.BuildConfFile(snap.Endpoint, device, db.Dns1, db.Dns2);
        _amneziaQr = ClientConfigFactory.BuildAmneziaQrChunks(snap.Endpoint, device, db.Dns1, db.Dns2, title);

        Header.Text = $"Доступ: {user.Name} — {device.Name}";
        SubHeader.Text = $"{device.Kind.Title()} · IP в VPN {device.Ip} · AmneziaWG {snap.Endpoint.Parameters.ProtocolVersionString} · сервер {snap.Endpoint.Host}:{snap.Endpoint.Port}";
        Instructions.Text = InstructionsFor(device.Kind);

        var format = device.Kind.DefaultFormat();
        try
        {
            _savedFile = AutoSave(exportFolder, format);
            SavedPath.Text = _savedFile;
        }
        catch (Exception ex)
        {
            SavedCard.Visibility = Visibility.Collapsed;
            MessageBox.Show(this, "Не удалось сохранить файл: " + ex.Message, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        if (format == ConfigFormat.AwgConf) QrConf.IsChecked = true;
        else QrAmnezia.IsChecked = true;
    }

    private string AutoSave(string exportFolder, ConfigFormat format)
    {
        var folder = Path.Combine(exportFolder, Safe(_snap.Db.ServerTitle), Safe(_user.Name));
        Directory.CreateDirectory(folder);
        var file = Path.Combine(folder, ClientConfigFactory.SuggestFileName(_user.Name, _device, format));
        File.WriteAllText(file, format == ConfigFormat.AwgConf ? _confText : _vpnKey, new UTF8Encoding(false));
        return file;
    }

    private static string Safe(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return name.Trim().Length == 0 ? "_" : name.Trim();
    }

    private static string InstructionsFor(DeviceKind kind) => kind switch
    {
        DeviceKind.Windows =>
            "1. Установите AmneziaVPN для Windows с сайта amnezia.org.\n" +
            "2. Перешлите человеку файл .vpn (или ключ vpn://).\n" +
            "3. В AmneziaVPN: «Добавить сервер» → «Файл с настройками» и выберите файл. Можно просто вставить ключ vpn://.\n" +
            "4. Нажмите «Подключиться».",
        DeviceKind.Android =>
            "1. Установите AmneziaVPN из Google Play или с amnezia.org.\n" +
            "2. Перешлите на телефон файл .vpn (Telegram, почта) и откройте его через AmneziaVPN.\n" +
            "   Или в приложении выберите добавление по QR-коду и отсканируйте код справа.\n" +
            "3. Разрешите создание VPN-подключения и нажмите «Подключиться».",
        DeviceKind.IPhone =>
            "1. Установите AmneziaWG (или AmneziaVPN) из App Store.\n" +
            "2. Перешлите на iPhone файл .conf (AirDrop, Telegram, почта) → «Поделиться» → AmneziaWG.\n" +
            "   Или в AmneziaWG: «+» → «Создать из QR-кода» и отсканируйте код справа (режим «.conf»).\n" +
            "3. Разрешите добавление конфигурации VPN и включите туннель.",
        DeviceKind.Mac =>
            "1. Установите AmneziaWG (или AmneziaVPN) из App Store.\n" +
            "2. В AmneziaWG: «Импорт туннелей из файла» → выберите файл .conf.\n" +
            "3. Разрешите добавление конфигурации VPN и включите туннель.",
        DeviceKind.Linux =>
            "Вариант 1: AmneziaVPN для Linux — импорт файла .vpn или ключа vpn://.\n" +
            "Вариант 2: amneziawg-tools — сохраните .conf как /etc/amnezia/amneziawg/awg0.conf и выполните «awg-quick up awg0».",
        _ =>
            "AmneziaVPN (Windows, Android, Linux): импорт файла .vpn или ключа vpn://.\n" +
            "AmneziaWG (iPhone, Mac): импорт файла .conf или QR-кода в режиме «.conf».",
    };

    // ───────────── QR ─────────────

    private void QrModeChanged(object sender, RoutedEventArgs e)
    {
        if (QrImage == null) return;
        _currentQr = QrConf.IsChecked == true ? new[] { _confText } : _amneziaQr;
        QrHint.Text = QrConf.IsChecked == true
            ? "Сканируйте в AmneziaWG (iPhone, Mac, Android)."
            : _amneziaQr.Count > 1
                ? "Сканируйте в AmneziaVPN все коды по очереди — приложение соберёт их само."
                : "Сканируйте в AmneziaVPN.";
        _qrIndex = 0;
        ShowQr();
    }

    private void ShowQr()
    {
        if (_currentQr.Count == 0) return;
        try
        {
            var png = QrImages.Png(_currentQr[_qrIndex], 6);
            var bmp = new BitmapImage();
            using (var ms = new MemoryStream(png))
            {
                bmp.BeginInit();
                bmp.CacheOption = BitmapCacheOption.OnLoad;
                bmp.StreamSource = ms;
                bmp.EndInit();
            }
            bmp.Freeze();
            QrImage.Source = bmp;
        }
        catch (Exception ex)
        {
            QrImage.Source = null;
            QrHint.Text = "QR-код не построен: " + ex.Message;
        }
        PagerPanel.Visibility = _currentQr.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
        PagerText.Text = $"{_qrIndex + 1} из {_currentQr.Count}";
    }

    private void PrevQr(object sender, RoutedEventArgs e)
    {
        if (_currentQr.Count == 0) return;
        _qrIndex = (_qrIndex - 1 + _currentQr.Count) % _currentQr.Count;
        ShowQr();
    }

    private void NextQr(object sender, RoutedEventArgs e)
    {
        if (_currentQr.Count == 0) return;
        _qrIndex = (_qrIndex + 1) % _currentQr.Count;
        ShowQr();
    }

    // ───────────── Действия ─────────────

    private void CopyKey(object sender, RoutedEventArgs e) => Copy(_vpnKey, "Ключ vpn:// скопирован.");

    private void CopyConf(object sender, RoutedEventArgs e) => Copy(_confText, "Текст .conf скопирован.");

    private void Copy(string text, string done)
    {
        try
        {
            Clipboard.SetText(text);
            MessageBox.Show(this, done, Title, MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Буфер обмена занят другим приложением: " + ex.Message, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void SaveVpnAs(object sender, RoutedEventArgs e) => SaveAs(ConfigFormat.AmneziaVpn);

    private void SaveConfAs(object sender, RoutedEventArgs e) => SaveAs(ConfigFormat.AwgConf);

    private void SaveAs(ConfigFormat format)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            FileName = ClientConfigFactory.SuggestFileName(_user.Name, _device, format),
            Filter = format == ConfigFormat.AwgConf ? "Конфиг AmneziaWG (*.conf)|*.conf" : "Ключ AmneziaVPN (*.vpn)|*.vpn",
        };
        if (_savedFile != null) dlg.InitialDirectory = Path.GetDirectoryName(_savedFile);
        if (dlg.ShowDialog(this) != true) return;
        File.WriteAllText(dlg.FileName, format == ConfigFormat.AwgConf ? _confText : _vpnKey, new UTF8Encoding(false));
    }

    private void ShowInFolder(object sender, RoutedEventArgs e)
    {
        if (_savedFile == null) return;
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_savedFile}\"") { UseShellExecute = true });
    }

    private void CloseClick(object sender, RoutedEventArgs e) => Close();
}
