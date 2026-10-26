using System.Windows;
using MayakVPN.Services;

namespace MayakVPN.Views;

public partial class ServerDialog : Window
{
    private readonly ServerProfile? _existing;
    private bool _resetFingerprint;

    public ServerProfile? Result { get; private set; }

    private sealed record JumpOption(Guid? Id, string Name);

    public ServerDialog(ServerProfile? existing, IEnumerable<ServerProfile> jumpCandidates)
    {
        InitializeComponent();
        _existing = existing;
        var options = new List<JumpOption> { new(null, "Напрямую") };
        options.AddRange(jumpCandidates
            .Where(c => c.Id != existing?.Id && c.JumpProfileId == null)
            .Select(c => new JumpOption(c.Id, $"Через «{c.Name}» ({c.Host})")));
        JumpBox.ItemsSource = options;
        JumpBox.SelectedItem = options.FirstOrDefault(o => o.Id != null && o.Id == existing?.JumpProfileId) ?? options[0];
        if (existing != null)
        {
            Header.Text = "Настройки сервера";
            NameBox.Text = existing.Name;
            HostBox.Text = existing.Host;
            PortBox.Text = existing.Port.ToString();
            UserBox.Text = existing.User;
            PasswordBox.Password = existing.Password ?? "";
            KeyBox.Text = existing.KeyPath ?? "";
            PassphraseBox.Password = existing.Passphrase ?? "";
            if (!string.IsNullOrEmpty(existing.KeyPath)) UseKey.IsChecked = true;
            if (!string.IsNullOrEmpty(existing.Fingerprint))
            {
                FingerprintPanel.Visibility = Visibility.Visible;
                FingerprintText.Text = "Отпечаток: " + existing.Fingerprint;
            }
        }
        Loaded += (_, _) => (existing == null ? HostBox : NameBox).Focus();
    }

    private void AuthChanged(object sender, RoutedEventArgs e)
    {
        if (PasswordPanel == null || KeyPanel == null) return;
        bool key = UseKey.IsChecked == true;
        PasswordPanel.Visibility = key ? Visibility.Collapsed : Visibility.Visible;
        KeyPanel.Visibility = key ? Visibility.Visible : Visibility.Collapsed;
    }

    private void BrowseKey(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Приватный SSH-ключ",
            InitialDirectory = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh"),
            Filter = "Все файлы|*.*",
        };
        if (dlg.ShowDialog(this) == true) KeyBox.Text = dlg.FileName;
    }

    private void ResetFingerprint(object sender, RoutedEventArgs e)
    {
        _resetFingerprint = true;
        FingerprintText.Text = "Отпечаток будет запомнен заново при следующем подключении.";
    }

    private void Ok(object sender, RoutedEventArgs e)
    {
        var host = HostBox.Text.Trim();
        if (host.Length == 0) { Warn("Укажите адрес сервера."); HostBox.Focus(); return; }
        if (!int.TryParse(PortBox.Text.Trim(), out var port) || port is < 1 or > 65535) { Warn("SSH-порт должен быть числом от 1 до 65535."); PortBox.Focus(); return; }
        var user = UserBox.Text.Trim();
        if (user.Length == 0) { Warn("Укажите логин."); UserBox.Focus(); return; }

        bool useKey = UseKey.IsChecked == true;
        if (useKey && KeyBox.Text.Trim().Length == 0) { Warn("Выберите файл ключа."); return; }
        if (!useKey && PasswordBox.Password.Length == 0) { Warn("Введите пароль."); PasswordBox.Focus(); return; }

        var p = _existing ?? new ServerProfile();
        bool hostChanged = _existing != null && !string.Equals(_existing.Host, host, StringComparison.OrdinalIgnoreCase);
        p.Name = string.IsNullOrWhiteSpace(NameBox.Text) ? host : NameBox.Text.Trim();
        p.Host = host;
        p.Port = port;
        p.User = user;
        if (useKey)
        {
            p.KeyPath = KeyBox.Text.Trim();
            p.Passphrase = PassphraseBox.Password;
            p.Password = null;
        }
        else
        {
            p.KeyPath = null;
            p.Passphrase = null;
            p.Password = PasswordBox.Password;
        }
        if (_resetFingerprint || hostChanged) p.Fingerprint = null;
        p.JumpProfileId = (JumpBox.SelectedItem as JumpOption)?.Id;

        Result = p;
        DialogResult = true;
    }

    private void Warn(string text) => MessageBox.Show(this, text, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
}
