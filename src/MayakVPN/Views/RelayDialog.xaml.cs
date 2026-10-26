using System.Collections.ObjectModel;
using System.Windows;
using MayakVPN.Services;
using MayakVPN.ViewModels;

namespace MayakVPN.Views;

public partial class RelayDialog : Window
{
    private readonly ObservableCollection<ServerProfile> _candidates;
    private ServerProfile? _created;

    public RelaySetup? Result { get; private set; }

    public RelayDialog(ServerProfile main, IEnumerable<ServerProfile> candidates)
    {
        InitializeComponent();
        _candidates = new ObservableCollection<ServerProfile>(candidates);
        RelayBox.ItemsSource = _candidates;
        RelayBox.SelectionChanged += (_, _) => UpdateHost();
        RelayBox.SelectedItem = _candidates.FirstOrDefault(c => c.Id == main.RelayProfileId) ?? _candidates.FirstOrDefault();
        ManageCheck.IsChecked = main.RelayProfileId == null || main.ManageViaRelay;
        SshPortBox.Text = main.RelaySshPort.ToString();
        UpdateHost();
    }

    private void UpdateHost() =>
        RelayHostText.Text = RelayBox.SelectedItem is ServerProfile p ? $"Адрес: {p.Host}, SSH-порт {p.Port}" : "Добавьте входной сервер кнопкой «+ Новый сервер…».";

    private void AddNew(object sender, RoutedEventArgs e)
    {
        var dlg = new ServerDialog(null) { Owner = this };
        if (dlg.ShowDialog() != true || dlg.Result == null) return;
        _created = dlg.Result;
        if (string.IsNullOrWhiteSpace(_created.Name) || _created.Name == _created.Host)
            _created.Name = "Вход: " + _created.Host;
        _candidates.Add(_created);
        RelayBox.SelectedItem = _created;
    }

    private void Ok(object sender, RoutedEventArgs e)
    {
        if (RelayBox.SelectedItem is not ServerProfile relay)
        {
            MessageBox.Show(this, "Выберите или добавьте входной сервер.", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (!int.TryParse(SshPortBox.Text.Trim(), out var port) || port is < 1024 or > 65535 || port == relay.Port)
        {
            MessageBox.Show(this, "Порт SSH на входе — число от 1024 до 65535, не совпадающее с SSH самого входа.", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        Result = new RelaySetup(relay, relay == _created, ManageCheck.IsChecked == true, port);
        DialogResult = true;
    }
}
