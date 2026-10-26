using System.Windows;
using System.Windows.Input;
using Mayak.Core.Models;
using Mayak.Core.Server;
using MayakVPN.Services;
using MayakVPN.ViewModels;

namespace MayakVPN.Views;

/// <summary>Постоянный список людей: изменения сразу сохраняются на компьютере.</summary>
public partial class PeopleWindow : Window
{
    private readonly List<Person> _people;
    private readonly ServerSnapshot? _snap;
    private readonly int _defaultDown, _defaultUp;

    private sealed record PersonRow(Person Model)
    {
        public string Name => Model.Name;
        public string Summary => Model.Devices.Count == 0
            ? "нет устройств"
            : string.Join(", ", Model.Devices.Select(d => d.Name));
    }

    private sealed record DeviceRow(PersonDevice Model)
    {
        public string Name => Model.Name;
        public string Kind => Model.Kind.Title();
        public string Limit => Model.DownMbps is int d && Model.UpMbps is int u
            ? (d == 0 && u == 0 ? "без лимита" : $"{(d == 0 ? "∞" : d)} / {(u == 0 ? "∞" : u)} Мбит/с")
            : "лимит сервера";
    }

    public PeopleWindow(ServerSnapshot? snap)
    {
        InitializeComponent();
        _snap = snap;
        _defaultDown = snap?.Db.DefaultDownMbps ?? 35;
        _defaultUp = snap?.Db.DefaultUpMbps ?? 35;
        _people = PeopleStore.Load();
        ImportButton.IsEnabled = snap != null && snap.Db.Users.Count > 0;
        ImportButton.ToolTip = snap == null ? "Откройте сервер, с которого взять пользователей" : $"Добавить в список пользователей с «{snap.Db.ServerTitle}»";
        RefreshPeople(_people.FirstOrDefault());
    }

    private Person? Selected => (PeopleList.SelectedItem as PersonRow)?.Model;
    private PersonDevice? SelectedDevice => (DevicesList.SelectedItem as DeviceRow)?.Model;

    private void Save()
    {
        try { PeopleStore.Save(_people); }
        catch (Exception ex) { MessageBox.Show(this, "Не удалось сохранить список: " + ex.Message, Title, MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void RefreshPeople(Person? select)
    {
        var rows = _people.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).Select(p => new PersonRow(p)).ToList();
        PeopleList.ItemsSource = rows;
        PeopleList.SelectedItem = rows.FirstOrDefault(r => r.Model == select);
        EmptyPeople.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        CountText.Text = rows.Count == 0 ? "Люди" : $"Люди · {rows.Count}";
        ShowPerson();
    }

    private void ShowPerson(PersonDevice? selectDevice = null)
    {
        var p = Selected;
        PersonPanel.Visibility = p == null ? Visibility.Collapsed : Visibility.Visible;
        NoPerson.Visibility = p == null && _people.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (p == null) return;
        PersonName.Text = p.Name;
        PersonNote.Text = p.Note;
        PersonNote.Visibility = string.IsNullOrWhiteSpace(p.Note) ? Visibility.Collapsed : Visibility.Visible;
        var rows = p.Devices.Select(d => new DeviceRow(d)).ToList();
        DevicesList.ItemsSource = rows;
        DevicesList.SelectedItem = rows.FirstOrDefault(r => r.Model == selectDevice);
        EmptyDevices.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void PersonSelected(object sender, System.Windows.Controls.SelectionChangedEventArgs e) => ShowPerson();

    private bool NameTaken(string name, Person? except) =>
        _people.Any(p => p != except && string.Equals(p.Name.Trim(), name.Trim(), StringComparison.CurrentCultureIgnoreCase));

    private void AddPerson(object sender, RoutedEventArgs e)
    {
        var dlg = new UserDialog("Новый человек", null) { Owner = this };
        if (dlg.ShowDialog() != true || dlg.Result == null) return;
        if (NameTaken(dlg.Result.Name, null)) { Warn($"«{dlg.Result.Name}» уже есть в списке."); return; }
        var person = new Person { Name = dlg.Result.Name, Note = dlg.Result.Note };
        _people.Add(person);
        Save();
        RefreshPeople(person);
        AddDevice(sender, e);
    }

    private void EditPerson(object sender, RoutedEventArgs e)
    {
        var p = Selected;
        if (p == null) return;
        var dlg = new UserDialog("Человек", new VpnUser { Name = p.Name, Note = p.Note }) { Owner = this };
        if (dlg.ShowDialog() != true || dlg.Result == null) return;
        if (NameTaken(dlg.Result.Name, p)) { Warn($"«{dlg.Result.Name}» уже есть в списке."); return; }
        p.Name = dlg.Result.Name;
        p.Note = dlg.Result.Note;
        Save();
        RefreshPeople(p);
    }

    private void PeopleList_DoubleClick(object sender, MouseButtonEventArgs e) => EditPerson(sender, e);

    private void DeletePerson(object sender, RoutedEventArgs e)
    {
        var p = Selected;
        if (p == null) return;
        if (MessageBox.Show(this, $"Убрать «{p.Name}» из списка?\n\nНа серверах ничего не изменится: выданный доступ продолжит работать.", Title,
                MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        _people.Remove(p);
        Save();
        RefreshPeople(null);
    }

    private void AddDevice(object sender, RoutedEventArgs e)
    {
        var p = Selected;
        if (p == null) return;
        var dlg = new DeviceDialog("Новое устройство", null, p.Name, _defaultDown, _defaultUp) { Owner = this };
        if (dlg.ShowDialog() != true || dlg.Result == null) return;
        var d = new PersonDevice { Name = dlg.Result.Name, Kind = dlg.Result.Kind, DownMbps = dlg.Result.DownMbps, UpMbps = dlg.Result.UpMbps };
        p.Devices.Add(d);
        Save();
        RefreshPeople(p);
        ShowPerson(d);
    }

    private void EditDevice(object sender, RoutedEventArgs e)
    {
        var p = Selected;
        var d = SelectedDevice;
        if (p == null || d == null) return;
        var temp = new VpnDevice { Name = d.Name, Kind = d.Kind, DownMbps = d.DownMbps ?? _defaultDown, UpMbps = d.UpMbps ?? _defaultUp };
        var dlg = new DeviceDialog("Устройство", temp, p.Name, _defaultDown, _defaultUp) { Owner = this };
        if (dlg.ShowDialog() != true || dlg.Result == null) return;
        d.Name = dlg.Result.Name;
        d.Kind = dlg.Result.Kind;
        d.DownMbps = dlg.Result.DownMbps;
        d.UpMbps = dlg.Result.UpMbps;
        Save();
        RefreshPeople(p);
        ShowPerson(d);
    }

    private void DevicesList_DoubleClick(object sender, MouseButtonEventArgs e) => EditDevice(sender, e);

    private void DeleteDevice(object sender, RoutedEventArgs e)
    {
        var p = Selected;
        var d = SelectedDevice;
        if (p == null || d == null) return;
        p.Devices.Remove(d);
        Save();
        RefreshPeople(p);
    }

    /// <summary>Добавляет в список пользователей открытого сервера, которых в нём ещё нет (и их устройства).</summary>
    private void Import(object sender, RoutedEventArgs e)
    {
        if (_snap == null) return;
        int newPeople = 0, newDevices = 0;
        foreach (var u in _snap.Db.Users)
        {
            var person = _people.FirstOrDefault(p => p.Id == u.PersonId)
                         ?? _people.FirstOrDefault(p => string.Equals(p.Name.Trim(), u.Name.Trim(), StringComparison.CurrentCultureIgnoreCase));
            if (person == null)
            {
                person = new Person { Name = u.Name, Note = u.Note };
                _people.Add(person);
                newPeople++;
            }
            foreach (var d in u.Devices.Where(d => d.CanExport))
            {
                bool known = person.Devices.Any(t => t.Id == d.TemplateId)
                             || person.Devices.Any(t => t.Kind == d.Kind && string.Equals(t.Name.Trim(), d.Name.Trim(), StringComparison.CurrentCultureIgnoreCase));
                if (known) continue;
                person.Devices.Add(new PersonDevice { Name = d.Name, Kind = d.Kind, DownMbps = d.DownMbps, UpMbps = d.UpMbps });
                newDevices++;
            }
        }
        Save();
        RefreshPeople(Selected ?? _people.FirstOrDefault());
        MessageBox.Show(this, newPeople == 0 && newDevices == 0
                ? "Все пользователи сервера уже есть в списке."
                : $"Добавлено в список: людей — {newPeople}, устройств — {newDevices}.",
            Title, MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Warn(string text) => MessageBox.Show(this, text, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
}
