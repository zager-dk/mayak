using System.Windows;
using Mayak.Core.Models;
using Mayak.Core.Server;
using MayakVPN.Services;

namespace MayakVPN.Views;

/// <summary>Выбор людей из постоянного списка, которым выдать доступ на сервере.</summary>
public partial class GrantDialog : Window
{
    private readonly ServerSnapshot _snap;
    private List<Row> _rows = new();

    public IReadOnlyList<Person>? Result { get; private set; }

    public sealed class Row
    {
        public required Person Person { get; init; }
        public bool IsChecked { get; set; }
        public int NewDevices { get; init; }
        public bool NewUser { get; init; }
        public string Name => Person.Name;
        public string Status { get; init; } = "";
    }

    public GrantDialog(ServerSnapshot snap)
    {
        InitializeComponent();
        _snap = snap;
        Header.Text = $"Выдать доступ на «{snap.Db.ServerTitle}»";
        Load(checkAll: true);
    }

    private void Load(bool checkAll)
    {
        var people = PeopleStore.Load();
        _rows = people.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).Select(p =>
        {
            var user = MayakServer.FindUser(_snap.Db, p);
            int missing = p.Devices.Count(t => user == null || MayakServer.FindDevice(user, t) == null);
            string status = p.Devices.Count == 0 ? "в списке нет устройств"
                : user == null ? $"новый пользователь, устройств: {p.Devices.Count} ({string.Join(", ", p.Devices.Select(d => d.Name))})"
                : missing > 0 ? $"добавится устройств: {missing}; остальные уже выданы"
                : "всё уже выдано — файлы будут сохранены заново";
            if (user is { Enabled: false }) status += " · доступ приостановлен на сервере";
            return new Row { Person = p, IsChecked = checkAll && p.Devices.Count > 0, NewDevices = missing, NewUser = user == null, Status = status };
        }).ToList();
        PeopleList.ItemsSource = _rows;
        UpdateSummary();
    }

    private void UpdateSummary()
    {
        var chosen = _rows.Where(r => r.IsChecked).ToList();
        int newDevices = chosen.Sum(r => r.NewDevices);
        SummaryText.Text = _rows.Count == 0
            ? "Список людей пуст — нажмите «Изменить список…»."
            : $"Отмечено: {chosen.Count} из {_rows.Count} · новых устройств: {newDevices}";
        OkButton.IsEnabled = chosen.Count > 0;
    }

    private void Reselect(Func<Row, bool> pick)
    {
        foreach (var r in _rows) r.IsChecked = pick(r) && r.Person.Devices.Count > 0;
        PeopleList.ItemsSource = null;
        PeopleList.ItemsSource = _rows;
        UpdateSummary();
    }

    private void SelectAll(object sender, RoutedEventArgs e) => Reselect(_ => true);
    private void SelectNew(object sender, RoutedEventArgs e) => Reselect(r => r.NewDevices > 0);
    private void SelectNone(object sender, RoutedEventArgs e) => Reselect(_ => false);
    private void CheckChanged(object sender, RoutedEventArgs e) => UpdateSummary();

    private void EditList(object sender, RoutedEventArgs e)
    {
        new PeopleWindow(_snap) { Owner = this }.ShowDialog();
        Load(checkAll: true);
    }

    private void Ok(object sender, RoutedEventArgs e)
    {
        Result = _rows.Where(r => r.IsChecked).Select(r => r.Person).ToList();
        DialogResult = true;
    }
}
