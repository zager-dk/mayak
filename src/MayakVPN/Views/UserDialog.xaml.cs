using System.Windows;
using Mayak.Core.Models;
using MayakVPN.ViewModels;

namespace MayakVPN.Views;

public partial class UserDialog : Window
{
    public UserEditResult? Result { get; private set; }

    public UserDialog(string title, VpnUser? existing)
    {
        InitializeComponent();
        Header.Text = title;
        if (existing != null)
        {
            NameBox.Text = existing.Name;
            NoteBox.Text = existing.Note;
        }
        Loaded += (_, _) => { NameBox.Focus(); NameBox.SelectAll(); };
    }

    private void Ok(object sender, RoutedEventArgs e)
    {
        var name = NameBox.Text.Trim();
        if (name.Length == 0)
        {
            MessageBox.Show(this, "Введите имя.", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        Result = new UserEditResult(name, NoteBox.Text.Trim());
        DialogResult = true;
    }
}
