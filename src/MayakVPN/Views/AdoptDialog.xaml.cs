using System.Windows;
using Mayak.Core.Models;

namespace MayakVPN.Views;

public partial class AdoptDialog : Window
{
    public VpnUser? SelectedUser { get; private set; }
    public DeviceKind SelectedKind { get; private set; } = DeviceKind.Other;

    public AdoptDialog(ForeignPeer peer, IReadOnlyList<VpnUser> users)
    {
        InitializeComponent();
        PeerText.Text = $"«{peer.Name}», IP {peer.Ip}";
        UserBox.ItemsSource = users.OrderBy(u => u.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        UserBox.SelectedIndex = 0;
        KindBox.ItemsSource = DeviceDialog.Kinds;
        KindBox.SelectedItem = DeviceDialog.Kinds.First(k => k.Kind == DeviceKind.Other);
    }

    private void Ok(object sender, RoutedEventArgs e)
    {
        SelectedUser = UserBox.SelectedItem as VpnUser;
        if (SelectedUser == null) return;
        SelectedKind = (KindBox.SelectedItem as KindOption)?.Kind ?? DeviceKind.Other;
        DialogResult = true;
    }
}
