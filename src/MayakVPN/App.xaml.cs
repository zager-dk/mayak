using System.IO;
using System.Windows;
using System.Windows.Threading;
using MayakVPN.Services;

namespace MayakVPN;

public partial class App : Application
{
    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(ProfileStore.Folder);
            File.AppendAllText(Path.Combine(ProfileStore.Folder, "crash.log"), $"{DateTime.Now:u}\n{e.Exception}\n\n");
        }
        catch { /* ignore */ }

        MessageBox.Show($"Непредвиденная ошибка:\n\n{e.Exception.Message}\n\nПодробности записаны в %APPDATA%\\MayakVPN\\crash.log",
            "Маяк VPN", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
