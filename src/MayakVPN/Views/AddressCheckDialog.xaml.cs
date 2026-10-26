using System.Windows;
using System.Windows.Media;
using Mayak.Core.Probe;
using MayakVPN.ViewModels;

namespace MayakVPN.Views;

/// <summary>Выполняет проверку адреса: (адрес, прогресс, отмена) → отчёт.</summary>
public delegate Task<AddressCheckReport> AddressCheckRunner(string host, IProgress<string> progress, CancellationToken ct);

public partial class AddressCheckDialog : Window
{
    private readonly AddressCheckRunner _run;
    private CancellationTokenSource? _cts;

    public AddressCheckDialog(AddressCheckRunner run, string? host)
    {
        InitializeComponent();
        _run = run;
        HostBox.Text = host ?? "";
        Loaded += (_, _) =>
        {
            HostBox.Focus();
            HostBox.SelectAll();
            if (!string.IsNullOrWhiteSpace(host)) Run(this, new RoutedEventArgs());
        };
        Closed += (_, _) => _cts?.Cancel();
    }

    private async void Run(object sender, RoutedEventArgs e)
    {
        var host = AddressCheck.Normalize(HostBox.Text);
        if (!AddressCheck.IsValidHost(host))
        {
            MessageBox.Show(this, "Введите IP-адрес или домен сервера, например 194.87.125.238.", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            HostBox.Focus();
            return;
        }
        HostBox.Text = host;

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        RunButton.IsEnabled = false;
        HostBox.IsEnabled = false;
        VerdictCard.Visibility = Visibility.Collapsed;
        LinesList.ItemsSource = null;
        ProgressPanel.Visibility = Visibility.Visible;
        ProgressText.Text = "Проверка…";
        try
        {
            var report = await _run(host, new Progress<string>(m => ProgressText.Text = m), _cts.Token);
            Show(report);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, Title, MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            if (IsLoaded)
            {
                ProgressPanel.Visibility = Visibility.Collapsed;
                RunButton.IsEnabled = true;
                HostBox.IsEnabled = true;
                RunButton.Content = "Проверить ещё раз";
            }
        }
    }

    private void Show(AddressCheckReport r)
    {
        var (bg, badge, icon) = r.Verdict switch
        {
            CheckStatus.Ok => ("#E9F7EF", "#1F9D55", "✔"),
            CheckStatus.Fail => ("#FDECEC", "#D64545", "✖"),
            _ => ("#FFF4E0", "#E07B00", "!"),
        };
        VerdictCard.Background = Brush(bg);
        VerdictBadge.Background = Brush(badge);
        VerdictIcon.Text = icon;
        VerdictTitle.Text = r.VerdictTitle;
        VerdictText.Text = r.VerdictText;
        VerdictCard.Visibility = Visibility.Visible;
        LinesList.ItemsSource = r.Lines.Select(l => new CheckLineItem(l)).ToList();
    }

    private static SolidColorBrush Brush(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}
