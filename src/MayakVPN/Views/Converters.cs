using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace MayakVPN.Views;

/// <summary>true → Visible. Parameter "invert" — наоборот.</summary>
public sealed class BoolToVisibility : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool b = value is true;
        if (parameter as string == "invert") b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>null/пустая строка/0 → Collapsed. Parameter "invert" — наоборот.</summary>
public sealed class NotEmptyToVisibility : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool has = value switch
        {
            null => false,
            string s => s.Length > 0,
            int i => i > 0,
            System.Collections.ICollection c => c.Count > 0,
            _ => true,
        };
        if (parameter as string == "invert") has = !has;
        return has ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>on / idle / off / warn → цвет точки статуса.</summary>
public sealed class StatusToBrush : IValueConverter
{
    private static readonly Brush On = Freeze(new SolidColorBrush(Color.FromRgb(0x1F, 0x9D, 0x55)));
    private static readonly Brush Idle = Freeze(new SolidColorBrush(Color.FromRgb(0xB8, 0xC2, 0xD0)));
    private static readonly Brush Off = Freeze(new SolidColorBrush(Color.FromRgb(0xD6, 0x45, 0x45)));
    private static readonly Brush Warn = Freeze(new SolidColorBrush(Color.FromRgb(0xE0, 0x7B, 0x00)));

    private static Brush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        "on" or true => On,
        "off" => Off,
        "warn" => Warn,
        _ => Idle,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}
