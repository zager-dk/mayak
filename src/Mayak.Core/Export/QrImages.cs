using QRCoder;

namespace Mayak.Core.Export;

/// <summary>PNG с QR-кодом (без зависимостей от System.Drawing).</summary>
public static class QrImages
{
    public static byte[] Png(string text, int pixelsPerModule = 8)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.L);
        var png = new PngByteQRCode(data);
        return png.GetGraphic(pixelsPerModule);
    }
}
