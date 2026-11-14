using System.Windows.Media.Imaging;
using Windows.Data.Pdf;
using Windows.Storage;
using Windows.Storage.Streams;

namespace DscSync.App.Services;

/// <summary>Renders PDF pages with the PDF engine built into Windows 10 / Server 2019 (no extra components).</summary>
public static class PdfPreview
{
    public static async Task<BitmapSource> RenderAsync(string path, int pageIndex, uint width)
    {
        var file = await StorageFile.GetFileFromPathAsync(Path.GetFullPath(path));
        var doc = await PdfDocument.LoadFromFileAsync(file);
        using var page = doc.GetPage((uint)Math.Clamp(pageIndex, 0, (int)doc.PageCount - 1));
        using var stream = new InMemoryRandomAccessStream();
        await page.RenderToStreamAsync(stream, new PdfPageRenderOptions { DestinationWidth = width });
        var bmp = new BitmapImage();
        bmp.BeginInit();
        bmp.CacheOption = BitmapCacheOption.OnLoad;
        bmp.StreamSource = stream.AsStream();
        bmp.EndInit();
        bmp.Freeze();
        return bmp;
    }
}
