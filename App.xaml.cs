using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace DetectAcUI;

public partial class App : Application
{
    // Неперехваченные сбои пишем в лог — иначе краш посреди проверки останется без объяснения
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "sentinel");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "crash.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {e.Exception}\n\n");
        }
        catch
        {
            // лог недоступен — остаётся штатное поведение
        }
        e.Handled = false; // не глотаем: приложение падает, но причина зафиксирована
    }
}
