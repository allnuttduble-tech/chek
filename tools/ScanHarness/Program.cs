using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DetectAcUI.Scanning;

// Прогон всех сканеров на реальной машине (диагностика парсеров)
Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine($"IsAdmin={new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)}");

if (args.Contains("--report-ui", StringComparer.OrdinalIgnoreCase))
{
    // изолированный тест окна отчёта
    var engine = new ScanEngine("ru");
    foreach (var key in ScanEngine.StageKeys)
    {
        var res = await engine.RunStageAsync(key, CancellationToken.None);
        Console.WriteLine($"stage {key}: {res.Count} ({res.Status})");
    }
    var report = engine.BuildReport();
    report.IsAdmin = true;

    Exception? uiError = null;
    var thread = new Thread(() =>
    {
        try
        {
            var app = new System.Windows.Application { ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown };
            var w = new DetectAcUI.ReportWindow("ru", report);
            w.Loaded += (_, _) => Console.WriteLine("UI: report window loaded, title=" + w.Title);
            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(6) };
            timer.Tick += (_, _) => { Console.WriteLine("UI: closing after 6s, isLoaded=" + w.IsLoaded); timer.Stop(); w.Close(); };
            timer.Start();
            w.Show();
            Console.WriteLine("UI: Show() returned immediately, isLoaded=" + w.IsLoaded);
            var pump = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            var ticks = 0;
            pump.Tick += (_, _) => { ticks++; if (ticks == 10) Console.WriteLine("UI: window alive after 3s, isVisible=" + w.IsVisible); if (ticks >= 20) pump.Stop(); };
            pump.Start();
            app.Run();
        }
        catch (Exception ex)
        {
            uiError = ex;
        }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
    Console.WriteLine(uiError == null ? "UI: NO ERROR" : "UI ERROR: " + uiError);
    return;
}

var steam = SteamScanner.Scan();
Console.WriteLine($"[steam] accounts={steam.Accounts.Count} steamPath={steam.SteamPath ?? "-"} auto={steam.AutoLoginUser ?? "-"}");
foreach (var a in steam.Accounts.Take(5))
    Console.WriteLine($"   {a.SteamId64} | {a.AccountName} | {a.PersonaName} | {TimeUtils.Fmt(a.LastLogin)} | recent={a.MostRecent}");

var recent = RecentFilesScanner.Scan();
Console.WriteLine($"[recent] items={recent.Items.Count}");
foreach (var r in recent.Items.Take(5))
    Console.WriteLine($"   {TimeUtils.Fmt(r.LastOpen)} | {r.Name} -> {r.Target}");

var bags = ShellBagsScanner.Scan();
Console.WriteLine($"[shellbags] entries={bags.Entries.Count} deleted={bags.Entries.Count(e => e.Deleted)} recycled={bags.Entries.Count(e => e.IsRecycled)}");
foreach (var e in bags.Entries.Take(8))
    Console.WriteLine($"   {(e.Deleted ? "DEL" : e.IsRecycled ? "BIN" : "OK ")} | {TimeUtils.Fmt(e.DeletedTime ?? e.NodeTime)} | {e.Path}");

var pf = PrefetchScanner.Scan();
Console.WriteLine($"[prefetch] status={pf.Status} entries={pf.Entries.Count}");
foreach (var p in pf.Entries.Take(5))
    Console.WriteLine($"   {p.Executable} | runs={p.RunCount} | {TimeUtils.Fmt(p.LastRun)} | {p.PfFile}");

var hist = HistoryScanner.Scan();
Console.WriteLine($"[history] items={hist.Items.Count} browsers={string.Join(",", hist.BrowsersFound.Distinct())} trunc={hist.TruncatedAt}");
foreach (var h in hist.Items.Take(5))
{
    var t = h.Title.Length > 40 ? h.Title[..40] : h.Title;
    var u = h.Url.Length > 60 ? h.Url[..60] : h.Url;
    Console.WriteLine($"   {h.Browser}/{h.Profile} | {TimeUtils.Fmt(h.LastVisit)} | {t} | {u}");
}

var dma = DmaScanner.Scan();
Console.WriteLine($"[dma] devices={dma.Devices.Count} suspects={dma.Devices.Count(d => d.Suspect)} present={dma.Devices.Count(d => d.Present)}");
foreach (var d in dma.Devices.Where(d => d.Suspect).Take(5))
    Console.WriteLine($"   SUSPECT {d.Name} | {d.VendorDevice} | present={d.Present}");
foreach (var d in dma.Devices.Take(3))
    Console.WriteLine($"   {d.Name[..Math.Min(50, d.Name.Length)]} | {d.VendorDevice} | present={d.Present} problem={d.HasProblem}");

var gs = GamingSoftwareScanner.Scan();
Console.WriteLine($"[software] products={gs.Products.Count}");
foreach (var p in gs.Products)
{
    var folders = string.Join("; ", p.MacroFolders.Select(f => f.Path));
    Console.WriteLine($"   {p.Vendor} | {p.Name} | v={p.Version} | running={p.Running} | folders={folders}");
}

var usb = UsbScanner.Scan();
Console.WriteLine($"[usb] devices={usb.Devices.Count}");
foreach (var u in usb.Devices)
    Console.WriteLine($"   {u.Type} | {u.Name} | serial={u.Serial} | in={TimeUtils.Fmt(u.LastArrival)} | out={TimeUtils.Fmt(u.LastRemoval)} | first={TimeUtils.Fmt(u.FirstSeen)}");

Console.WriteLine("DONE");
