// WinUI application bootstrap. It creates MainWindow and writes managed crash
// reports so UI failures can be diagnosed after the window closes.
using Microsoft.UI.Xaml;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace chat;

public partial class App : Application
{
    private Window? window;

    public App()
    {
        InitializeComponent();
        // 三类托管异常都写入 cr/，方便验收或调试时定位 UI 崩溃来源。
        UnhandledException += (_, e) => WriteCrashReport("Application.UnhandledException", e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            WriteCrashReport("AppDomain.UnhandledException", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            WriteCrashReport("TaskScheduler.UnobservedTaskException", e.Exception);
            e.SetObserved();
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // WinUI 应用真正的主窗口在这里创建；界面逻辑都在 MainWindow.xaml.cs。
        window = new MainWindow();
        window.Activate();
    }

    internal static void WriteCrashReport(string source, Exception? exception)
    {
        try
        {
            // 日志写在程序目录下，避免依赖额外服务；写失败时吞掉异常，防止二次崩溃。
            var directory = Path.Combine(AppContext.BaseDirectory, "cr");
            Directory.CreateDirectory(directory);
            var fileName = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff") + ".log";
            var path = Path.Combine(directory, fileName);
            var builder = new StringBuilder();
            builder.AppendLine("SecureChat crash report");
            builder.AppendLine("time: " + DateTime.Now.ToString("O"));
            builder.AppendLine("source: " + source);
            builder.AppendLine("base_directory: " + AppContext.BaseDirectory);
            builder.AppendLine();
            builder.AppendLine(exception?.ToString() ?? "No managed exception object was provided.");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }
        catch
        {
        }
    }
}
