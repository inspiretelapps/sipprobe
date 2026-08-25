using Avalonia;

namespace InspireTel.SipProbe.Mac;

internal static class Program
{
    public static string? StartupCfgPath { get; private set; }

    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Any(argument => argument is "--cli" or "--headless"))
            Environment.Exit(CliProbe.RunAsync(args).GetAwaiter().GetResult());

        StartupCfgPath = GetCfgPath(args);
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    private static string? GetCfgPath(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--cfg" or "--config" && i + 1 < args.Length)
                return args[i + 1];
            if (args[i].EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) && File.Exists(args[i]))
                return args[i];
        }
        return null;
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
