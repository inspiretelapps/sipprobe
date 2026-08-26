namespace InspireTel.SipProbe.App;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) => ReportFatal(e.ExceptionObject as Exception);
        Application.ThreadException += (_, e) => ReportFatal(e.Exception);
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

        try
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
        }
        catch (Exception ex)
        {
            ReportFatal(ex);
        }
    }

    private static void ReportFatal(Exception? ex)
    {
        if (ex is null)
            return;

        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "InspireTel-SIPProbe-crash.log");
        try
        {
            File.WriteAllText(path, $"{DateTimeOffset.Now:u}{Environment.NewLine}{ex}");
        }
        catch
        {
            path = "(could not be written)";
        }

        MessageBox.Show(
            $"{ex.GetType().Name}: {ex.Message}{Environment.NewLine}{Environment.NewLine}Details written to:{Environment.NewLine}{path}",
            "SIP Probe could not start",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }
}
