using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using Avalonia.Threading;
using InspireTel.SipProbe.Core;

namespace InspireTel.SipProbe.Mac;

public sealed class MainWindow : Window
{
    private readonly TextBox _server = Field("pbx.example.com");
    private readonly NumericUpDown _port = NumberField(1, 65535, 5061);
    private readonly ComboBox _transport = new() { HorizontalAlignment = HorizontalAlignment.Stretch, MinHeight = 34 };
    private readonly TextBox _sipUser = Field("Extension / SIP user");
    private readonly TextBox _authName = Field("Registration / authentication name");
    private readonly TextBox _password = Field("Not saved or logged");
    private readonly NumericUpDown _localPort = NumberField(0, 65535, 0);
    private readonly NumericUpDown _expiry = NumberField(30, 86400, 600);
    private readonly NumericUpDown _timeout = NumberField(2, 60, 7);
    private readonly CheckBox _forceTls12 = new() { Content = "Force TLS 1.2", IsChecked = true };
    private readonly CheckBox _ignoreCertificateErrors = new() { Content = "Ignore certificate errors (diagnostic only)" };
    private readonly NumericUpDown _udpPort = NumberField(1, 65535, 5060);
    private readonly NumericUpDown _tcpPort = NumberField(1, 65535, 5060);
    private readonly NumericUpDown _tlsPort = NumberField(1, 65535, 5061);
    private readonly TextBox _apiUrl = Field("https://tenant.pbx.yeastarycm.co.za");
    private readonly TextBox _apiClientId = Field("OpenAPI Client ID");
    private readonly TextBox _apiSecret = Field("Not saved or logged");
    private IReadOnlyList<string> _ntpServers = Array.Empty<string>();

    private readonly StackPanel _logLines = new() { Spacing = 1 };
    private readonly ScrollViewer _logScroll = new()
    {
        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto
    };

    private readonly Button _runRegister = new();
    private readonly Button _runMatrix = new();
    private readonly Button _checkPbx = new();
    private readonly Button _loadCfg = new();
    private readonly Button _stop = new();
    private readonly Button _clear = new();
    private readonly Button _export = new();
    private readonly ToggleSwitch _darkMode = new()
    {
        OnContent = "Dark",
        OffContent = "Light",
        VerticalAlignment = VerticalAlignment.Center
    };

    private readonly TextBlock _status = new()
    {
        Text = "Ready",
        VerticalAlignment = VerticalAlignment.Center,
        TextTrimming = TextTrimming.CharacterEllipsis
    };
    private readonly TextBlock _title = new() { Text = "SIP Probe", FontSize = 22, FontWeight = FontWeight.SemiBold, LetterSpacing = -0.4 };
    private readonly TextBlock _subtitle = new()
    {
        Text = "Find out why a handset will not register — without guessing.",
        FontSize = 12.5
    };
    private readonly Border _header = new();
    private readonly Border _leftCard = new() { CornerRadius = new CornerRadius(14), Padding = new Thickness(16, 14, 16, 14) };
    private readonly Border _rightCard = new() { CornerRadius = new CornerRadius(14), ClipToBounds = true };
    private readonly Border _logToolbar = new();
    private readonly Border _statusBar = new();
    private readonly List<TextBlock> _mutedLabels = new();

    private readonly List<DiagnosticLogEntry> _allEntries = new();
    private CancellationTokenSource? _activeRun;
    private bool _applyingTheme;

    public MainWindow()
    {
        Title = "InspireTel SIP Probe";
        Width = 1280;
        Height = 800;
        MinWidth = 1080;
        MinHeight = 700;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        FontFamily = new FontFamily("SF Pro Text, Helvetica Neue, system-ui");
        FontSize = 13;

        _password.PasswordChar = '•';
        _apiSecret.PasswordChar = '•';
        _logScroll.Content = _logLines;
        _stop.IsEnabled = false;

        StyleAction(_loadCfg, "Load phone config", "Reads a Yealink .cfg and fills the fields. The password stays in memory and is never logged.", false);
        StyleAction(_runMatrix, "Test path", "Tries UDP, TCP and TLS without the password. A 401 means the PBX is reachable. Safe first step — it will not lock the extension.", false);
        StyleAction(_runRegister, "Prove login", "Sends one authenticated REGISTER with these credentials, then removes it. Use after Test path succeeds.", true);
        StyleAction(_checkPbx, "Check PBX", "Asks the Yeastar API whether this extension is online, assigned a phone, or on the blocked-IP list. Needs Client ID and Secret under Advanced.", false);
        StyleAction(_stop, "Stop", "Cancels the test that is currently running.", false);
        StyleGhost(_clear, "Clear");
        StyleGhost(_export, "Export");

        _transport.ItemsSource = Enum.GetNames<SipTransport>();
        _transport.SelectedItem = SipTransport.Tls.ToString();
        _transport.SelectionChanged += (_, _) =>
        {
            _port.Value = MatrixPortFor(SelectedTransport());
            var tls = SelectedTransport() == SipTransport.Tls;
            _forceTls12.IsEnabled = tls;
            _ignoreCertificateErrors.IsEnabled = tls;
        };
        _ignoreCertificateErrors.IsCheckedChanged += async (_, _) =>
        {
            if (_ignoreCertificateErrors.IsChecked == true)
            {
                await ShowAlert(
                    "Diagnostic-only certificate bypass",
                    "Certificate validation will be bypassed only inside this diagnostic run. Do not treat a successful result with this option as proof that the handset will trust the certificate.");
            }
        };

        _runRegister.Click += async (_, _) => await RunAuthenticatedAsync();
        _runMatrix.Click += async (_, _) => await RunMatrixAsync();
        _checkPbx.Click += async (_, _) => await RunPbxCheckAsync();
        _loadCfg.Click += async (_, _) => await LoadYealinkConfigAsync();
        _stop.Click += (_, _) => _activeRun?.Cancel();
        _clear.Click += (_, _) => ClearLog();
        _export.Click += async (_, _) => await ExportLogAsync();
        _darkMode.IsCheckedChanged += (_, _) =>
        {
            if (_applyingTheme || Application.Current is null)
                return;
            Application.Current.RequestedThemeVariant = _darkMode.IsChecked == true ? ThemeVariant.Dark : ThemeVariant.Light;
            ApplyChrome();
        };

        Content = BuildRoot();
        ApplyChrome();
        ActualThemeVariantChanged += (_, _) => ApplyChrome();
        AppendWelcome();
        Opened += async (_, _) =>
        {
            SyncDarkToggle();
            if (string.IsNullOrWhiteSpace(Program.StartupCfgPath))
                return;
            try
            {
                ApplyYealinkSettings(Program.StartupCfgPath, YealinkConfigParser.Parse(await File.ReadAllLinesAsync(Program.StartupCfgPath)));
            }
            catch (Exception ex)
            {
                await ShowAlert("Could not load Yealink configuration", ex.Message);
            }
        };
    }

    private Control BuildRoot()
    {
        var root = new Grid { RowDefinitions = RowDefinitions.Parse("64,*,36") };
        var header = BuildHeader();
        var body = BuildBody();
        var status = BuildStatusBar();
        Grid.SetRow(header, 0);
        Grid.SetRow(body, 1);
        Grid.SetRow(status, 2);
        root.Children.Add(header);
        root.Children.Add(body);
        root.Children.Add(status);
        return root;
    }

    private Control BuildHeader()
    {
        _header.Padding = new Thickness(22, 0, 18, 0);
        var grid = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("Auto,*,Auto") };
        var mark = new Border
        {
            Width = 8,
            Height = 28,
            CornerRadius = new CornerRadius(3),
            Background = Accent(),
            Margin = new Thickness(0, 0, 12, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        var titles = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Center };
        titles.Children.Add(_title);
        titles.Children.Add(_subtitle);
        var brand = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 0,
            VerticalAlignment = VerticalAlignment.Center,
            Children = { mark, titles }
        };
        var tools = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 14,
            VerticalAlignment = VerticalAlignment.Center,
            Children =
            {
                _darkMode,
                Muted("v1.3  ·  passwords never logged")
            }
        };
        Grid.SetColumn(tools, 2);
        grid.Children.Add(brand);
        grid.Children.Add(tools);
        _header.Child = grid;
        return _header;
    }

    private Control BuildBody()
    {
        var body = new Grid
        {
            ColumnDefinitions = ColumnDefinitions.Parse("430,14,*"),
            Margin = new Thickness(16, 10, 16, 8)
        };
        _leftCard.Child = BuildConfigurationPanel();
        _rightCard.Child = BuildLogPanel();
        Grid.SetColumn(_rightCard, 2);
        body.Children.Add(_leftCard);
        body.Children.Add(_rightCard);
        return body;
    }

    private Control BuildConfigurationPanel()
    {
        var panel = new Grid { RowDefinitions = RowDefinitions.Parse("Auto,*,Auto") };
        var intro = new StackPanel { Spacing = 2, Margin = new Thickness(0, 0, 0, 10) };
        intro.Children.Add(SectionTitle("Endpoint"));
        intro.Children.Add(Muted("Same values as the handset. Load a Yealink cfg if you have one."));

        var fields = new StackPanel { Spacing = 8 };
        fields.Children.Add(Labeled("PBX hostname", _server, "DNS name of the Cloud PBX, not an IP, when using TLS."));
        fields.Children.Add(TwoCol(
            Labeled("Transport", _transport, "Must match the extension on the PBX. Yeastar Cloud remote phones usually use TLS."),
            Labeled("Port", _port, "Destination port for Prove login. TLS is typically 5061; UDP/TCP 5060.")));
        fields.Children.Add(TwoCol(
            Labeled("SIP user", _sipUser, "Extension number, for example 101."),
            Labeled("Auth name", _authName, "P-Series Registration Name. Often different from the extension number.")));
        fields.Children.Add(Labeled("Password", BuildPasswordField(_password), "Registration password. Never written to the log or export."));

        var advanced = new Expander
        {
            Header = "Advanced — extra ports, TLS, PBX API",
            IsExpanded = false,
            Margin = new Thickness(0, 6, 0, 0),
            Content = BuildAdvanced()
        };

        var mid = new StackPanel { Spacing = 0 };
        mid.Children.Add(fields);
        mid.Children.Add(advanced);

        var actions = BuildActionPanel();
        Grid.SetRow(mid, 1);
        Grid.SetRow(actions, 2);
        panel.Children.Add(intro);
        panel.Children.Add(mid);
        panel.Children.Add(actions);
        return panel;
    }

    private Control BuildAdvanced()
    {
        var stack = new StackPanel { Spacing = 8, Margin = new Thickness(0, 8, 0, 4) };
        stack.Children.Add(Muted("These stay hidden for the usual cfg workflow."));
        stack.Children.Add(ThreeCol(
            Labeled("Local port", _localPort, "0 = automatic. Change only if you are testing a specific source port."),
            Labeled("Expiry", _expiry, "REGISTER Expires. Yeastar Cloud minimum is often 600."),
            Labeled("Timeout", _timeout, "Seconds to wait for each network step.")));
        stack.Children.Add(TlsOptions());
        stack.Children.Add(SectionTitle("Path test ports"));
        stack.Children.Add(Muted("Test path tries all three. A custom Prove login port is added if it is different."));
        stack.Children.Add(ThreeCol(
            Labeled("UDP", _udpPort, "UDP listener to try during Test path."),
            Labeled("TCP", _tcpPort, "TCP listener to try during Test path."),
            Labeled("TLS", _tlsPort, "TLS listener to try during Test path.")));
        stack.Children.Add(SectionTitle("PBX API"));
        stack.Children.Add(Muted("Settings → Integrations → API. Leave URL blank to use https:// plus the hostname."));
        stack.Children.Add(Labeled("API URL", _apiUrl, "Yeastar web URL. Blank means https:// plus the PBX hostname."));
        stack.Children.Add(TwoCol(
            Labeled("Client ID", _apiClientId, "OpenAPI Client ID from the PBX."),
            Labeled("Client secret", BuildPasswordField(_apiSecret), "OpenAPI Client Secret. Never logged.")));
        return stack;
    }

    private Control TlsOptions()
    {
        _ignoreCertificateErrors.Foreground = new SolidColorBrush(Color.FromRgb(196, 92, 64));
        var stack = new StackPanel { Spacing = 4 };
        stack.Children.Add(_forceTls12);
        stack.Children.Add(_ignoreCertificateErrors);
        return stack;
    }

    private static Control BuildPasswordField(TextBox password)
    {
        var show = new Button
        {
            Content = "Show",
            Width = 58,
            Height = 30,
            Padding = new Thickness(0)
        };
        show.PointerPressed += (_, _) => password.PasswordChar = '\0';
        show.PointerReleased += (_, _) => password.PasswordChar = '•';
        show.PointerExited += (_, _) => password.PasswordChar = '•';
        var row = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,6,Auto") };
        Grid.SetColumn(show, 2);
        row.Children.Add(password);
        row.Children.Add(show);
        return row;
    }

    private Control BuildActionPanel()
    {
        var grid = new Grid
        {
            ColumnDefinitions = ColumnDefinitions.Parse("*,10,*"),
            RowDefinitions = RowDefinitions.Parse("Auto,8,Auto,8,Auto"),
            Margin = new Thickness(0, 14, 0, 0)
        };
        Place(grid, _loadCfg, 0, 0);
        Place(grid, _runMatrix, 0, 2);
        Place(grid, _runRegister, 2, 0);
        Place(grid, _checkPbx, 2, 2);
        Grid.SetColumnSpan(_stop, 3);
        Place(grid, _stop, 4, 0);
        foreach (var button in new[] { _loadCfg, _runMatrix, _runRegister, _checkPbx, _stop })
            button.HorizontalAlignment = HorizontalAlignment.Stretch;
        return grid;
    }

    private Control BuildLogPanel()
    {
        var panel = new Grid { RowDefinitions = RowDefinitions.Parse("48,*") };
        var toolbar = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,Auto,Auto"), Margin = new Thickness(14, 0) };
        var title = new TextBlock
        {
            Text = "Live trace",
            Foreground = new SolidColorBrush(Color.FromRgb(210, 230, 226)),
            FontWeight = FontWeight.SemiBold,
            FontSize = 13,
            VerticalAlignment = VerticalAlignment.Center
        };
        _clear.Margin = new Thickness(0, 0, 8, 0);
        Grid.SetColumn(_clear, 1);
        Grid.SetColumn(_export, 2);
        toolbar.Children.Add(title);
        toolbar.Children.Add(_clear);
        toolbar.Children.Add(_export);
        _logToolbar.Child = toolbar;
        _logToolbar.Background = new SolidColorBrush(Color.FromRgb(16, 28, 30));
        _logScroll.Background = new SolidColorBrush(Color.FromRgb(10, 18, 20));
        _logScroll.Padding = new Thickness(12, 8);
        Grid.SetRow(_logScroll, 1);
        panel.Children.Add(_logToolbar);
        panel.Children.Add(_logScroll);
        return panel;
    }

    private Control BuildStatusBar()
    {
        _statusBar.Padding = new Thickness(22, 0, 16, 0);
        var bar = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,Auto") };
        var help = new Button
        {
            Content = "How to read results",
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Foreground = Accent(),
            Padding = new Thickness(8, 4),
            VerticalAlignment = VerticalAlignment.Center
        };
        help.Click += async (_, _) => await ShowAlert("How to read results", InterpretationText);
        Grid.SetColumn(help, 1);
        bar.Children.Add(_status);
        bar.Children.Add(help);
        _statusBar.Child = bar;
        return _statusBar;
    }

    private async Task RunAuthenticatedAsync()
    {
        DiagnosticProfile profile;
        try
        {
            profile = ReadProfile(authenticate: true).Validate();
        }
        catch (Exception ex)
        {
            await ShowAlert("Check the probe configuration", ex.Message);
            return;
        }

        AppendSeparator($"PROVE LOGIN  {profile.Transport.ToString().ToUpperInvariant()}");
        await RunOneAsync(profile);
    }

    private async Task RunMatrixAsync()
    {
        DiagnosticProfile baseProfile;
        try
        {
            baseProfile = ReadProfile(authenticate: false).Validate();
        }
        catch (Exception ex)
        {
            await ShowAlert("Check the probe configuration", ex.Message);
            return;
        }

        SetRunning(true, "Testing UDP, TCP and TLS without a password...");
        _activeRun = new CancellationTokenSource();
        try
        {
            foreach (var item in baseProfile.MatrixTargets())
            {
                _activeRun.Token.ThrowIfCancellationRequested();
                AppendSeparator($"TEST PATH  {item.Transport.ToString().ToUpperInvariant()} / {item.Port}");
                var profile = baseProfile with
                {
                    Transport = item.Transport,
                    Port = item.Port,
                    Authenticate = false,
                    Password = string.Empty
                };
                await ExecuteEngineAsync(profile, _activeRun.Token);
            }
            _status.Text = "Path test complete";
        }
        catch (OperationCanceledException)
        {
            AppendLocal(DiagnosticLevel.Warning, "Test cancelled by the operator.");
            _status.Text = "Cancelled";
        }
        finally
        {
            _activeRun.Dispose();
            _activeRun = null;
            SetRunning(false, _status.Text ?? "Ready");
        }
    }

    private async Task RunOneAsync(DiagnosticProfile profile)
    {
        SetRunning(true, "Proving login...");
        _activeRun = new CancellationTokenSource();
        try
        {
            var result = await ExecuteEngineAsync(profile, _activeRun.Token);
            _status.Text = result.Registered
                ? "Login succeeded"
                : result.SipResponseReceived
                    ? $"PBX replied {result.FinalStatusCode}"
                    : result.Summary;
        }
        catch (OperationCanceledException)
        {
            AppendLocal(DiagnosticLevel.Warning, "Test cancelled by the operator.");
            _status.Text = "Cancelled";
        }
        finally
        {
            _activeRun.Dispose();
            _activeRun = null;
            SetRunning(false, _status.Text ?? "Ready");
        }
    }

    private async Task<DiagnosticResult> ExecuteEngineAsync(DiagnosticProfile profile, CancellationToken token)
    {
        var engine = new SipDiagnosticEngine();
        engine.EntryAdded += entry => Dispatcher.UIThread.Post(() => AppendEntry(entry));
        return await engine.RunAsync(profile, token);
    }

    private async Task RunPbxCheckAsync()
    {
        if (string.IsNullOrWhiteSpace(_sipUser.Text))
        {
            await ShowAlert("Check the probe configuration", "Enter the SIP user / extension first.");
            return;
        }

        if (string.IsNullOrWhiteSpace(_apiClientId.Text) || string.IsNullOrWhiteSpace(_apiSecret.Text))
        {
            await ShowAlert("Check PBX",
                "Open Advanced and enter the Yeastar OpenAPI Client ID and Client Secret. They are under Settings → Integrations → API on the PBX.");
            return;
        }

        var apiUrl = string.IsNullOrWhiteSpace(_apiUrl.Text)
            ? "https://" + (_server.Text ?? string.Empty).Trim()
            : _apiUrl.Text.Trim();

        AppendSeparator("CHECK PBX");
        SetRunning(true, "Checking PBX...");
        _activeRun = new CancellationTokenSource();
        try
        {
            var diagnostic = new YeastarPbxDiagnostic();
            diagnostic.EntryAdded += entry => Dispatcher.UIThread.Post(() => AppendEntry(entry));
            await diagnostic.RunAsync(new YeastarPbxCheckRequest
            {
                ApiBaseUrl = apiUrl,
                ClientId = _apiClientId.Text,
                ClientSecret = _apiSecret.Text,
                ExtensionNumber = _sipUser.Text,
                AuthenticationName = _authName.Text ?? string.Empty,
                TimeoutSeconds = (int)(_timeout.Value ?? 7)
            }, _activeRun.Token);
            _status.Text = "PBX check complete";
        }
        catch (OperationCanceledException)
        {
            AppendLocal(DiagnosticLevel.Warning, "Test cancelled by the operator.");
            _status.Text = "Cancelled";
        }
        catch (Exception ex)
        {
            AppendLocal(DiagnosticLevel.Error, ex.Message);
            _status.Text = "PBX check failed";
        }
        finally
        {
            _activeRun.Dispose();
            _activeRun = null;
            SetRunning(false, _status.Text ?? "Ready");
        }
    }

    private DiagnosticProfile ReadProfile(bool authenticate) => new()
    {
        Server = _server.Text ?? string.Empty,
        Port = (int)(_port.Value ?? 5061),
        UdpPort = (int)(_udpPort.Value ?? 5060),
        TcpPort = (int)(_tcpPort.Value ?? 5060),
        TlsPort = (int)(_tlsPort.Value ?? 5061),
        Transport = SelectedTransport(),
        SipUser = _sipUser.Text ?? string.Empty,
        AuthenticationName = _authName.Text ?? string.Empty,
        Password = authenticate ? _password.Text ?? string.Empty : string.Empty,
        LocalPort = (int)(_localPort.Value ?? 0),
        RegistrationExpirySeconds = (int)(_expiry.Value ?? 600),
        TimeoutSeconds = (int)(_timeout.Value ?? 7),
        ForceTls12 = _forceTls12.IsChecked == true,
        IgnoreTlsCertificateErrors = _ignoreCertificateErrors.IsChecked == true,
        Authenticate = authenticate,
        NtpServers = _ntpServers
    };

    private SipTransport SelectedTransport() =>
        Enum.TryParse<SipTransport>(_transport.SelectedItem?.ToString(), out var value) ? value : SipTransport.Tls;

    private decimal MatrixPortFor(SipTransport transport) => transport switch
    {
        SipTransport.Udp => _udpPort.Value ?? 5060,
        SipTransport.Tcp => _tcpPort.Value ?? 5060,
        _ => _tlsPort.Value ?? 5061
    };

    private void SetRunning(bool running, string status)
    {
        _runRegister.IsEnabled = !running;
        _runMatrix.IsEnabled = !running;
        _checkPbx.IsEnabled = !running;
        _loadCfg.IsEnabled = !running;
        _stop.IsEnabled = running;
        _transport.IsEnabled = !running;
        _status.Text = status;
        Cursor = running ? new Cursor(StandardCursorType.Wait) : Cursor.Default;
    }

    private void AppendWelcome()
    {
        AppendLocal(DiagnosticLevel.Info, "Load a phone config, then Test path. A 401 means the PBX is reachable. Then Prove login.");
        AppendLocal(DiagnosticLevel.Detail, "Hover the ⓘ on a button for what it does. Passwords are never logged.");
    }

    private void AppendSeparator(string title)
    {
        var line = Environment.NewLine + "──  " + title + "  ──";
        AppendLogVisual(line, Color.FromRgb(94, 234, 212));
        _logScroll.ScrollToEnd();
    }

    private void AppendLocal(DiagnosticLevel level, string message) =>
        AppendEntry(new DiagnosticLogEntry(DateTimeOffset.Now, level, message));

    private void AppendEntry(DiagnosticLogEntry entry)
    {
        _allEntries.Add(entry);
        var color = entry.Level switch
        {
            DiagnosticLevel.Success => Color.FromRgb(52, 211, 153),
            DiagnosticLevel.Warning => Color.FromRgb(251, 191, 36),
            DiagnosticLevel.Error => Color.FromRgb(248, 113, 113),
            DiagnosticLevel.Detail => Color.FromRgb(148, 163, 184),
            _ => Color.FromRgb(226, 232, 240)
        };
        AppendLogVisual(entry.ToString(), color);
        _logScroll.ScrollToEnd();
    }

    private void AppendLogVisual(string text, Color color)
    {
        _logLines.Children.Add(new SelectableTextBlock
        {
            Text = text,
            Foreground = new SolidColorBrush(color),
            FontFamily = new FontFamily("IBM Plex Mono, Menlo, SF Mono, ui-monospace, monospace"),
            FontSize = 12,
            TextWrapping = TextWrapping.NoWrap
        });
    }

    private void ClearLog()
    {
        _allEntries.Clear();
        _logLines.Children.Clear();
        AppendWelcome();
    }

    private async Task ExportLogAsync()
    {
        var top = GetTopLevel(this);
        if (top is null)
            return;
        var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export redacted SIP diagnostic log",
            SuggestedFileName = $"SIPProbe-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            DefaultExtension = "txt",
            FileTypeChoices = new[]
            {
                new FilePickerFileType("Text log") { Patterns = new[] { "*.txt" } }
            }
        });
        if (file is null)
            return;

        var path = file.TryGetLocalPath() ?? file.Path.LocalPath;
        var header = new[]
        {
            "InspireTel SIP Probe v1.3 (macOS)",
            $"Exported: {DateTimeOffset.Now:u}",
            $"Server: {(_server.Text ?? string.Empty).Trim()}:{_port.Value}",
            $"Transport: {_transport.SelectedItem}",
            $"SIP user: {(_sipUser.Text ?? string.Empty).Trim()}",
            $"Authentication name: {(_authName.Text ?? string.Empty).Trim()}",
            "Password/digest: REDACTED",
            new string('-', 72)
        };
        await File.WriteAllLinesAsync(path, header.Concat(_allEntries.Select(entry => entry.ToString())));
        _status.Text = $"Log exported to {path}";
    }

    private async Task LoadYealinkConfigAsync()
    {
        var top = GetTopLevel(this);
        if (top is null)
            return;
        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Load a generated Yealink configuration",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Yealink configuration") { Patterns = new[] { "*.cfg" } },
                new FilePickerFileType("Text files") { Patterns = new[] { "*.txt" } },
                FilePickerFileTypes.All
            }
        });
        var file = files.FirstOrDefault();
        if (file is null)
            return;

        try
        {
            var path = file.TryGetLocalPath() ?? file.Path.LocalPath;
            ApplyYealinkSettings(path, YealinkConfigParser.Parse(await File.ReadAllLinesAsync(path)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            await ShowAlert("Could not load Yealink configuration", ex.Message);
        }
    }

    private void ApplyYealinkSettings(string path, YealinkAccountSettings settings)
    {
        var loaded = settings.LoadedFields;
        if (loaded.Count == 0)
            throw new FormatException("No supported account.1 Yealink SIP parameters were found.");

        if (settings.Server is not null)
            _server.Text = settings.Server;
        if (settings.SipUser is not null)
            _sipUser.Text = settings.SipUser;
        if (settings.AuthenticationName is not null)
            _authName.Text = settings.AuthenticationName;
        if (settings.Password is not null)
            _password.Text = settings.Password;
        if (settings.Transport is not null)
            _transport.SelectedItem = settings.Transport.Value.ToString();
        if (settings.Port is not null)
        {
            _port.Value = settings.Port.Value;
            switch (settings.Transport ?? SelectedTransport())
            {
                case SipTransport.Udp:
                    _udpPort.Value = settings.Port.Value;
                    break;
                case SipTransport.Tcp:
                    _tcpPort.Value = settings.Port.Value;
                    break;
                default:
                    _tlsPort.Value = settings.Port.Value;
                    break;
            }
        }

        if (settings.ExpirySeconds is not null &&
            settings.ExpirySeconds.Value >= _expiry.Minimum &&
            settings.ExpirySeconds.Value <= _expiry.Maximum)
        {
            _expiry.Value = settings.ExpirySeconds.Value;
        }

        _ntpServers = settings.NtpServers;
        if (string.IsNullOrWhiteSpace(_apiUrl.Text) && !string.IsNullOrWhiteSpace(_server.Text))
            _apiUrl.Text = "https://" + _server.Text.Trim();

        AppendLocal(DiagnosticLevel.Info,
            $"Loaded Yealink config '{Path.GetFileName(path)}': {string.Join(", ", loaded)}.");
        AppendLocal(DiagnosticLevel.Detail,
            "The file remains local. Its password is held only in the password field and is never logged or exported.");
        foreach (var finding in ClockCertificateCheck.AnalyzeNtpServers(_ntpServers))
            AppendLocal(finding.Level, finding.Message);
        foreach (var warning in settings.Warnings())
            AppendLocal(warning.Level, warning.Message);
        _status.Text = $"Loaded {Path.GetFileName(path)}";
    }

    private async Task ShowAlert(string title, string message)
    {
        var ok = new Button { Content = "OK", Width = 88, HorizontalAlignment = HorizontalAlignment.Right };
        var dialog = new Window
        {
            Title = title,
            Width = 520,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false,
            Content = new StackPanel
            {
                Margin = new Thickness(22),
                Spacing = 16,
                Children =
                {
                    new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
                    ok
                }
            }
        };
        ok.Click += (_, _) => dialog.Close();
        await dialog.ShowDialog(this);
    }

    private void ApplyChrome()
    {
        var dark = IsDark;
        _applyingTheme = true;
        try
        {
            SyncDarkToggle();
            Background = dark ? Rgb(14, 18, 19) : Rgb(232, 238, 236);
            _header.Background = dark ? Rgb(14, 18, 19) : Rgb(232, 238, 236);
            _leftCard.Background = dark ? Rgb(24, 31, 32) : Brushes.White;
            _leftCard.BorderBrush = dark ? Rgb(42, 54, 55) : Rgb(214, 224, 221);
            _leftCard.BorderThickness = new Thickness(1);
            _rightCard.BorderBrush = dark ? Rgb(20, 40, 42) : Rgb(16, 28, 30);
            _rightCard.BorderThickness = new Thickness(1);
            _statusBar.Background = dark ? Rgb(14, 18, 19) : Rgb(232, 238, 236);
            _title.Foreground = dark ? Rgb(236, 245, 243) : Rgb(12, 32, 34);
            _subtitle.Foreground = dark ? Rgb(156, 178, 176) : Rgb(90, 110, 108);
            _status.Foreground = dark ? Rgb(156, 178, 176) : Rgb(90, 110, 108);
            foreach (var label in _mutedLabels)
                label.Foreground = dark ? Rgb(140, 160, 158) : Rgb(100, 118, 116);
            StyleAction(_runRegister, "Prove login",
                "Sends one authenticated REGISTER with these credentials, then removes it. Use after Test path succeeds.", true, dark);
            StyleAction(_runMatrix, "Test path",
                "Tries UDP, TCP and TLS without the password. A 401 means the PBX is reachable. Safe first step — it will not lock the extension.", false, dark);
            StyleAction(_loadCfg, "Load phone config",
                "Reads a Yealink .cfg and fills the fields. The password stays in memory and is never logged.", false, dark);
            StyleAction(_checkPbx, "Check PBX",
                "Asks the Yeastar API whether this extension is online, assigned a phone, or on the blocked-IP list. Needs Client ID and Secret under Advanced.", false, dark);
            StyleAction(_stop, "Stop", "Cancels the test that is currently running.", false, dark);
            StyleGhost(_clear, "Clear", dark);
            StyleGhost(_export, "Export", dark);
        }
        finally
        {
            _applyingTheme = false;
        }
    }

    private void SyncDarkToggle()
    {
        _darkMode.IsChecked = IsDark;
    }

    private bool IsDark =>
        ActualThemeVariant == ThemeVariant.Dark ||
        Application.Current?.ActualThemeVariant == ThemeVariant.Dark;

    private Control Labeled(string title, Control field, string tip)
    {
        var caption = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        var text = new TextBlock { Text = title, FontSize = 11.5, FontWeight = FontWeight.Medium };
        _mutedLabels.Add(text);
        caption.Children.Add(text);
        caption.Children.Add(InfoIcon(tip));
        var stack = new StackPanel { Spacing = 3 };
        stack.Children.Add(caption);
        stack.Children.Add(field);
        ToolTip.SetTip(field, tip);
        return stack;
    }

    private static Control InfoIcon(string tip)
    {
        var icon = new TextBlock
        {
            Text = "ⓘ",
            FontSize = 11,
            Opacity = 0.55,
            VerticalAlignment = VerticalAlignment.Center
        };
        ToolTip.SetTip(icon, tip);
        ToolTip.SetShowDelay(icon, 150);
        return icon;
    }

    private TextBlock Muted(string text)
    {
        var block = new TextBlock { Text = text, FontSize = 11.5, TextWrapping = TextWrapping.Wrap };
        _mutedLabels.Add(block);
        return block;
    }

    private TextBlock SectionTitle(string text) => new()
    {
        Text = text,
        FontSize = 13,
        FontWeight = FontWeight.SemiBold,
        Foreground = Accent(),
        Margin = new Thickness(0, 4, 0, 0)
    };

    private static Control TwoCol(Control left, Control right)
    {
        var grid = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,10,*") };
        Grid.SetColumn(right, 2);
        grid.Children.Add(left);
        grid.Children.Add(right);
        return grid;
    }

    private static Control ThreeCol(Control a, Control b, Control c)
    {
        var grid = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,8,*,8,*") };
        Grid.SetColumn(b, 2);
        Grid.SetColumn(c, 4);
        grid.Children.Add(a);
        grid.Children.Add(b);
        grid.Children.Add(c);
        return grid;
    }

    private static void Place(Grid grid, Control child, int row, int column)
    {
        Grid.SetRow(child, row);
        Grid.SetColumn(child, column);
        grid.Children.Add(child);
    }

    private static void StyleAction(Button button, string title, string tip, bool primary, bool dark = false)
    {
        var label = new TextBlock
        {
            Text = title,
            FontWeight = FontWeight.SemiBold,
            FontSize = 13,
            VerticalAlignment = VerticalAlignment.Center
        };
        var info = new TextBlock
        {
            Text = "ⓘ",
            FontSize = 12,
            Opacity = 0.7,
            VerticalAlignment = VerticalAlignment.Center
        };
        button.Content = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 7,
            HorizontalAlignment = HorizontalAlignment.Center,
            Children = { label, info }
        };
        button.Height = primary ? 44 : 38;
        button.CornerRadius = new CornerRadius(10);
        button.BorderThickness = primary ? new Thickness(0) : new Thickness(1);
        button.Padding = new Thickness(8, 0);
        if (primary)
        {
            button.Background = Accent();
            button.Foreground = Brushes.White;
            label.Foreground = Brushes.White;
            info.Foreground = Brushes.White;
        }
        else
        {
            button.Background = dark ? Rgb(36, 46, 47) : Rgb(241, 246, 245);
            button.BorderBrush = dark ? Rgb(58, 74, 74) : Rgb(198, 214, 211);
            var ink = dark ? Rgb(230, 240, 238) : Rgb(24, 42, 44);
            button.Foreground = ink;
            label.Foreground = ink;
            info.Foreground = ink;
        }
        ToolTip.SetTip(button, tip);
        ToolTip.SetShowDelay(button, 150);
    }

    private static void StyleGhost(Button button, string title, bool dark = false)
    {
        button.Content = title;
        button.Height = 30;
        button.Padding = new Thickness(10, 0);
        button.CornerRadius = new CornerRadius(8);
        button.BorderThickness = new Thickness(0);
        button.Background = dark ? Rgb(28, 40, 42) : Rgb(36, 56, 58);
        button.Foreground = new SolidColorBrush(Color.FromRgb(210, 230, 226));
    }

    private static TextBox Field(string watermark) => new()
    {
        Watermark = watermark,
        HorizontalAlignment = HorizontalAlignment.Stretch,
        MinHeight = 34
    };

    private static NumericUpDown NumberField(decimal min, decimal max, decimal value) => new()
    {
        Minimum = min,
        Maximum = max,
        Value = value,
        Increment = 1,
        FormatString = "0",
        HorizontalAlignment = HorizontalAlignment.Stretch,
        MinHeight = 34
    };

    private static SolidColorBrush Accent() => new(Color.FromRgb(14, 122, 122));

    private static SolidColorBrush Rgb(byte r, byte g, byte b) => new(Color.FromRgb(r, g, b));

    private const string InterpretationText =
        "TEST PATH — tries UDP, TCP and TLS without a password.\n" +
        "A 401/407 is success: the PBX is reachable and return traffic works.\n\n" +
        "PROVE LOGIN — one authenticated REGISTER, then it unregisters.\n" +
        "200 OK means credentials work from this computer; look at the handset next.\n\n" +
        "CHECK PBX — Yeastar API: extension online, assigned phone, blocked IPs.\n\n" +
        "DNS fails — wrong hostname or DNS policy.\n" +
        "TCP/TLS connect fails — firewall, ISP, wrong port, or service down.\n" +
        "TLS handshake fails — certificate, clock, or TLS inspection.\n" +
        "Via sent-by rewritten — SIP ALG. received=/rport= alone is normal NAT.\n" +
        "Clock vs certificate — fix NTP (no private 172.19.x.x) before blaming TLS.";
}
