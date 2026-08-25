using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using InspireTel.SipProbe.Core;

namespace InspireTel.SipProbe.Mac;

public sealed class MainWindow : Window
{
    private readonly TextBox _server = Field("pbx.example.com");
    private readonly NumericUpDown _port = NumberField(1, 65535, 5061);
    private readonly ComboBox _transport = new() { HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox _sipUser = Field("Extension / SIP user");
    private readonly TextBox _authName = Field("Registration / authentication name");
    private readonly TextBox _password = Field("Not saved or logged");
    private readonly NumericUpDown _localPort = NumberField(0, 65535, 0);
    private readonly NumericUpDown _expiry = NumberField(30, 86400, 600);
    private readonly NumericUpDown _timeout = NumberField(2, 60, 7);
    private readonly CheckBox _forceTls12 = new() { Content = "Force TLS 1.2", IsChecked = true };
    private readonly CheckBox _ignoreCertificateErrors = new()
    {
        Content = "Ignore certificate errors (diagnostic only)",
        Foreground = Rgb(170, 60, 45)
    };
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
        Background = Rgb(20, 25, 31),
        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto
    };

    private readonly Button _runRegister = PrimaryButton("Run authenticated REGISTER");
    private readonly Button _runMatrix = SecondaryButton("Run transport matrix (no auth)");
    private readonly Button _checkPbx = SecondaryButton("Check PBX status");
    private readonly Button _loadCfg = SecondaryButton("Load Yealink .cfg");
    private readonly Button _stop = SecondaryButton("Stop");
    private readonly Button _clear = SecondaryButton("Clear log");
    private readonly Button _export = SecondaryButton("Export log");
    private readonly TextBlock _status = new()
    {
        Text = "Ready",
        VerticalAlignment = VerticalAlignment.Center,
        Foreground = Rgb(71, 85, 105)
    };

    private readonly List<DiagnosticLogEntry> _allEntries = new();
    private CancellationTokenSource? _activeRun;

    public MainWindow()
    {
        Title = "InspireTel SIP Probe";
        Width = 1260;
        Height = 820;
        MinWidth = 1050;
        MinHeight = 720;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Rgb(241, 245, 249);
        FontFamily = new FontFamily("SF Pro Text, Helvetica Neue, system-ui");
        FontSize = 13.5;

        _password.PasswordChar = '•';
        _apiSecret.PasswordChar = '•';
        _logScroll.Content = _logLines;
        _stop.IsEnabled = false;

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

        Content = BuildRoot();
        AppendWelcome();
        Opened += async (_, _) =>
        {
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
        var root = new Grid
        {
            RowDefinitions = RowDefinitions.Parse("96,*,42")
        };
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
        var header = new Grid
        {
            Background = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 0, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Color.FromRgb(8, 86, 91), 0),
                    new GradientStop(Color.FromRgb(13, 116, 122), 1)
                }
            },
            ColumnDefinitions = ColumnDefinitions.Parse("*,Auto")
        };
        var titles = new StackPanel { Margin = new Thickness(30, 16, 20, 12), Spacing = 4 };
        titles.Children.Add(new TextBlock
        {
            Text = "InspireTel SIP Probe",
            Foreground = Brushes.White,
            FontSize = 26,
            FontWeight = FontWeight.SemiBold
        });
        titles.Children.Add(new TextBlock
        {
            Text = "Prove DNS, firewall, TLS and SIP registration independently of the handset",
            Foreground = new SolidColorBrush(Color.FromRgb(204, 251, 241)),
            FontSize = 14
        });
        var version = new TextBlock
        {
            Text = "v1.2  •  macOS  •  Passwords and digest values are never logged",
            Foreground = new SolidColorBrush(Color.FromRgb(153, 246, 228)),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 28, 0)
        };
        Grid.SetColumn(version, 1);
        header.Children.Add(titles);
        header.Children.Add(version);
        return header;
    }

    private Control BuildBody()
    {
        var body = new Grid
        {
            ColumnDefinitions = ColumnDefinitions.Parse("420,6,*"),
            Margin = new Thickness(16)
        };
        var left = new Border
        {
            Background = Brushes.White,
            Padding = new Thickness(18, 14, 18, 14),
            CornerRadius = new CornerRadius(6),
            Child = BuildConfigurationPanel()
        };
        var splitter = new GridSplitter
        {
            Width = 6,
            Background = Rgb(203, 213, 225),
            ResizeDirection = GridResizeDirection.Columns
        };
        var right = new Border
        {
            Background = Rgb(20, 25, 31),
            CornerRadius = new CornerRadius(6),
            ClipToBounds = true,
            Child = BuildLogPanel()
        };
        Grid.SetColumn(left, 0);
        Grid.SetColumn(splitter, 1);
        Grid.SetColumn(right, 2);
        body.Children.Add(left);
        body.Children.Add(splitter);
        body.Children.Add(right);
        return body;
    }

    private Control BuildConfigurationPanel()
    {
        var panel = new Grid { RowDefinitions = RowDefinitions.Parse("Auto,Auto,*,Auto") };
        var title = new TextBlock
        {
            Text = "Probe configuration",
            FontSize = 18,
            FontWeight = FontWeight.SemiBold,
            Foreground = Rgb(15, 23, 42),
            Margin = new Thickness(0, 0, 0, 4)
        };
        var subtitle = new TextBlock
        {
            Text = "Use the same SIP values as the endpoint. The matrix uses the UDP/TCP/TLS ports on the Matrix tab.",
            Foreground = Rgb(71, 85, 105),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10)
        };
        var tabs = new TabControl();
        tabs.Items.Add(new TabItem { Header = "SIP", Content = new ScrollViewer { Content = BuildSipFields(), VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });
        tabs.Items.Add(new TabItem { Header = "Matrix", Content = BuildMatrixFields() });
        tabs.Items.Add(new TabItem { Header = "PBX API", Content = BuildApiFields() });
        var actions = BuildActionPanel();
        Grid.SetRow(subtitle, 1);
        Grid.SetRow(tabs, 2);
        Grid.SetRow(actions, 3);
        panel.Children.Add(title);
        panel.Children.Add(subtitle);
        panel.Children.Add(tabs);
        panel.Children.Add(actions);
        return panel;
    }

    private Control BuildSipFields()
    {
        return FormGrid(
            ("PBX hostname", _server),
            ("Transport", _transport),
            ("Destination port", _port),
            ("SIP user", _sipUser),
            ("Auth name", _authName),
            ("Password", BuildPasswordField(_password)),
            ("Local port", _localPort),
            ("Register expiry", _expiry),
            ("Timeout", _timeout),
            ("TLS options", TlsOptions()),
            ("", Hint("Local port 0 = automatic. Destination port is for authenticated REGISTER. Matrix ports are on the Matrix tab.")));
    }

    private Control BuildMatrixFields()
    {
        return FormGrid(
            ("UDP port", _udpPort),
            ("TCP port", _tcpPort),
            ("TLS port", _tlsPort),
            ("", Hint("The no-auth matrix tests these three listeners. If Destination port on the SIP tab is different, that custom target is added as a fourth probe.")));
    }

    private Control BuildApiFields()
    {
        return FormGrid(
            ("API URL", _apiUrl),
            ("Client ID", _apiClientId),
            ("Client secret", BuildPasswordField(_apiSecret)),
            ("", Hint("Settings → Integrations → API. Leave URL blank to use https:// plus the SIP hostname.")));
    }

    private Control TlsOptions()
    {
        var stack = new StackPanel { Spacing = 6 };
        stack.Children.Add(_forceTls12);
        stack.Children.Add(_ignoreCertificateErrors);
        return stack;
    }

    private static Control BuildPasswordField(TextBox password)
    {
        var show = SecondaryButton("Show");
        show.Width = 64;
        show.Height = 30;
        show.PointerPressed += (_, _) => password.PasswordChar = '\0';
        show.PointerReleased += (_, _) => password.PasswordChar = '•';
        show.PointerExited += (_, _) => password.PasswordChar = '•';
        var row = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,8,Auto") };
        Grid.SetColumn(show, 2);
        row.Children.Add(password);
        row.Children.Add(show);
        return row;
    }

    private Control BuildActionPanel()
    {
        var actions = new StackPanel { Spacing = 8, Margin = new Thickness(0, 12, 0, 0) };
        foreach (var button in new[] { _loadCfg, _runRegister, _runMatrix, _checkPbx, _stop })
        {
            button.HorizontalAlignment = HorizontalAlignment.Stretch;
            actions.Children.Add(button);
        }
        return actions;
    }

    private Control BuildLogPanel()
    {
        var panel = new Grid { RowDefinitions = RowDefinitions.Parse("52,*") };
        var toolbar = new Grid
        {
            Background = Rgb(30, 41, 50),
            ColumnDefinitions = ColumnDefinitions.Parse("*,Auto,Auto"),
            Margin = new Thickness(12, 8)
        };
        var title = new TextBlock
        {
            Text = "Diagnostic log",
            Foreground = Rgb(226, 232, 240),
            FontWeight = FontWeight.SemiBold,
            FontSize = 15,
            VerticalAlignment = VerticalAlignment.Center
        };
        _clear.Margin = new Thickness(0, 0, 8, 0);
        Grid.SetColumn(_clear, 1);
        Grid.SetColumn(_export, 2);
        toolbar.Children.Add(title);
        toolbar.Children.Add(_clear);
        toolbar.Children.Add(_export);
        Grid.SetRow(_logScroll, 1);
        panel.Children.Add(toolbar);
        panel.Children.Add(_logScroll);
        return panel;
    }

    private Control BuildStatusBar()
    {
        var bar = new Grid
        {
            Background = Brushes.White,
            ColumnDefinitions = ColumnDefinitions.Parse("*,Auto"),
            Margin = new Thickness(18, 0)
        };
        var help = new Button
        {
            Content = "Interpretation guide",
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Foreground = Rgb(13, 116, 122),
            Padding = new Thickness(8, 4),
            VerticalAlignment = VerticalAlignment.Center
        };
        help.Click += async (_, _) => await ShowAlert("SIP Probe interpretation guide", InterpretationText);
        Grid.SetColumn(help, 1);
        bar.Children.Add(_status);
        bar.Children.Add(help);
        return bar;
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

        AppendSeparator($"AUTHENTICATED {profile.Transport.ToString().ToUpperInvariant()} REGISTER");
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

        SetRunning(true, "Running no-auth transport matrix...");
        _activeRun = new CancellationTokenSource();
        try
        {
            foreach (var item in baseProfile.MatrixTargets())
            {
                _activeRun.Token.ThrowIfCancellationRequested();
                AppendSeparator($"MATRIX: {item.Transport.ToString().ToUpperInvariant()} / {item.Port} (NO AUTH)");
                var profile = baseProfile with
                {
                    Transport = item.Transport,
                    Port = item.Port,
                    Authenticate = false,
                    Password = string.Empty
                };
                await ExecuteEngineAsync(profile, _activeRun.Token);
            }
            _status.Text = "Transport matrix complete";
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
        SetRunning(true, "Running SIP probe...");
        _activeRun = new CancellationTokenSource();
        try
        {
            var result = await ExecuteEngineAsync(profile, _activeRun.Token);
            _status.Text = result.Registered
                ? "REGISTER succeeded"
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
            await ShowAlert("Check the probe configuration",
                "Enter the Yeastar OpenAPI Client ID and Client Secret on the PBX API tab.");
            return;
        }

        var apiUrl = string.IsNullOrWhiteSpace(_apiUrl.Text)
            ? "https://" + (_server.Text ?? string.Empty).Trim()
            : _apiUrl.Text.Trim();

        AppendSeparator("YEASTAR PBX API STATUS");
        SetRunning(true, "Checking PBX API...");
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
            _status.Text = "PBX API check complete";
        }
        catch (OperationCanceledException)
        {
            AppendLocal(DiagnosticLevel.Warning, "Test cancelled by the operator.");
            _status.Text = "Cancelled";
        }
        catch (Exception ex)
        {
            AppendLocal(DiagnosticLevel.Error, ex.Message);
            _status.Text = "PBX API check failed";
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
        AppendLocal(DiagnosticLevel.Info, "Ready. Start with the no-auth matrix to compare UDP, TCP and TLS on the configured ports.");
        AppendLocal(DiagnosticLevel.Detail, "A 401/407 challenge is a positive reachability result; Via rewrite is reported as SIP ALG. Use Check PBX status when OpenAPI credentials are available.");
    }

    private void AppendSeparator(string title)
    {
        var line = Environment.NewLine + new string('═', Math.Min(82, title.Length + 8)) + Environment.NewLine +
                   $"   {title}" + Environment.NewLine + new string('═', Math.Min(82, title.Length + 8));
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
            FontFamily = new FontFamily("Menlo, SF Mono, ui-monospace, monospace"),
            FontSize = 12.25,
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
            "InspireTel SIP Probe v1.2 (macOS)",
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

    private static Control FormGrid(params (string Label, Control Control)[] rows)
    {
        var grid = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("125,*") };
        for (var i = 0; i < rows.Length; i++)
        {
            grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            var caption = new TextBlock
            {
                Text = rows[i].Label,
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = Rgb(51, 65, 85),
                Margin = new Thickness(0, 8, 8, 0)
            };
            rows[i].Control.Margin = new Thickness(0, 4);
            Grid.SetRow(caption, i);
            Grid.SetRow(rows[i].Control, i);
            Grid.SetColumn(rows[i].Control, 1);
            if (!string.IsNullOrEmpty(rows[i].Label))
                grid.Children.Add(caption);
            grid.Children.Add(rows[i].Control);
        }
        return grid;
    }

    private static TextBox Field(string watermark) => new()
    {
        Watermark = watermark,
        HorizontalAlignment = HorizontalAlignment.Stretch,
        MinHeight = 32
    };

    private static NumericUpDown NumberField(decimal min, decimal max, decimal value) => new()
    {
        Minimum = min,
        Maximum = max,
        Value = value,
        Increment = 1,
        FormatString = "0",
        HorizontalAlignment = HorizontalAlignment.Stretch,
        MinHeight = 32
    };

    private static TextBlock Hint(string text) => new()
    {
        Text = text,
        Foreground = Rgb(100, 116, 139),
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 8, 0, 0)
    };

    private static Button PrimaryButton(string text) => new()
    {
        Content = text,
        Height = 38,
        Background = Rgb(13, 116, 122),
        Foreground = Brushes.White,
        FontWeight = FontWeight.SemiBold,
        CornerRadius = new CornerRadius(4),
        BorderThickness = new Thickness(0)
    };

    private static Button SecondaryButton(string text) => new()
    {
        Content = text,
        Height = 34,
        Background = Rgb(241, 245, 249),
        Foreground = Rgb(30, 41, 59),
        CornerRadius = new CornerRadius(4)
    };

    private static SolidColorBrush Rgb(byte r, byte g, byte b) => new(Color.FromRgb(r, g, b));

    private const string InterpretationText =
        "RESULT INTERPRETATION\n\n" +
        "DNS fails — wrong hostname or DNS policy.\n\n" +
        "TCP/TLS connection fails — firewall, router, ISP policy, wrong port, or service not listening.\n\n" +
        "TLS handshake fails — certificate trust/hostname/time/TLS-version issue, or TLS inspection.\n\n" +
        "401/407 challenge — positive result: the PBX is reachable and return traffic works.\n\n" +
        "200 OK — network, PBX and credentials work from this computer; focus on the handset.\n\n" +
        "Repeated 401 or 403 — credentials, extension transport policy, registration security or blocked IP.\n\n" +
        "Via sent-by rewritten — SIP ALG on the customer router. received=/rport= alone is normal NAT.\n\n" +
        "Clock behind/ahead of certificate dates — fix handset NTP (avoid private 172.19.x.x) before blaming TLS.\n\n" +
        "No SIP response after connection — SIP-aware firewall/ALG, proxy interference, or PBX service problem.";
}
