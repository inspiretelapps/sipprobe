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
    private readonly ComboBox _transport = new()
    {
        HorizontalAlignment = HorizontalAlignment.Stretch,
        Height = 38,
        VerticalContentAlignment = VerticalAlignment.Center,
        Padding = new Thickness(12, 0),
        CornerRadius = new CornerRadius(9)
    };
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
    private readonly Button _unregister = new();
    private readonly Button _capture = new();
    private readonly CheckBox _keepRegistered = new()
    {
        Content = "Keep Registered On The PBX",
        IsChecked = true
    };
    private readonly CheckBox _relayToPbx = new()
    {
        Content = "Relay the handset to the PBX"
    };
    private readonly Border _resultBanner = new()
    {
        CornerRadius = new CornerRadius(12),
        Padding = new Thickness(16, 14),
        Margin = new Thickness(14, 14, 14, 0)
    };
    private readonly TextBlock _resultTitle = new() { FontSize = 17, FontWeight = FontWeight.SemiBold };
    private readonly TextBlock _resultDetail = new()
    {
        FontSize = 12.5,
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 4, 0, 0),
        Opacity = 0.9
    };
    private readonly TextBlock _resultAdvice = new()
    {
        FontSize = 12,
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 10, 0, 0),
        Opacity = 0.92,
        IsVisible = false
    };
    private readonly TextBlock _chipConfigText = new() { FontSize = 11.5, FontWeight = FontWeight.Medium };
    private readonly TextBlock _chipPathText = new() { FontSize = 11.5, FontWeight = FontWeight.Medium };
    private readonly TextBlock _chipRegText = new() { FontSize = 11.5, FontWeight = FontWeight.Medium };
    private readonly Border _chipConfig = new() { Width = 9, Height = 9, CornerRadius = new CornerRadius(4.5), VerticalAlignment = VerticalAlignment.Center };
    private readonly Border _chipPath = new() { Width = 9, Height = 9, CornerRadius = new CornerRadius(4.5), VerticalAlignment = VerticalAlignment.Center };
    private readonly Border _chipReg = new() { Width = 9, Height = 9, CornerRadius = new CornerRadius(4.5), VerticalAlignment = VerticalAlignment.Center };
    private readonly Border _railLine1 = new() { Height = 1.5, Margin = new Thickness(10, 0), VerticalAlignment = VerticalAlignment.Center };
    private readonly Border _railLine2 = new() { Height = 1.5, Margin = new Thickness(10, 0), VerticalAlignment = VerticalAlignment.Center };
    private readonly Border _beacon = new() { Width = 8, Height = 8, CornerRadius = new CornerRadius(4), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 1, 0, 0) };
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
    private readonly TextBlock _title = new() { Text = "SIP Probe", FontSize = 27, FontWeight = FontWeight.SemiBold, LetterSpacing = -0.6 };
    private readonly TextBlock _subtitle = new()
    {
        Text = "Find out why a handset will not register — without guessing.",
        FontSize = 12.5
    };
    private readonly Border _header = new();
    private readonly Border _leftCard = new() { CornerRadius = new CornerRadius(18), Padding = new Thickness(20, 18, 20, 12), ClipToBounds = true };
    private readonly Border _rightCard = new() { CornerRadius = new CornerRadius(18), ClipToBounds = true };
    private readonly Border _logToolbar = new();
    private readonly Border _logBody = new() { CornerRadius = new CornerRadius(0, 0, 18, 18), ClipToBounds = true };
    private readonly Border _statusBar = new();
    private readonly Border _actionDock = new();
    private readonly Border _advancedPanel = new() { CornerRadius = new CornerRadius(12), Padding = new Thickness(14, 12, 14, 14), Margin = new Thickness(0, 10, 0, 4) };
    private readonly List<TextBlock> _mutedLabels = new();
    private readonly List<Button> _eyeButtons = new();
    private readonly List<Border> _infoIcons = new();
    private readonly List<TextBlock> _infoLetters = new();
    private readonly List<TemplatedControl> _inputs = new();

    private readonly List<DiagnosticLogEntry> _allEntries = new();
    private CancellationTokenSource? _activeRun;
    private bool _applyingTheme;
    private bool _configLoaded;
    private string? _configName;
    private string _pathState = "idle";
    private string _regState = "idle";
    private DiagnosticProfile? _heldProfile;
    private IHeldSipRegistration? _heldSession;
    private SipCaptureListener? _captureListener;
    private bool _configBlocked;
    private YealinkAccountSettings? _handsetSettings;
    private readonly List<DiagnosticResult> _pathResults = new();
    private DiagnosticResult? _registrationResult;
    private Diagnosis? _diagnosis;

    private const int CapturePort = 5060;

    private const string CaptureTip =
        "Listens on port 5060 for SIP from the handset. Point the phone's SIP server (or outbound proxy) at this computer, " +
        "then reboot it. Shows the handset's REGISTER verbatim, including the authentication name it really uses.";

    public MainWindow()
    {
        Title = "InspireTel SIP Probe";
        Width = 1280;
        Height = 800;
        MinWidth = 1080;
        MinHeight = 700;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        FontFamily = new FontFamily(
            "SF Pro Text, Helvetica Neue, Inter, Noto Sans, DejaVu Sans, Liberation Sans, system-ui, sans-serif");
        FontSize = 13;

        _inputs.AddRange(new TemplatedControl[]
        {
            _server, _port, _transport, _sipUser, _authName, _password,
            _localPort, _expiry, _timeout, _udpPort, _tcpPort, _tlsPort,
            _apiUrl, _apiClientId, _apiSecret
        });
        _password.PasswordChar = '•';
        _apiSecret.PasswordChar = '•';
        _logScroll.Content = _logLines;
        _stop.IsEnabled = false;

        StyleAction(_loadCfg, "Load Phone Config", "Reads a Yealink .cfg and fills the fields. The password stays in memory and is never logged.", false);
        StyleAction(_runMatrix, "Test Path", "Tries UDP, TCP and TLS without the password. A 401 means the PBX is reachable. Safe first step — it will not lock the extension.", false);
        StyleAction(_runRegister, "Test SIP Registration", "Sends one authenticated REGISTER with these credentials. Tick Keep Registered to leave it on the PBX so you can confirm it in Yeastar.", true);
        StyleAction(_checkPbx, "Check PBX Status", "Looks up this extension on the Yeastar: online or not, assigned phone, and blocked IPs. Needs Client ID and Secret under Advanced.", false);
        StyleAction(_stop, "Stop", "Cancels the test that is currently running.", false);
        StyleAction(_unregister, "Unregister Now", "Removes the diagnostic registration from the PBX so the extension is free again.", false);
        StyleAction(_capture, "Listen For Handset", CaptureTip, false);
        _unregister.IsVisible = false;
        ToolTip.SetTip(_relayToPbx,
            "While listening, forward the handset's SIP to the PBX using the settings above. This laptop does the DNS lookup and TLS handshake, " +
            "so if the handset registers this way its credentials and SIP stack are fine and the fault is in its own path.");
        ToolTip.SetTip(_keepRegistered, "If ticked, a successful Test SIP Registration stays on the PBX until Unregister Now or the expiry timer. Use this to confirm the binding in Yeastar.");
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
        _unregister.Click += async (_, _) => await RunUnregisterAsync();
        _loadCfg.Click += async (_, _) => await LoadYealinkConfigAsync();
        _capture.Click += async (_, _) => await ToggleCaptureAsync();
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
        RefreshResultBanner();
        ActualThemeVariantChanged += (_, _) => ApplyChrome();
        AppendWelcome();
        Closed += (_, _) =>
        {
            var held = _heldSession;
            _heldSession = null;
            if (held is not null)
                _ = held.DisposeAsync().AsTask();

            var listener = _captureListener;
            _captureListener = null;
            if (listener is not null)
                _ = listener.DisposeAsync().AsTask();
        };
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
        var root = new Grid { RowDefinitions = RowDefinitions.Parse("76,*,42") };
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
        _header.Padding = new Thickness(24, 0, 22, 0);
        var grid = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("Auto,*,Auto") };
        var mark = new Border
        {
            Width = 6,
            Height = 30,
            CornerRadius = new CornerRadius(3),
            Background = Accent(),
            Margin = new Thickness(0, 0, 14, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        var titleRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            VerticalAlignment = VerticalAlignment.Center,
            Children = { _title, _beacon }
        };
        var titles = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Center };
        titles.Children.Add(titleRow);
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
                Muted("v1.5")
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
            ColumnDefinitions = ColumnDefinitions.Parse("440,20,*"),
            Margin = new Thickness(22, 16, 22, 14)
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

        var fields = new StackPanel { Spacing = 16 };
        fields.Children.Add(Labeled("PBX hostname", _server, "DNS name of the Cloud PBX, not an IP, when using TLS."));
        fields.Children.Add(TwoCol(
            Labeled("Transport", _transport, "Must match the extension on the PBX. Yeastar Cloud remote phones usually use TLS."),
            Labeled("Port", _port, "Destination port for Test SIP Registration. TLS is typically 5061; UDP/TCP 5060.")));
        fields.Children.Add(TwoCol(
            Labeled("SIP user", _sipUser, "Extension number, for example 101."),
            Labeled("Auth name", _authName, "P-Series Registration Name. Often different from the extension number.")));
        fields.Children.Add(Labeled("Password", BuildPasswordField(_password), "Registration password. Never written to the log or export."));

        var advanced = BuildAdvancedSection();
        var mid = new StackPanel { Spacing = 0 };
        mid.Children.Add(fields);
        mid.Children.Add(advanced);

        var scroller = new ScrollViewer
        {
            Content = mid,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
        };

        _actionDock.Child = BuildActionPanel();
        _actionDock.Padding = new Thickness(0, 10, 0, 0);
        Grid.SetRow(scroller, 1);
        Grid.SetRow(_actionDock, 2);
        panel.Children.Add(intro);
        panel.Children.Add(scroller);
        panel.Children.Add(_actionDock);
        return panel;
    }

    private Control BuildAdvancedSection()
    {
        var header = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,Auto") };
        var glyph = new TextBlock
        {
            Text = "▸",
            FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 6, 0)
        };
        var title = new TextBlock
        {
            Text = "ADVANCED",
            FontSize = 11,
            FontWeight = FontWeight.Bold,
            LetterSpacing = 0.8,
            VerticalAlignment = VerticalAlignment.Center
        };
        var titleRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center,
            Children = { glyph, title }
        };
        var chevron = new TextBlock
        {
            Text = "Show extra ports, TLS and PBX API",
            FontSize = 11.5,
            VerticalAlignment = VerticalAlignment.Center
        };
        _mutedLabels.Add(glyph);
        _mutedLabels.Add(title);
        _mutedLabels.Add(chevron);
        Grid.SetColumn(chevron, 1);
        header.Children.Add(titleRow);
        header.Children.Add(chevron);

        var body = BuildAdvanced();
        body.IsVisible = false;
        body.Margin = new Thickness(0, 10, 0, 0);

        var toggle = new Button
        {
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(2, 0),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Content = header
        };
        toggle.Click += (_, _) =>
        {
            body.IsVisible = !body.IsVisible;
            glyph.Text = body.IsVisible ? "▾" : "▸";
            chevron.Text = body.IsVisible ? "Hide" : "Show extra ports, TLS and PBX API";
        };

        var stack = new StackPanel();
        stack.Children.Add(toggle);
        stack.Children.Add(body);
        _advancedPanel.Child = stack;
        return _advancedPanel;
    }

    private Control BuildAdvanced()
    {
        var stack = new StackPanel { Spacing = 14 };
        stack.Children.Add(ThreeCol(
            Labeled("Local port", _localPort, "0 = automatic. Change only if you are testing a specific source port."),
            Labeled("Expiry", _expiry, "REGISTER Expires. Yeastar Cloud minimum is often 600."),
            Labeled("Timeout", _timeout, "Seconds to wait for each network step.")));
        stack.Children.Add(TlsOptions());
        stack.Children.Add(SectionTitle("Path test ports"));
        stack.Children.Add(Muted("Test Path tries all three. A custom Test SIP Registration port is added if it is different."));
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

    private Control BuildPasswordField(TextBox password)
    {
        password.Padding = new Thickness(10, 0, 36, 0);
        var revealed = false;
        var eye = new Button
        {
            Width = 30,
            Height = 30,
            Padding = new Thickness(0),
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            HorizontalAlignment = HorizontalAlignment.Right,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 4, 0),
            Content = EyeIcon(false)
        };
        ToolTip.SetTip(eye, "Show password");
        eye.Click += (_, _) =>
        {
            revealed = !revealed;
            password.PasswordChar = revealed ? '\0' : '•';
            eye.Content = EyeIcon(revealed);
            ToolTip.SetTip(eye, revealed ? "Hide password" : "Show password");
        };
        _eyeButtons.Add(eye);
        var host = new Grid();
        host.Children.Add(password);
        host.Children.Add(eye);
        return host;
    }

    private Control BuildActionPanel()
    {
        var grid = new Grid
        {
            ColumnDefinitions = ColumnDefinitions.Parse("*,12,*"),
            RowDefinitions = RowDefinitions.Parse("Auto,10,Auto,10,Auto,10,Auto,10,Auto"),
            Margin = new Thickness(0, 16, 0, 0)
        };
        Place(grid, _loadCfg, 0, 0);
        Place(grid, _runMatrix, 0, 2);
        Place(grid, _runRegister, 2, 0);
        Place(grid, _checkPbx, 2, 2);
        Grid.SetColumnSpan(_capture, 3);
        Place(grid, _capture, 4, 0);
        var toggles = new StackPanel { Spacing = 4 };
        toggles.Children.Add(_relayToPbx);
        toggles.Children.Add(_keepRegistered);
        Grid.SetColumnSpan(toggles, 3);
        Place(grid, toggles, 6, 0);
        Grid.SetColumnSpan(_stop, 3);
        Place(grid, _stop, 8, 0);
        Grid.SetColumnSpan(_unregister, 3);
        Place(grid, _unregister, 8, 0);
        foreach (var button in new[] { _loadCfg, _runMatrix, _runRegister, _checkPbx, _stop, _unregister, _capture })
            button.HorizontalAlignment = HorizontalAlignment.Stretch;
        return grid;
    }

    private Control BuildLogPanel()
    {
        var panel = new Grid { RowDefinitions = RowDefinitions.Parse("Auto,*") };
        var chips = BuildSignalRail();
        var headline = new StackPanel { Spacing = 0 };
        headline.Children.Add(_resultTitle);
        headline.Children.Add(_resultDetail);
        headline.Children.Add(_resultAdvice);
        _resultBanner.Child = headline;
        var top = new StackPanel { Spacing = 0, Margin = new Thickness(0, 0, 0, 14) };
        top.Children.Add(chips);
        top.Children.Add(_resultBanner);

        var toolbar = new Grid
        {
            ColumnDefinitions = ColumnDefinitions.Parse("*,Auto,Auto"),
            Margin = new Thickness(14, 0),
            Height = 48,
            VerticalAlignment = VerticalAlignment.Center
        };
        var title = new TextBlock
        {
            Text = "LIVE TRACE",
            Foreground = new SolidColorBrush(Color.FromRgb(210, 230, 226)),
            FontWeight = FontWeight.Bold,
            FontSize = 11,
            LetterSpacing = 0.8,
            VerticalAlignment = VerticalAlignment.Center
        };
        _clear.Margin = new Thickness(0, 0, 8, 0);
        Grid.SetColumn(_clear, 1);
        Grid.SetColumn(_export, 2);
        toolbar.Children.Add(title);
        toolbar.Children.Add(_clear);
        toolbar.Children.Add(_export);
        _logLines.HorizontalAlignment = HorizontalAlignment.Left;
        _logLines.Margin = new Thickness(14, 10, 18, 12);
        _logToolbar.Child = toolbar;
        _logToolbar.Background = new SolidColorBrush(Color.FromRgb(16, 28, 30));
        _logScroll.Background = new SolidColorBrush(Color.FromRgb(10, 18, 20));
        _logScroll.HorizontalScrollBarVisibility = ScrollBarVisibility.Auto;
        _logScroll.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;

        var body = new Grid { RowDefinitions = RowDefinitions.Parse("Auto,*") };
        Grid.SetRow(_logToolbar, 0);
        Grid.SetRow(_logScroll, 1);
        body.Children.Add(_logToolbar);
        body.Children.Add(_logScroll);
        _logBody.Background = new SolidColorBrush(Color.FromRgb(10, 18, 20));
        _logBody.Child = body;

        Grid.SetRow(top, 0);
        Grid.SetRow(_logBody, 1);
        panel.Children.Add(top);
        panel.Children.Add(_logBody);
        return panel;
    }

    private Control BuildSignalRail()
    {
        var grid = new Grid
        {
            ColumnDefinitions = ColumnDefinitions.Parse("Auto,36,Auto,36,Auto"),
            HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new Thickness(14, 14, 14, 0)
        };
        var node1 = RailNode(_chipConfig, _chipConfigText);
        var node2 = RailNode(_chipPath, _chipPathText);
        var node3 = RailNode(_chipReg, _chipRegText);
        Grid.SetColumn(node1, 0);
        Grid.SetColumn(_railLine1, 1);
        Grid.SetColumn(node2, 2);
        Grid.SetColumn(_railLine2, 3);
        Grid.SetColumn(node3, 4);
        grid.Children.Add(node1);
        grid.Children.Add(_railLine1);
        grid.Children.Add(node2);
        grid.Children.Add(_railLine2);
        grid.Children.Add(node3);
        return grid;
    }

    private static Control RailNode(Border dot, TextBlock label) => new StackPanel
    {
        Orientation = Orientation.Horizontal,
        Spacing = 7,
        VerticalAlignment = VerticalAlignment.Center,
        Children = { dot, label }
    };

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

        AppendSeparator($"TEST SIP REGISTRATION  {profile.Transport.ToString().ToUpperInvariant()}");
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
        var anyReachable = false;
        var allReachable = true;
        var pathResults = new List<DiagnosticResult>();
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
                var result = await ExecuteEngineAsync(profile, _activeRun.Token);
                pathResults.Add(result);
                anyReachable |= result.SipResponseReceived;
                allReachable &= result.SipResponseReceived;
            }
            _pathResults.Clear();
            _pathResults.AddRange(pathResults);
            _pathState = allReachable ? "ok" : anyReachable ? "partial" : "fail";
            _status.Text = allReachable ? "Path Reachable" : anyReachable ? "Path Partially Reachable" : "Path Failed";
            PresentDiagnosis(DiagnosisEngine.From(_pathResults, _handsetSettings, _registrationResult), switchTransport: true);
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
            _registrationResult = result;
            if (result.Registered)
            {
                await ReplaceHeldSessionAsync(result.Held);
                _regState = result.Held is not null ? "held" : "ok";
                _heldProfile = result.Held is not null ? profile : null;
                _status.Text = result.Held is not null ? "Registered — Session Held Open" : "Registered";
            }
            else
            {
                _regState = "fail";
                await ReplaceHeldSessionAsync(null);
                _heldProfile = null;
                _status.Text = result.SipResponseReceived
                    ? $"Registration Failed ({result.FinalStatusCode})"
                    : result.Summary;
            }
            PresentDiagnosis(DiagnosisEngine.From(_pathResults, _handsetSettings, result), switchTransport: false);
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
            await ShowAlert("Check PBX Status",
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
            _status.Text = "PBX Status Checked";
            RefreshResultBanner();
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
        KeepRegistered = _keepRegistered.IsChecked == true,
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
        _keepRegistered.IsEnabled = !running;
        _relayToPbx.IsEnabled = !running && _captureListener is null;
        _stop.IsEnabled = running;
        _stop.IsVisible = running || _heldProfile is null;
        _unregister.IsVisible = !running && _heldProfile is not null;
        _unregister.IsEnabled = !running && _heldProfile is not null;
        _transport.IsEnabled = !running;
        _status.Text = status;
        Cursor = running ? new Cursor(StandardCursorType.Wait) : Cursor.Default;
        UpdateBeacon(running);
    }

    private void AppendWelcome()
    {
        AppendLocal(DiagnosticLevel.Info, "Load Phone Config, then Test Path. A 401 means the PBX is reachable. Then Test SIP Registration.");
        AppendLocal(DiagnosticLevel.Detail, "Tick Keep Registered On The PBX if you want to confirm the binding in Yeastar. Passwords are never logged.");
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
            FontFamily = new FontFamily(
                "IBM Plex Mono, Menlo, SF Mono, DejaVu Sans Mono, Liberation Mono, Noto Sans Mono, ui-monospace, monospace"),
            FontSize = 12,
            TextWrapping = TextWrapping.NoWrap,
            TextTrimming = TextTrimming.None,
            HorizontalAlignment = HorizontalAlignment.Left
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
            $"InspireTel SIP Probe v1.5 ({PlatformName})",
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
        foreach (var warning in settings.Audit())
            AppendLocal(warning.Level, warning.Message);
        _configBlocked = settings.HasBlockingProblem;
        _handsetSettings = settings;
        _configLoaded = true;
        _configName = Path.GetFileName(path);
        _status.Text = $"Config Loaded — {_configName}";
        if (_pathResults.Count > 0)
            PresentDiagnosis(DiagnosisEngine.From(_pathResults, _handsetSettings, _registrationResult), switchTransport: false);
        else
            RefreshResultBanner();
        ApplyChrome();
    }

    private async Task ToggleCaptureAsync()
    {
        if (_captureListener is not null)
        {
            await StopCaptureAsync();
            return;
        }

        var listener = new SipCaptureListener();
        listener.EntryAdded += entry => Dispatcher.UIThread.Post(() => AppendEntry(entry));
        try
        {
            AppendSeparator("LISTEN FOR HANDSET");
            await listener.StartAsync(new SipCaptureOptions
            {
                Port = CapturePort,
                Relay = _relayToPbx.IsChecked == true
                    ? new SipRelayTarget
                    {
                        Server = (_server.Text ?? string.Empty).Trim(),
                        Port = (int)(_port.Value ?? 5061),
                        Transport = SelectedTransport(),
                        ForceTls12 = _forceTls12.IsChecked == true,
                        IgnoreCertificateErrors = _ignoreCertificateErrors.IsChecked == true
                    }
                    : null
            });
            _captureListener = listener;
            _status.Text = $"Listening for the handset on port {CapturePort}";
            StyleAction(_capture, "Stop Listening", CaptureTip, false, IsDark);
            _relayToPbx.IsEnabled = false;
        }
        catch (Exception ex)
        {
            await listener.DisposeAsync();
            await ShowAlert("Could not start listening", ex.Message);
        }
    }

    private async Task StopCaptureAsync()
    {
        var listener = _captureListener;
        _captureListener = null;
        if (listener is null)
            return;

        await listener.DisposeAsync();
        StyleAction(_capture, "Listen For Handset", CaptureTip, false, IsDark);
        _relayToPbx.IsEnabled = true;
        _status.Text = "Stopped listening";
    }

    private async Task RunUnregisterAsync()
    {
        if (_heldSession is null)
            return;

        AppendSeparator("UNREGISTER");
        SetRunning(true, "Removing diagnostic registration...");
        _activeRun = new CancellationTokenSource();
        try
        {
            _heldSession.EntryAdded += OnHeldLog;
            await _heldSession.UnregisterAsync(_activeRun.Token);
            _heldProfile = null;
            _heldSession = null;
            _regState = "ok";
            _status.Text = "Unregistered";
            RefreshResultBanner();
        }
        catch (OperationCanceledException)
        {
            AppendLocal(DiagnosticLevel.Warning, "Unregister cancelled.");
            _status.Text = "Cancelled";
        }
        finally
        {
            _activeRun.Dispose();
            _activeRun = null;
            SetRunning(false, _status.Text ?? "Ready");
        }
    }

    private void RefreshResultBanner()
    {
        PaintChip(_chipConfig, _chipConfigText,
            _configLoaded ? "ok" : "idle",
            _configLoaded ? $"✓  Config Loaded" : "Config");
        PaintChip(_chipPath, _chipPathText, _pathState, _pathState switch
        {
            "ok" => "✓  Path Reachable",
            "partial" => "Path Partial",
            "fail" => "Path Failed",
            _ => "Path"
        });
        PaintChip(_chipReg, _chipRegText, _regState, _regState switch
        {
            "ok" => "✓  Registered",
            "held" => "✓  Registered",
            "fail" => "Registration Failed",
            _ => "SIP Registration"
        });

        if (_diagnosis is not null)
        {
            ShowDiagnosisBanner(_diagnosis);
        }
        else if (_configBlocked)
        {
            ShowBanner(
                Color.FromRgb(72, 24, 24),
                Color.FromRgb(252, 165, 165),
                Color.FromRgb(254, 202, 202),
                "Handset Config Will Not Register",
                "This phone configuration has a fault that blocks registration on every transport, " +
                "even when this computer registers fine. Read the red lines in the trace.");
        }
        else if (_configLoaded)
        {
            ShowBanner(
                Color.FromRgb(14, 64, 52),
                Color.FromRgb(110, 232, 180),
                Color.FromRgb(186, 230, 210),
                "Config Loaded",
                _configName is null
                    ? "Phone configuration is in the fields."
                    : $"{_configName} is loaded. Next: Test Path, then Test SIP Registration.");
        }
        else
        {
            _resultBanner.IsVisible = false;
            _resultAdvice.IsVisible = false;
        }

        _unregister.IsVisible = _heldProfile is not null && _activeRun is null;
        _stop.IsVisible = _activeRun is not null || _heldProfile is null;
        UpdateBeacon();
    }

    private void PresentDiagnosis(Diagnosis diagnosis, bool switchTransport)
    {
        _diagnosis = diagnosis;
        AppendSeparator("WHAT THIS MEANS");
        foreach (var line in diagnosis.ToTraceLines())
            AppendLocal(line.Level, line.Message);
        if (switchTransport)
            ApplySuggestedTransport(diagnosis);
        RefreshResultBanner();
    }

    private void ApplySuggestedTransport(Diagnosis diagnosis)
    {
        if (diagnosis.SuggestedTransport is not { } transport || diagnosis.SuggestedPort is not { } port)
            return;
        if (SelectedTransport() == transport && (int)(_port.Value ?? 0) == port)
            return;
        var previous = SelectedTransport();
        _transport.SelectedItem = transport.ToString();
        _port.Value = port;
        AppendLocal(DiagnosticLevel.Info,
            $"Switched the form to {transport.ToString().ToUpperInvariant()} / {port} so Test SIP Registration uses the path that worked (was {previous.ToString().ToUpperInvariant()}).");
    }

    private void ShowDiagnosisBanner(Diagnosis diagnosis)
    {
        var (background, title, detail) = diagnosis.Severity switch
        {
            DiagnosisSeverity.Pass => (Color.FromRgb(14, 64, 52), Color.FromRgb(110, 232, 180), Color.FromRgb(186, 230, 210)),
            DiagnosisSeverity.Warn => (Color.FromRgb(64, 42, 14), Color.FromRgb(252, 211, 125), Color.FromRgb(253, 230, 176)),
            DiagnosisSeverity.Fail => (Color.FromRgb(72, 24, 24), Color.FromRgb(252, 165, 165), Color.FromRgb(254, 202, 202)),
            _ => throw new ArgumentOutOfRangeException(nameof(diagnosis.Severity), diagnosis.Severity, null)
        };
        var summary = diagnosis.Summary;
        if (_regState == "held")
            summary += " The SIP session is being held open. Confirm it in Yeastar, then click Unregister Now.";
        else if (_regState == "ok" && diagnosis.Cause == DiagnosisCause.Registered)
            summary += " Tick Keep Registered On The PBX to leave it visible in Yeastar.";
        ShowBanner(background, title, detail, diagnosis.Headline, summary, diagnosis.HasAdvice ? diagnosis.FormatAdviceBody() : null);
    }

    private void ShowBanner(
        Color background,
        Color title,
        Color detail,
        string heading,
        string body,
        string? advice = null)
    {
        _resultBanner.IsVisible = true;
        _resultBanner.Background = new SolidColorBrush(background);
        _resultTitle.Text = heading;
        _resultTitle.Foreground = new SolidColorBrush(title);
        _resultDetail.Text = body;
        _resultDetail.Foreground = new SolidColorBrush(detail);
        if (string.IsNullOrWhiteSpace(advice))
        {
            _resultAdvice.IsVisible = false;
            _resultAdvice.Text = string.Empty;
        }
        else
        {
            _resultAdvice.IsVisible = true;
            _resultAdvice.Text = advice;
            _resultAdvice.Foreground = new SolidColorBrush(detail);
        }
    }

    private async Task ReplaceHeldSessionAsync(IHeldSipRegistration? next)
    {
        if (_heldSession is not null)
        {
            _heldSession.EntryAdded -= OnHeldLog;
            try { await _heldSession.DisposeAsync(); }
            catch { /* previous session already gone */ }
        }

        _heldSession = next;
        if (_heldSession is not null)
            _heldSession.EntryAdded += OnHeldLog;
    }

    private void OnHeldLog(DiagnosticLogEntry entry)
    {
        Dispatcher.UIThread.Post(() =>
        {
            AppendEntry(entry);
            if (_heldSession is { IsAlive: false })
            {
                _heldSession = null;
                _heldProfile = null;
                _regState = "fail";
                _status.Text = "Registration Dropped";
                RefreshResultBanner();
            }
        });
    }

    private static void PaintChip(Border dot, TextBlock label, string state, string text)
    {
        label.Text = text;
        label.FontWeight = state is "ok" or "held" or "fail" or "partial" ? FontWeight.SemiBold : FontWeight.Medium;
        dot.Background = new SolidColorBrush(state switch
        {
            "ok" or "held" => Color.FromRgb(52, 211, 153),
            "partial" => Color.FromRgb(251, 191, 36),
            "fail" => Color.FromRgb(248, 113, 113),
            _ => Color.FromRgb(120, 138, 136)
        });
    }

    private void UpdateBeacon(bool? runningOverride = null)
    {
        Color color;
        string tip;
        if (runningOverride ?? _activeRun is not null)
        {
            color = Color.FromRgb(251, 191, 36);
            tip = "Test running";
        }
        else if (_diagnosis?.Severity == DiagnosisSeverity.Warn || _pathState == "partial")
        {
            color = Color.FromRgb(251, 191, 36);
            tip = _diagnosis?.Headline ?? "Path partially reachable";
        }
        else if (_regState is "ok" or "held")
        {
            color = Color.FromRgb(52, 211, 153);
            tip = "Last result: registered";
        }
        else if (_regState == "fail" || _pathState == "fail")
        {
            color = Color.FromRgb(248, 113, 113);
            tip = "Last result: failed";
        }
        else if (_pathState is "ok" or "partial" || _configLoaded)
        {
            color = Color.FromRgb(56, 178, 172);
            tip = "Ready for the next step";
        }
        else
        {
            color = Color.FromRgb(120, 138, 136);
            tip = "Idle";
        }
        _beacon.Background = new SolidColorBrush(color);
        ToolTip.SetTip(_beacon, tip);
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
            var windowBg = dark ? Rgb(9, 13, 14) : Rgb(226, 233, 231);
            var cardBg = dark ? Rgb(26, 34, 36) : Rgb(255, 255, 255);
            var cardHairline = dark ? Rgba(22, 255, 255, 255) : Rgba(18, 0, 0, 0);
            var cardShadow = dark
                ? BoxShadows.Parse("0 18 44 -22 #85000000")
                : BoxShadows.Parse("0 18 44 -22 #22000000");
            Background = windowBg;
            _header.Background = windowBg;
            _leftCard.Background = cardBg;
            _leftCard.BorderBrush = cardHairline;
            _leftCard.BorderThickness = new Thickness(1);
            _leftCard.BoxShadow = cardShadow;
            _actionDock.Background = cardBg;
            _actionDock.BorderBrush = cardHairline;
            _actionDock.BorderThickness = new Thickness(0, 1, 0, 0);
            _actionDock.ZIndex = 2;
            _advancedPanel.Background = dark ? Rgb(19, 25, 27) : Rgb(242, 246, 245);
            _advancedPanel.BorderBrush = cardHairline;
            _advancedPanel.BorderThickness = new Thickness(1);
            _rightCard.Background = cardBg;
            _rightCard.BorderBrush = cardHairline;
            _rightCard.BorderThickness = new Thickness(1);
            _rightCard.BoxShadow = cardShadow;
            _statusBar.Background = windowBg;
            _title.Foreground = dark ? Rgb(236, 245, 243) : Rgb(12, 32, 34);
            _subtitle.Foreground = dark ? Rgb(156, 178, 176) : Rgb(90, 110, 108);
            _status.Foreground = dark ? Rgb(156, 178, 176) : Rgb(90, 110, 108);
            var muted = dark ? Rgb(140, 160, 158) : Rgb(100, 118, 116);
            foreach (var label in _mutedLabels)
                label.Foreground = muted;
            foreach (var icon in _infoIcons)
                icon.BorderBrush = muted;
            foreach (var letter in _infoLetters)
                letter.Foreground = muted;
            var railInk = dark ? Rgb(214, 228, 225) : Rgb(28, 46, 48);
            var railLine = dark ? Rgb(42, 54, 55) : Rgb(214, 224, 221);
            _chipConfigText.Foreground = railInk;
            _chipPathText.Foreground = railInk;
            _chipRegText.Foreground = railInk;
            _railLine1.Background = railLine;
            _railLine2.Background = railLine;
            var fieldBg = dark ? Rgb(36, 47, 49) : Rgb(246, 249, 248);
            var fieldBorder = dark ? Rgb(54, 68, 70) : Rgb(222, 230, 228);
            var fieldInk = dark ? Rgb(232, 241, 239) : Rgb(20, 36, 38);
            foreach (var input in _inputs)
            {
                input.Background = fieldBg;
                input.BorderBrush = fieldBorder;
                input.BorderThickness = new Thickness(1);
                input.Foreground = fieldInk;
            }
            StyleAction(_runRegister, "Test SIP Registration",
                "Sends one authenticated REGISTER with these credentials. Tick Keep Registered On The PBX so you can confirm it in Yeastar.", true, dark);
            StyleAction(_runMatrix, "Test Path",
                "Tries UDP, TCP and TLS without the password. A 401 means the PBX is reachable. Safe first step — it will not lock the extension.", false, dark);
            StyleAction(_loadCfg, "Load Phone Config",
                "Reads a Yealink .cfg and fills the fields. The password stays in memory and is never logged.", false, dark, _configLoaded);
            StyleAction(_checkPbx, "Check PBX Status",
                "Looks up this extension on the Yeastar: online or not, assigned phone, and blocked IPs. Needs Client ID and Secret under Advanced.", false, dark);
            StyleAction(_stop, "Stop", "Cancels the test that is currently running.", false, dark);
            StyleAction(_capture, _captureListener is null ? "Listen For Handset" : "Stop Listening", CaptureTip, false, dark);
            StyleAction(_unregister, "Unregister Now",
                "Removes the diagnostic registration from the PBX so the extension is free again.", false, dark);
            var cautionInk = new SolidColorBrush(Color.FromRgb(214, 118, 88));
            _unregister.Background = new SolidColorBrush(Color.FromArgb(dark ? (byte)46 : (byte)26, 196, 92, 64));
            TintButtonText(_unregister, cautionInk);
            _keepRegistered.Foreground = dark ? Rgb(210, 230, 226) : Rgb(24, 42, 44);
            _relayToPbx.Foreground = _keepRegistered.Foreground;
            StyleGhost(_clear, "Clear", dark);
            StyleGhost(_export, "Export", dark);
            var eyeFill = dark ? Rgb(156, 178, 176) : Rgb(90, 110, 108);
            foreach (var eye in _eyeButtons)
            {
                if (eye.Content is Avalonia.Controls.Shapes.Path path)
                {
                    path.Stroke = eyeFill;
                    path.Fill = Brushes.Transparent;
                }
            }
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
        var text = new TextBlock
        {
            Text = title,
            FontSize = 12,
            FontWeight = FontWeight.Medium,
            VerticalAlignment = VerticalAlignment.Center
        };
        _mutedLabels.Add(text);
        var caption = new DockPanel { LastChildFill = false, Height = 18 };
        DockPanel.SetDock(text, Dock.Left);
        var info = InfoIcon(tip);
        DockPanel.SetDock(info, Dock.Left);
        info.Margin = new Thickness(6, 0, 0, 0);
        caption.Children.Add(text);
        caption.Children.Add(info);
        var stack = new StackPanel { Spacing = 6 };
        stack.Children.Add(caption);
        stack.Children.Add(field);
        ToolTip.SetTip(field, tip);
        return stack;
    }

    private Control InfoIcon(string tip)
    {
        var letter = new TextBlock
        {
            Text = "i",
            FontSize = 9,
            FontWeight = FontWeight.Bold,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        };
        var icon = new Border
        {
            Width = 14,
            Height = 14,
            CornerRadius = new CornerRadius(7),
            BorderThickness = new Thickness(1.15),
            VerticalAlignment = VerticalAlignment.Center,
            Child = letter
        };
        _infoIcons.Add(icon);
        _infoLetters.Add(letter);
        ToolTip.SetTip(icon, tip);
        ToolTip.SetShowDelay(icon, 150);
        return icon;
    }

    private static Avalonia.Controls.Shapes.Path EyeIcon(bool revealed)
    {
        var data = revealed
            ? "M 2,3 L 22,17 M 4.2,6.2 C 2.4,7.8 1.4,10 1.4,10 C 1.4,10 5.2,17.2 12,17.2 C 14.2,17.2 16.1,16.5 17.6,15.5 M 9.2,4.1 C 10.1,3.8 11,3.6 12,3.6 C 18.8,3.6 22.6,10.8 22.6,10.8 C 22.6,10.8 21.7,12.4 20.1,13.8 M 9.8,10.2 A 2.4,2.4 0 0 0 14.2,12.8"
            : "M 1.6,10 C 1.6,10 5.4,3.6 12,3.6 C 18.6,3.6 22.4,10 22.4,10 C 22.4,10 18.6,16.4 12,16.4 C 5.4,16.4 1.6,10 1.6,10 Z M 12,8 A 2.2,2.2 0 1 1 12,12.4 A 2.2,2.2 0 1 1 12,8 Z";
        return new Avalonia.Controls.Shapes.Path
        {
            Data = Geometry.Parse(data),
            Stroke = Rgb(140, 160, 158),
            StrokeThickness = 1.4,
            StrokeLineCap = PenLineCap.Round,
            Fill = revealed ? Brushes.Transparent : Brushes.Transparent,
            Width = 18,
            Height = 14,
            Stretch = Stretch.Uniform
        };
    }

    private TextBlock Muted(string text)
    {
        var block = new TextBlock { Text = text, FontSize = 11.5, TextWrapping = TextWrapping.Wrap };
        _mutedLabels.Add(block);
        return block;
    }

    private TextBlock SectionTitle(string text) => new()
    {
        Text = text.ToUpperInvariant(),
        FontSize = 11,
        FontWeight = FontWeight.Bold,
        Foreground = Accent(),
        LetterSpacing = 0.8,
        Margin = new Thickness(0, 6, 0, 0)
    };

    private static Control TwoCol(Control left, Control right)
    {
        var grid = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,14,*") };
        Grid.SetColumn(right, 2);
        grid.Children.Add(left);
        grid.Children.Add(right);
        return grid;
    }

    private static Control ThreeCol(Control a, Control b, Control c)
    {
        var grid = new Grid { ColumnDefinitions = ColumnDefinitions.Parse("*,12,*,12,*") };
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

    private static void StyleAction(Button button, string title, string tip, bool primary, bool dark = false, bool loaded = false)
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
        var content = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 7,
            HorizontalAlignment = HorizontalAlignment.Center
        };
        if (loaded)
        {
            content.Children.Add(new TextBlock
            {
                Text = "✓",
                FontSize = 15,
                FontWeight = FontWeight.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(52, 211, 153)),
                VerticalAlignment = VerticalAlignment.Center
            });
        }
        content.Children.Add(label);
        content.Children.Add(info);
        button.Content = content;
        button.Height = primary ? 46 : 40;
        button.CornerRadius = new CornerRadius(12);
        button.BorderThickness = new Thickness(0);
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
            button.Background = dark ? Rgb(40, 52, 54) : Rgb(236, 242, 241);
            var ink = dark ? Rgb(232, 241, 239) : Rgb(24, 42, 44);
            button.Foreground = ink;
            label.Foreground = ink;
            info.Foreground = ink;
        }
        ToolTip.SetTip(button, tip);
        ToolTip.SetShowDelay(button, 150);
    }

    private static void TintButtonText(Button button, IBrush color)
    {
        if (button.Content is StackPanel stack)
        {
            foreach (var child in stack.Children)
            {
                if (child is TextBlock text)
                    text.Foreground = color;
            }
        }
    }

    private static void StyleGhost(Button button, string title, bool dark = false)
    {
        button.Content = title;
        button.Height = 32;
        button.Padding = new Thickness(12, 0);
        button.CornerRadius = new CornerRadius(9);
        button.BorderThickness = new Thickness(0);
        button.Background = dark ? Rgb(28, 40, 42) : Rgb(36, 56, 58);
        button.Foreground = new SolidColorBrush(Color.FromRgb(210, 230, 226));
    }

    private static TextBox Field(string watermark) => new()
    {
        Watermark = watermark,
        HorizontalAlignment = HorizontalAlignment.Stretch,
        Height = 38,
        VerticalContentAlignment = VerticalAlignment.Center,
        CornerRadius = new CornerRadius(9),
        Padding = new Thickness(12, 0)
    };

    private static NumericUpDown NumberField(decimal min, decimal max, decimal value) => new()
    {
        Minimum = min,
        Maximum = max,
        Value = value,
        Increment = 1,
        FormatString = "0",
        HorizontalAlignment = HorizontalAlignment.Stretch,
        Height = 38,
        VerticalContentAlignment = VerticalAlignment.Center,
        Padding = new Thickness(12, 0),
        CornerRadius = new CornerRadius(9),
        ShowButtonSpinner = false,
        AllowSpin = true
    };

    private static string PlatformName =>
        OperatingSystem.IsMacOS() ? "macOS"
        : OperatingSystem.IsLinux() ? "Linux"
        : OperatingSystem.IsWindows() ? "Windows"
        : "desktop";

    private static SolidColorBrush Accent() => new(Color.FromRgb(14, 122, 122));

    private static SolidColorBrush Rgb(byte r, byte g, byte b) => new(Color.FromRgb(r, g, b));

    private static SolidColorBrush Rgba(byte a, byte r, byte g, byte b) => new(Color.FromArgb(a, r, g, b));

    private const string InterpretationText =
        "TEST PATH — tries UDP, TCP and TLS without a password.\n" +
        "A 401/407 is success: the PBX is reachable and return traffic works.\n\n" +
        "TEST SIP REGISTRATION — one authenticated REGISTER.\n" +
        "Tick Keep Registered On The PBX to leave it visible in Yeastar, then Unregister Now.\n" +
        "200 OK means credentials work from this computer.\n\n" +
        "CHECK PBX STATUS — Yeastar API: extension online, assigned phone, blocked IPs.\n\n" +
        "DNS fails — wrong hostname or DNS policy.\n" +
        "TCP/TLS connect fails — firewall, ISP, wrong port, or service down.\n" +
        "TLS handshake fails — certificate, clock, or TLS inspection.\n" +
        "Via sent-by rewritten — SIP ALG. received=/rport= alone is normal NAT.\n" +
        "UDP silent while TCP/TLS answers — the router, not the PBX. If you cannot change the router, put the Yealink on TLS.\n" +
        "Do not enable STUN to fix SIP ALG.\n" +
        "Clock vs certificate — fix NTP (no private 172.19.x.x) before blaming TLS.";
}
