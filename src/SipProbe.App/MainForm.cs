using System.Drawing.Drawing2D;
using InspireTel.SipProbe.Core;
using Microsoft.Win32;

namespace InspireTel.SipProbe.App;

public sealed class MainForm : Form
{
    private readonly ToolTip _tips = new()
    {
        AutoPopDelay = 20000,
        InitialDelay = 150,
        ReshowDelay = 100,
        ShowAlways = true
    };

    private readonly TextBox _server = new() { PlaceholderText = "pbx.example.com" };
    private readonly NumericUpDown _port = NumberField(1, 65535, 5061);
    private readonly ComboBox _transport = new() { DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat };
    private readonly TextBox _sipUser = new() { PlaceholderText = "Extension / SIP user" };
    private readonly TextBox _authName = new() { PlaceholderText = "Registration / authentication name" };
    private readonly TextBox _password = new() { UseSystemPasswordChar = true, PlaceholderText = "Not saved or logged" };
    private readonly NumericUpDown _localPort = NumberField(0, 65535, 0);
    private readonly NumericUpDown _expiry = NumberField(30, 86400, 600);
    private readonly NumericUpDown _timeout = NumberField(2, 60, 7);
    private readonly CheckBox _forceTls12 = new() { Text = "Force TLS 1.2", Checked = true, AutoSize = true };
    private readonly CheckBox _ignoreCertificateErrors = new()
    {
        Text = "Ignore certificate errors (diagnostic only)",
        AutoSize = true,
        ForeColor = Color.FromArgb(196, 92, 64)
    };
    private readonly NumericUpDown _udpPort = NumberField(1, 65535, 5060);
    private readonly NumericUpDown _tcpPort = NumberField(1, 65535, 5060);
    private readonly NumericUpDown _tlsPort = NumberField(1, 65535, 5061);
    private readonly TextBox _apiUrl = new() { PlaceholderText = "https://tenant.pbx.yeastarycm.co.za" };
    private readonly TextBox _apiClientId = new() { PlaceholderText = "OpenAPI Client ID" };
    private readonly TextBox _apiSecret = new() { UseSystemPasswordChar = true, PlaceholderText = "Not saved or logged" };
    private IReadOnlyList<string> _ntpServers = Array.Empty<string>();

    private readonly RichTextBox _log = new()
    {
        ReadOnly = true,
        BorderStyle = BorderStyle.None,
        BackColor = Color.FromArgb(10, 18, 20),
        ForeColor = Color.FromArgb(226, 232, 240),
        Font = new Font("Cascadia Mono", 9.25f),
        DetectUrls = false,
        WordWrap = false,
        Dock = DockStyle.Fill,
        ScrollBars = RichTextBoxScrollBars.Both,
        HideSelection = false
    };

    private readonly Button _runRegister = new();
    private readonly Button _runMatrix = new();
    private readonly Button _checkPbx = new();
    private readonly Button _loadCfg = new();
    private readonly Button _stop = new();
    private readonly Button _unregister = new();
    private readonly Button _clear = new();
    private readonly Button _export = new();
    private readonly Button _capture = new();
    private readonly CheckBox _keepRegistered = new()
    {
        Text = "Keep Registered On The PBX",
        Checked = true,
        AutoSize = true
    };
    private readonly CheckBox _relayToPbx = new()
    {
        Text = "Relay the handset to the PBX",
        AutoSize = true
    };
    private readonly CheckBox _darkMode = new()
    {
        Text = "Dark",
        AutoSize = true,
        Cursor = Cursors.Hand
    };

    private readonly Panel _header = new() { Dock = DockStyle.Fill, Padding = new Padding(24, 0, 22, 0) };
    private readonly Panel _leftCard = new() { Dock = DockStyle.Fill, Padding = new Padding(20, 18, 20, 12) };
    private readonly Panel _rightCard = new() { Dock = DockStyle.Fill };
    private readonly Panel _statusBar = new() { Dock = DockStyle.Fill, Padding = new Padding(24, 0, 22, 0) };
    private readonly Panel _actionDock = new()
    {
        Padding = new Padding(0, 12, 0, 0),
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink
    };
    private readonly Panel _advancedPanel = new() { Padding = new Padding(14, 12, 14, 14), Margin = new Padding(0, 10, 0, 4) };
    private readonly Panel _advancedToggle = new() { Height = 28, Cursor = Cursors.Hand };
    private readonly Panel _advancedBody = new() { Visible = false, AutoSize = true };
    private readonly Label _advancedHint = new()
    {
        Text = "Show extra ports, TLS and PBX API",
        AutoSize = true,
        Font = new Font("Segoe UI", 9f)
    };
    private readonly Panel _resultBanner = new() { Padding = new Padding(14, 12, 14, 12), Visible = false };
    private readonly Label _resultTitle = new()
    {
        Text = "",
        AutoSize = true,
        Font = new Font("Segoe UI Semibold", 14f),
        ForeColor = Color.FromArgb(110, 232, 180)
    };
    private readonly Label _resultDetail = new()
    {
        Text = "",
        AutoSize = true,
        MaximumSize = new Size(720, 0),
        Font = new Font("Segoe UI", 9.5f),
        ForeColor = Color.FromArgb(186, 230, 210)
    };
    private readonly Panel _chipConfig = DotPanel();
    private readonly Panel _chipPath = DotPanel();
    private readonly Panel _chipReg = DotPanel();
    private readonly Label _chipConfigText = RailLabel("Config");
    private readonly Label _chipPathText = RailLabel("Path");
    private readonly Label _chipRegText = RailLabel("SIP Registration");
    private readonly Panel _railLine1 = new() { Height = 2, Margin = new Padding(8, 9, 8, 0) };
    private readonly Panel _railLine2 = new() { Height = 2, Margin = new Padding(8, 9, 8, 0) };
    private readonly Panel _beacon = new() { Size = new Size(9, 9), Margin = new Padding(10, 10, 0, 0) };
    private readonly Label _title = new()
    {
        Text = "SIP Probe",
        AutoSize = true,
        Font = new Font("Segoe UI Semibold", 22f),
        ForeColor = Color.FromArgb(12, 32, 34)
    };
    private readonly Label _subtitle = new()
    {
        Text = "Find out why a handset will not register — without guessing.",
        AutoSize = true,
        Font = new Font("Segoe UI", 9.5f),
        ForeColor = Color.FromArgb(90, 110, 108)
    };
    private readonly Label _status = new()
    {
        Text = "Ready",
        AutoSize = false,
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleLeft,
        ForeColor = Color.FromArgb(90, 110, 108)
    };
    private readonly Label _version = new()
    {
        Text = "v1.4",
        AutoSize = true,
        Font = new Font("Segoe UI", 9f),
        ForeColor = Color.FromArgb(90, 110, 108)
    };

    private readonly List<Label> _mutedLabels = new();
    private readonly List<Label> _infoIcons = new();
    private readonly List<Button> _eyeButtons = new();
    private readonly List<Control> _inputs = new();
    private readonly List<DiagnosticLogEntry> _allEntries = new();
    private CancellationTokenSource? _activeRun;
    private bool _applyingTheme;
    private bool _configLoaded;
    private string? _configName;
    private string _pathState = "idle";
    private string _regState = "idle";
    private DiagnosticProfile? _heldProfile;
    private IHeldSipRegistration? _heldSession;
    private bool _passwordRevealed;
    private bool _apiSecretRevealed;
    private SipCaptureListener? _captureListener;
    private bool _configBlocked;

    private const int CapturePort = 5060;

    private const string CaptureTip =
        "Listens on port 5060 for SIP from the handset. Point the phone's SIP server (or outbound proxy) at this computer, " +
        "then reboot it. Shows the handset's REGISTER verbatim, including the authentication name it really uses.";

    public MainForm()
    {
        Text = "InspireTel SIP Probe";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1080, 700);
        Size = new Size(1280, 820);
        Font = new Font("Segoe UI", 9.5f);
        AutoScaleMode = AutoScaleMode.Dpi;

        _mutedLabels.AddRange(new[] { _chipConfigText, _chipPathText, _chipRegText });
        StyleAction(_loadCfg, "Load Phone Config",
            "Reads a Yealink .cfg and fills the fields. The password stays in memory and is never logged.", false);
        StyleAction(_runMatrix, "Test Path",
            "Tries UDP, TCP and TLS without the password. A 401 means the PBX is reachable. Safe first step — it will not lock the extension.", false);
        StyleAction(_runRegister, "Test SIP Registration",
            "Sends one authenticated REGISTER with these credentials. Tick Keep Registered On The PBX so you can confirm it in Yeastar.", true);
        StyleAction(_checkPbx, "Check PBX Status",
            "Looks up this extension on the Yeastar: online or not, assigned phone, and blocked IPs. Needs Client ID and Secret under Advanced.", false);
        StyleAction(_stop, "Stop", "Cancels the test that is currently running.", false);
        StyleAction(_unregister, "Unregister Now",
            "Removes the diagnostic registration from the PBX so the extension is free again.", false);
        StyleAction(_capture, "Listen For Handset", CaptureTip, false);
        StyleGhost(_clear, "Clear");
        StyleGhost(_export, "Export");
        _unregister.Visible = false;
        _tips.SetToolTip(_relayToPbx,
            "While listening, forward the handset's SIP to the PBX using the settings above. This laptop does the DNS lookup and TLS handshake, " +
            "so if the handset registers this way its credentials and SIP stack are fine and the fault is in its own path.");
        _tips.SetToolTip(_keepRegistered,
            "If ticked, a successful Test SIP Registration stays on the PBX until Unregister Now or the expiry timer. Use this to confirm the binding in Yeastar.");

        _transport.Items.AddRange(Enum.GetNames<SipTransport>());
        _transport.SelectedItem = SipTransport.Tls.ToString();
        _transport.SelectedIndexChanged += (_, _) =>
        {
            _port.Value = MatrixPortFor(SelectedTransport());
            var tls = SelectedTransport() == SipTransport.Tls;
            _forceTls12.Enabled = tls;
            _ignoreCertificateErrors.Enabled = tls;
        };

        _ignoreCertificateErrors.CheckedChanged += (_, _) =>
        {
            if (_ignoreCertificateErrors.Checked)
            {
                MessageBox.Show(
                    this,
                    "Certificate validation will be bypassed only inside this diagnostic run. Do not treat a successful result with this option as proof that the handset will trust the certificate.",
                    "Diagnostic-only certificate bypass",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        };

        _runRegister.Click += async (_, _) => await RunAuthenticatedAsync();
        _runMatrix.Click += async (_, _) => await RunMatrixAsync();
        _checkPbx.Click += async (_, _) => await RunPbxCheckAsync();
        _unregister.Click += async (_, _) => await RunUnregisterAsync();
        _loadCfg.Click += (_, _) => LoadYealinkConfig();
        _capture.Click += async (_, _) => await ToggleCaptureAsync();
        _stop.Click += (_, _) => _activeRun?.Cancel();
        _clear.Click += (_, _) => ClearLog();
        _export.Click += (_, _) => ExportLog();
        _stop.Enabled = false;
        _darkMode.Checked = SystemPrefersDark();
        _darkMode.CheckedChanged += (_, _) =>
        {
            if (!_applyingTheme)
                ApplyTheme();
        };

        RoundCorners(_beacon, 5);
        RoundCorners(_leftCard, 18);
        RoundCorners(_rightCard, 18);
        RoundCorners(_advancedPanel, 12);
        RoundCorners(_resultBanner, 12);
        foreach (var button in new[] { _loadCfg, _runMatrix, _runRegister, _checkPbx, _stop, _unregister, _capture })
            RoundCorners(button, 12);
        RoundCorners(_clear, 9);
        RoundCorners(_export, 9);

        Controls.Add(BuildRoot());
        ApplyTheme();
        RefreshResultBanner();
        AppendWelcome();
        FormClosed += (_, _) =>
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
    }

    private Control BuildRoot()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(0),
            Margin = new Padding(0)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 76));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        root.Controls.Add(BuildHeader(), 0, 0);
        root.Controls.Add(BuildBody(), 0, 1);
        root.Controls.Add(BuildStatusBar(), 0, 2);
        return root;
    }

    private Control BuildHeader()
    {
        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var mark = new Panel
        {
            Width = 6,
            Height = 30,
            BackColor = Accent,
            Margin = new Padding(0, 16, 14, 0)
        };
        RoundCorners(mark, 3);
        var titleRow = new FlowLayoutPanel
        {
            AutoSize = true,
            WrapContents = false,
            Margin = new Padding(0)
        };
        titleRow.Controls.Add(_title);
        titleRow.Controls.Add(_beacon);
        var titles = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Margin = new Padding(0, 8, 0, 0)
        };
        titles.Controls.Add(titleRow);
        _subtitle.Margin = new Padding(0, 0, 0, 0);
        titles.Controls.Add(_subtitle);
        var brand = new FlowLayoutPanel
        {
            AutoSize = true,
            WrapContents = false,
            Margin = new Padding(0)
        };
        brand.Controls.Add(mark);
        brand.Controls.Add(titles);

        var tools = new FlowLayoutPanel
        {
            AutoSize = true,
            WrapContents = false,
            FlowDirection = FlowDirection.LeftToRight,
            Margin = new Padding(0, 20, 0, 0)
        };
        _darkMode.Margin = new Padding(0, 2, 14, 0);
        _version.Margin = new Padding(0, 4, 0, 0);
        _mutedLabels.Add(_version);
        tools.Controls.Add(_darkMode);
        tools.Controls.Add(_version);

        grid.Controls.Add(brand, 0, 0);
        grid.Controls.Add(tools, 2, 0);
        _header.Controls.Add(grid);
        return _header;
    }

    private Control BuildBody()
    {
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            FixedPanel = FixedPanel.Panel1,
            SplitterWidth = 20,
            BackColor = Color.Transparent,
            Padding = new Padding(22, 16, 22, 14)
        };
        split.Panel1.Padding = new Padding(0, 0, 0, 0);
        split.Panel2.Padding = new Padding(0);
        _leftCard.Controls.Add(BuildConfigurationPanel());
        _rightCard.Controls.Add(BuildLogPanel());
        split.Panel1.Controls.Add(_leftCard);
        split.Panel2.Controls.Add(_rightCard);

        // A new SplitContainer is only 150px wide, so applying the minimum
        // panel sizes here would leave no valid splitter position and throw.
        // Wait until layout has given it a real width.
        void ApplyInitialSplit(object? sender, EventArgs e)
        {
            const int panel1Min = 380;
            const int panel2Min = 420;
            const int preferred = 440;
            var available = split.Width - split.SplitterWidth;
            if (available < panel1Min + panel2Min)
                return;

            split.SizeChanged -= ApplyInitialSplit;
            split.SplitterDistance = Math.Clamp(preferred, panel1Min, available - panel2Min);
            split.Panel1MinSize = panel1Min;
            split.Panel2MinSize = panel2Min;
        }

        split.SizeChanged += ApplyInitialSplit;
        return split;
    }

    private Control BuildConfigurationPanel()
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3
        };
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var intro = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Margin = new Padding(0, 0, 0, 10)
        };
        intro.Controls.Add(SectionTitle("Endpoint"));
        intro.Controls.Add(Muted("Same values as the handset. Load a Yealink cfg if you have one."));

        var fields = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Dock = DockStyle.Top
        };
        fields.Controls.Add(FullWidth(Labeled("PBX hostname", Track(_server), "DNS name of the Cloud PBX, not an IP, when using TLS.")));
        fields.Controls.Add(TwoCol(
            Labeled("Transport", Track(_transport), "Must match the extension on the PBX. Yeastar Cloud remote phones usually use TLS."),
            Labeled("Port", Track(_port), "Destination port for Test SIP Registration. TLS is typically 5061; UDP/TCP 5060.")));
        fields.Controls.Add(TwoCol(
            Labeled("SIP user", Track(_sipUser), "Extension number, for example 101."),
            Labeled("Auth name", Track(_authName), "P-Series Registration Name. Often different from the extension number.")));
        fields.Controls.Add(FullWidth(Labeled("Password", BuildPasswordField(_password, isApiSecret: false), "Registration password. Never written to the log or export.")));
        fields.Controls.Add(BuildAdvancedSection());

        var scroller = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        void FitFields()
        {
            var width = Math.Max(320, scroller.ClientSize.Width - 8);
            fields.Width = width;
            _advancedPanel.Width = width;
            _advancedToggle.Width = width;
            _advancedBody.Width = width;
        }
        scroller.Resize += (_, _) => FitFields();
        FitFields();
        scroller.Controls.Add(fields);

        _actionDock.Controls.Add(BuildActionPanel());
        _actionDock.Dock = DockStyle.Top;
        panel.Controls.Add(intro, 0, 0);
        panel.Controls.Add(scroller, 0, 1);
        panel.Controls.Add(_actionDock, 0, 2);
        return panel;
    }

    private Control BuildAdvancedSection()
    {
        var header = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3, Height = 24 };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var glyph = new Label
        {
            Text = "▸",
            AutoSize = true,
            Font = new Font("Segoe UI", 8f),
            Margin = new Padding(2, 3, 6, 0)
        };
        var title = new Label
        {
            Text = "ADVANCED",
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 9.5f),
            Margin = new Padding(0, 2, 0, 0)
        };
        _mutedLabels.Add(glyph);
        _mutedLabels.Add(title);
        _mutedLabels.Add(_advancedHint);
        header.Controls.Add(glyph, 0, 0);
        header.Controls.Add(title, 1, 0);
        header.Controls.Add(_advancedHint, 2, 0);

        header.Dock = DockStyle.Fill;
        _advancedToggle.Controls.Add(header);
        void ToggleAdvanced(object? sender, EventArgs e)
        {
            _advancedBody.Visible = !_advancedBody.Visible;
            glyph.Text = _advancedBody.Visible ? "▾" : "▸";
            _advancedHint.Text = _advancedBody.Visible ? "Hide" : "Show extra ports, TLS and PBX API";
        }
        _advancedToggle.Click += ToggleAdvanced;
        header.Click += ToggleAdvanced;
        title.Click += ToggleAdvanced;
        glyph.Click += ToggleAdvanced;
        _advancedHint.Click += ToggleAdvanced;
        title.Cursor = Cursors.Hand;
        glyph.Cursor = Cursors.Hand;
        _advancedHint.Cursor = Cursors.Hand;

        _advancedBody.Dock = DockStyle.Top;
        _advancedBody.Controls.Add(BuildAdvanced());

        var stack = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Dock = DockStyle.Top
        };
        _advancedToggle.Width = 390;
        _advancedBody.Width = 390;
        stack.Controls.Add(_advancedToggle);
        stack.Controls.Add(_advancedBody);
        _advancedPanel.Controls.Add(stack);
        _advancedPanel.AutoSize = true;
        _advancedPanel.Dock = DockStyle.Top;
        _advancedPanel.Width = 390;
        return _advancedPanel;
    }

    private Control BuildAdvanced()
    {
        var stack = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(0, 10, 0, 0)
        };
        stack.Controls.Add(ThreeCol(
            Labeled("Local port", Track(_localPort), "0 = automatic. Change only if you are testing a specific source port."),
            Labeled("Expiry", Track(_expiry), "REGISTER Expires. Yeastar Cloud minimum is often 600."),
            Labeled("Timeout", Track(_timeout), "Seconds to wait for each network step.")));
        stack.Controls.Add(TlsOptions());
        stack.Controls.Add(SectionTitle("Path test ports"));
        stack.Controls.Add(Muted("Test Path tries all three. A custom Test SIP Registration port is added if it is different."));
        stack.Controls.Add(ThreeCol(
            Labeled("UDP", Track(_udpPort), "UDP listener to try during Test Path."),
            Labeled("TCP", Track(_tcpPort), "TCP listener to try during Test Path."),
            Labeled("TLS", Track(_tlsPort), "TLS listener to try during Test Path.")));
        stack.Controls.Add(SectionTitle("PBX API"));
        stack.Controls.Add(Muted("Settings → Integrations → API. Leave URL blank to use https:// plus the hostname."));
        stack.Controls.Add(FullWidth(Labeled("API URL", Track(_apiUrl), "Yeastar web URL. Blank means https:// plus the PBX hostname.")));
        stack.Controls.Add(TwoCol(
            Labeled("Client ID", Track(_apiClientId), "OpenAPI Client ID from the PBX."),
            Labeled("Client secret", BuildPasswordField(_apiSecret, isApiSecret: true), "OpenAPI Client Secret. Never logged.")));
        return stack;
    }

    private Control TlsOptions()
    {
        var stack = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Margin = new Padding(0, 4, 0, 8)
        };
        stack.Controls.Add(_forceTls12);
        stack.Controls.Add(_ignoreCertificateErrors);
        return stack;
    }

    private Control BuildPasswordField(TextBox password, bool isApiSecret)
    {
        var panel = new Panel { Height = 32, Width = 360, Margin = new Padding(0, 0, 0, 0) };
        password.Dock = DockStyle.Fill;
        var eye = new Button
        {
            Text = "\uE7B3",
            Font = new Font("Segoe MDL2 Assets", 10f),
            Width = 32,
            Dock = DockStyle.Right,
            FlatStyle = FlatStyle.Flat,
            TabStop = false,
            Cursor = Cursors.Hand
        };
        eye.FlatAppearance.BorderSize = 0;
        _tips.SetToolTip(eye, "Show password");
        eye.Click += (_, _) =>
        {
            if (isApiSecret)
            {
                _apiSecretRevealed = !_apiSecretRevealed;
                password.UseSystemPasswordChar = !_apiSecretRevealed;
                _tips.SetToolTip(eye, _apiSecretRevealed ? "Hide password" : "Show password");
            }
            else
            {
                _passwordRevealed = !_passwordRevealed;
                password.UseSystemPasswordChar = !_passwordRevealed;
                _tips.SetToolTip(eye, _passwordRevealed ? "Hide password" : "Show password");
            }
        };
        _eyeButtons.Add(eye);
        panel.Controls.Add(password);
        panel.Controls.Add(eye);
        eye.BringToFront();
        return panel;
    }

    private Control BuildActionPanel()
    {
        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 2,
            RowCount = 5,
            Margin = new Padding(0, 8, 0, 0)
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        for (var row = 0; row < 5; row++)
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _loadCfg.Margin = new Padding(0, 0, 5, 8);
        _runRegister.Margin = new Padding(5, 0, 0, 8);
        _runMatrix.Margin = new Padding(0, 0, 5, 8);
        _checkPbx.Margin = new Padding(5, 0, 0, 8);
        _capture.Margin = new Padding(0, 0, 0, 8);
        _keepRegistered.Margin = new Padding(0, 4, 0, 8);
        _stop.Margin = new Padding(0);
        _unregister.Margin = new Padding(0);
        _loadCfg.Dock = DockStyle.Fill;
        _runRegister.Dock = DockStyle.Fill;
        _runMatrix.Dock = DockStyle.Fill;
        _checkPbx.Dock = DockStyle.Fill;
        _capture.Dock = DockStyle.Fill;
        _stop.Dock = DockStyle.Fill;
        _unregister.Dock = DockStyle.Fill;

        grid.Controls.Add(_loadCfg, 0, 0);
        grid.Controls.Add(_runRegister, 1, 0);
        grid.Controls.Add(_runMatrix, 0, 1);
        grid.Controls.Add(_checkPbx, 1, 1);
        grid.SetColumnSpan(_capture, 2);
        grid.Controls.Add(_capture, 0, 2);

        var toggles = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Margin = new Padding(0, 4, 0, 8)
        };
        _relayToPbx.Margin = new Padding(0, 0, 0, 4);
        _keepRegistered.Margin = new Padding(0);
        toggles.Controls.Add(_relayToPbx);
        toggles.Controls.Add(_keepRegistered);
        grid.SetColumnSpan(toggles, 2);
        grid.Controls.Add(toggles, 0, 3);

        var stopRow = new Panel { Height = 38, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 0) };
        stopRow.Controls.Add(_stop);
        stopRow.Controls.Add(_unregister);
        grid.SetColumnSpan(stopRow, 2);
        grid.Controls.Add(stopRow, 0, 4);
        return grid;
    }

    private Control BuildLogPanel()
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3
        };
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var chips = BuildSignalRail();

        _resultBanner.AutoSize = true;
        _resultBanner.Dock = DockStyle.Top;
        _resultBanner.Margin = new Padding(12, 8, 12, 8);
        var headline = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Dock = DockStyle.Fill
        };
        _resultTitle.Margin = new Padding(0);
        _resultDetail.Margin = new Padding(0, 4, 0, 0);
        headline.Controls.Add(_resultTitle);
        headline.Controls.Add(_resultDetail);
        _resultBanner.Controls.Add(headline);

        var top = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Dock = DockStyle.Fill
        };
        top.Controls.Add(chips);
        top.Controls.Add(_resultBanner);

        var toolbar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            BackColor = Color.FromArgb(16, 28, 30),
            Padding = new Padding(14, 0, 14, 0)
        };
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var live = new Label
        {
            Text = "Live trace",
            ForeColor = Color.FromArgb(210, 230, 226),
            Font = new Font("Segoe UI Semibold", 10f),
            AutoSize = true,
            Dock = DockStyle.Left,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(0, 14, 0, 0)
        };
        _clear.Margin = new Padding(0, 8, 8, 8);
        _export.Margin = new Padding(0, 8, 0, 8);
        toolbar.Controls.Add(live, 0, 0);
        toolbar.Controls.Add(_clear, 1, 0);
        toolbar.Controls.Add(_export, 2, 0);

        panel.Controls.Add(top, 0, 0);
        panel.Controls.Add(toolbar, 0, 1);
        panel.Controls.Add(_log, 0, 2);
        return panel;
    }

    private Control BuildSignalRail()
    {
        var row = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 5,
            RowCount = 1,
            Margin = new Padding(14, 14, 14, 0)
        };
        row.Controls.Add(RailNode(_chipConfig, _chipConfigText), 0, 0);
        row.Controls.Add(_railLine1, 1, 0);
        row.Controls.Add(RailNode(_chipPath, _chipPathText), 2, 0);
        row.Controls.Add(_railLine2, 3, 0);
        row.Controls.Add(RailNode(_chipReg, _chipRegText), 4, 0);
        _railLine1.Width = 36;
        _railLine2.Width = 36;
        return row;
    }

    private static Control RailNode(Panel dot, Label label)
    {
        var node = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        dot.Margin = new Padding(0, 6, 7, 0);
        label.Margin = new Padding(0);
        node.Controls.Add(dot);
        node.Controls.Add(label);
        return node;
    }

    private Control BuildStatusBar()
    {
        var bar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2
        };
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var help = new LinkLabel
        {
            Text = "How to read results",
            AutoSize = true,
            LinkColor = Accent,
            ActiveLinkColor = Accent,
            Margin = new Padding(8, 10, 0, 0)
        };
        help.LinkClicked += (_, _) =>
        {
            MessageBox.Show(this, InterpretationText, "How to read results", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };
        bar.Controls.Add(_status, 0, 0);
        bar.Controls.Add(help, 1, 0);
        _statusBar.Controls.Add(bar);
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
            MessageBox.Show(this, ex.Message, "Check the probe configuration", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
            MessageBox.Show(this, ex.Message, "Check the probe configuration", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        SetRunning(true, "Testing UDP, TCP and TLS without a password...");
        _activeRun = new CancellationTokenSource();
        var anyReachable = false;
        var allReachable = true;
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
                anyReachable |= result.SipResponseReceived;
                allReachable &= result.SipResponseReceived;
            }
            _pathState = allReachable ? "ok" : anyReachable ? "partial" : "fail";
            _status.Text = allReachable ? "Path Reachable" : anyReachable ? "Path Partially Reachable" : "Path Failed";
            RefreshResultBanner();
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
            SetRunning(false, _status.Text);
        }
    }

    private async Task RunOneAsync(DiagnosticProfile profile)
    {
        SetRunning(true, "Testing SIP registration...");
        _activeRun = new CancellationTokenSource();
        try
        {
            var result = await ExecuteEngineAsync(profile, _activeRun.Token);
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
            RefreshResultBanner();
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
            SetRunning(false, _status.Text);
        }
    }

    private async Task<DiagnosticResult> ExecuteEngineAsync(DiagnosticProfile profile, CancellationToken token)
    {
        var engine = new SipDiagnosticEngine();
        engine.EntryAdded += entry =>
        {
            if (IsDisposed)
                return;
            if (InvokeRequired)
                BeginInvoke(() => AppendEntry(entry));
            else
                AppendEntry(entry);
        };
        return await engine.RunAsync(profile, token);
    }

    private async Task RunPbxCheckAsync()
    {
        if (string.IsNullOrWhiteSpace(_sipUser.Text))
        {
            MessageBox.Show(this, "Enter the SIP user / extension first.", "Check the probe configuration",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(_apiClientId.Text) || string.IsNullOrWhiteSpace(_apiSecret.Text))
        {
            MessageBox.Show(this,
                "Open Advanced and enter the Yeastar OpenAPI Client ID and Client Secret. They are under Settings → Integrations → API on the PBX.",
                "Check PBX Status",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var apiUrl = string.IsNullOrWhiteSpace(_apiUrl.Text)
            ? "https://" + _server.Text.Trim()
            : _apiUrl.Text.Trim();

        AppendSeparator("CHECK PBX STATUS");
        SetRunning(true, "Checking PBX...");
        _activeRun = new CancellationTokenSource();
        try
        {
            var diagnostic = new YeastarPbxDiagnostic();
            diagnostic.EntryAdded += entry =>
            {
                if (IsDisposed)
                    return;
                if (InvokeRequired)
                    BeginInvoke(() => AppendEntry(entry));
                else
                    AppendEntry(entry);
            };
            await diagnostic.RunAsync(new YeastarPbxCheckRequest
            {
                ApiBaseUrl = apiUrl,
                ClientId = _apiClientId.Text,
                ClientSecret = _apiSecret.Text,
                ExtensionNumber = _sipUser.Text,
                AuthenticationName = _authName.Text,
                TimeoutSeconds = (int)_timeout.Value
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
            SetRunning(false, _status.Text);
        }
    }

    private DiagnosticProfile ReadProfile(bool authenticate) => new()
    {
        Server = _server.Text,
        Port = (int)_port.Value,
        UdpPort = (int)_udpPort.Value,
        TcpPort = (int)_tcpPort.Value,
        TlsPort = (int)_tlsPort.Value,
        Transport = SelectedTransport(),
        SipUser = _sipUser.Text,
        AuthenticationName = _authName.Text,
        Password = authenticate ? _password.Text : string.Empty,
        LocalPort = (int)_localPort.Value,
        RegistrationExpirySeconds = (int)_expiry.Value,
        TimeoutSeconds = (int)_timeout.Value,
        ForceTls12 = _forceTls12.Checked,
        IgnoreTlsCertificateErrors = _ignoreCertificateErrors.Checked,
        Authenticate = authenticate,
        KeepRegistered = _keepRegistered.Checked,
        NtpServers = _ntpServers
    };

    private SipTransport SelectedTransport() =>
        Enum.TryParse<SipTransport>(_transport.SelectedItem?.ToString(), out var value) ? value : SipTransport.Tls;

    private decimal MatrixPortFor(SipTransport transport) => transport switch
    {
        SipTransport.Udp => _udpPort.Value,
        SipTransport.Tcp => _tcpPort.Value,
        _ => _tlsPort.Value
    };

    private void SetRunning(bool running, string status)
    {
        _runRegister.Enabled = !running;
        _runMatrix.Enabled = !running;
        _checkPbx.Enabled = !running;
        _loadCfg.Enabled = !running;
        _keepRegistered.Enabled = !running;
        _relayToPbx.Enabled = !running && _captureListener is null;
        _stop.Enabled = running;
        _stop.Visible = running || _heldProfile is null;
        _unregister.Visible = !running && _heldProfile is not null;
        _unregister.Enabled = !running && _heldProfile is not null;
        _transport.Enabled = !running;
        _status.Text = status;
        UseWaitCursor = running;
        UpdateBeacon(running);
    }

    private void AppendWelcome()
    {
        AppendLocal(DiagnosticLevel.Info, "Load Phone Config, then Test Path. A 401 means the PBX is reachable. Then Test SIP Registration.");
        AppendLocal(DiagnosticLevel.Detail, "Tick Keep Registered On The PBX if you want to confirm the binding in Yeastar. Passwords are never logged.");
    }

    private void AppendSeparator(string title)
    {
        var line = Environment.NewLine + "──  " + title + "  ──" + Environment.NewLine;
        _log.SelectionStart = _log.TextLength;
        _log.SelectionColor = Color.FromArgb(94, 234, 212);
        _log.AppendText(line);
        _log.ScrollToCaret();
    }

    private void AppendLocal(DiagnosticLevel level, string message) =>
        AppendEntry(new DiagnosticLogEntry(DateTimeOffset.Now, level, message));

    private void AppendEntry(DiagnosticLogEntry entry)
    {
        _allEntries.Add(entry);
        _log.SelectionStart = _log.TextLength;
        _log.SelectionColor = entry.Level switch
        {
            DiagnosticLevel.Success => Color.FromArgb(52, 211, 153),
            DiagnosticLevel.Warning => Color.FromArgb(251, 191, 36),
            DiagnosticLevel.Error => Color.FromArgb(248, 113, 113),
            DiagnosticLevel.Detail => Color.FromArgb(148, 163, 184),
            _ => Color.FromArgb(226, 232, 240)
        };
        _log.AppendText(entry + Environment.NewLine);
        _log.SelectionColor = _log.ForeColor;
        _log.ScrollToCaret();
    }

    private void ClearLog()
    {
        _allEntries.Clear();
        _log.Clear();
        AppendWelcome();
    }

    private void ExportLog()
    {
        using var dialog = new SaveFileDialog
        {
            Title = "Export redacted SIP diagnostic log",
            Filter = "Text log (*.txt)|*.txt|All files (*.*)|*.*",
            FileName = $"SIPProbe-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            AddExtension = true,
            DefaultExt = "txt"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;

        var header = new[]
        {
            "InspireTel SIP Probe v1.4 (Windows)",
            $"Exported: {DateTimeOffset.Now:u}",
            $"Server: {_server.Text.Trim()}:{_port.Value}",
            $"Transport: {_transport.SelectedItem}",
            $"SIP user: {_sipUser.Text.Trim()}",
            $"Authentication name: {_authName.Text.Trim()}",
            "Password/digest: REDACTED",
            new string('-', 72)
        };
        File.WriteAllLines(dialog.FileName, header.Concat(_allEntries.Select(entry => entry.ToString())));
        _status.Text = $"Log exported to {dialog.FileName}";
    }

    private void LoadYealinkConfig()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Load a generated Yealink configuration",
            Filter = "Yealink configuration (*.cfg)|*.cfg|Text files (*.txt)|*.txt|All files (*.*)|*.*",
            Multiselect = false,
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;

        try
        {
            ApplyYealinkSettings(dialog.FileName, YealinkConfigParser.Parse(File.ReadLines(dialog.FileName)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            MessageBox.Show(this, ex.Message, "Could not load Yealink configuration", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
        _configLoaded = true;
        _configName = Path.GetFileName(path);
        _status.Text = $"Config Loaded — {_configName}";
        RefreshResultBanner();
        ApplyTheme();
    }

    private async Task ToggleCaptureAsync()
    {
        if (_captureListener is not null)
        {
            await StopCaptureAsync();
            return;
        }

        var listener = new SipCaptureListener();
        listener.EntryAdded += entry =>
        {
            if (IsDisposed)
                return;
            if (InvokeRequired)
                BeginInvoke(() => AppendEntry(entry));
            else
                AppendEntry(entry);
        };

        try
        {
            AppendSeparator("LISTEN FOR HANDSET");
            await listener.StartAsync(new SipCaptureOptions
            {
                Port = CapturePort,
                Relay = _relayToPbx.Checked
                    ? new SipRelayTarget
                    {
                        Server = _server.Text.Trim(),
                        Port = (int)_port.Value,
                        Transport = SelectedTransport(),
                        ForceTls12 = _forceTls12.Checked,
                        IgnoreCertificateErrors = _ignoreCertificateErrors.Checked
                    }
                    : null
            });
            _captureListener = listener;
            _status.Text = $"Listening for the handset on port {CapturePort}";
            _capture.Text = "Stop Listening";
            _relayToPbx.Enabled = false;
        }
        catch (Exception ex)
        {
            await listener.DisposeAsync();
            MessageBox.Show(this, ex.Message, "Could not start listening", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private async Task StopCaptureAsync()
    {
        var listener = _captureListener;
        _captureListener = null;
        if (listener is null)
            return;

        await listener.DisposeAsync();
        _capture.Text = "Listen For Handset";
        _relayToPbx.Enabled = true;
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
            SetRunning(false, _status.Text);
        }
    }

    private void RefreshResultBanner()
    {
        PaintChip(_chipConfig, _chipConfigText, _configLoaded ? "ok" : "idle",
            _configLoaded ? "✓  Config Loaded" : "Config");
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

        if (_regState == "held")
        {
            ShowBanner(
                Color.FromArgb(14, 64, 52),
                Color.FromArgb(110, 232, 180),
                Color.FromArgb(186, 230, 210),
                "Passed — Registered",
                "The SIP session is being held open. Yeastar only shows TLS registrations while this connection stays up. Confirm it now, then click Unregister Now.");
        }
        else if (_regState == "ok")
        {
            ShowBanner(
                Color.FromArgb(14, 64, 52),
                Color.FromArgb(110, 232, 180),
                Color.FromArgb(186, 230, 210),
                "Passed — Registered",
                "SIP registration succeeded and was then removed. Tick Keep Registered On The PBX to leave it visible in Yeastar.");
        }
        else if (_regState == "fail")
        {
            ShowBanner(
                Color.FromArgb(72, 24, 24),
                Color.FromArgb(252, 165, 165),
                Color.FromArgb(254, 202, 202),
                "Registration Failed",
                "The PBX rejected or did not complete SIP registration. Read the live trace for the SIP code.");
        }
        else if (_pathState == "ok")
        {
            ShowBanner(
                Color.FromArgb(14, 52, 64),
                Color.FromArgb(125, 211, 252),
                Color.FromArgb(186, 220, 232),
                "Passed — Path Reachable",
                "The PBX answered on the tested transports. Next: Test SIP Registration.");
        }
        else if (_pathState == "fail")
        {
            ShowBanner(
                Color.FromArgb(72, 24, 24),
                Color.FromArgb(252, 165, 165),
                Color.FromArgb(254, 202, 202),
                "Path Failed",
                "No usable SIP response. Check DNS, firewall, port and transport.");
        }
        else if (_configBlocked)
        {
            ShowBanner(
                Color.FromArgb(72, 24, 24),
                Color.FromArgb(252, 165, 165),
                Color.FromArgb(254, 202, 202),
                "Handset Config Will Not Register",
                "This phone configuration has a fault that blocks registration on every transport, " +
                "even when this computer registers fine. Read the red lines in the trace.");
        }
        else if (_configLoaded)
        {
            ShowBanner(
                Color.FromArgb(14, 64, 52),
                Color.FromArgb(110, 232, 180),
                Color.FromArgb(186, 230, 210),
                "Config Loaded",
                _configName is null
                    ? "Phone configuration is in the fields."
                    : $"{_configName} is loaded. Next: Test Path, then Test SIP Registration.");
        }
        else
        {
            _resultBanner.Visible = false;
        }

        _unregister.Visible = _heldProfile is not null && _activeRun is null;
        _stop.Visible = _activeRun is not null || _heldProfile is null;
        UpdateBeacon();
    }

    private void UpdateBeacon(bool? runningOverride = null)
    {
        Color color;
        string tip;
        if (runningOverride ?? _activeRun is not null)
        {
            color = Color.FromArgb(251, 191, 36);
            tip = "Test running";
        }
        else if (_regState is "ok" or "held")
        {
            color = Color.FromArgb(52, 211, 153);
            tip = "Last result: registered";
        }
        else if (_regState == "fail" || _pathState == "fail")
        {
            color = Color.FromArgb(248, 113, 113);
            tip = "Last result: failed";
        }
        else if (_pathState is "ok" or "partial" || _configLoaded)
        {
            color = Color.FromArgb(56, 178, 172);
            tip = "Ready for the next step";
        }
        else
        {
            color = Color.FromArgb(120, 138, 136);
            tip = "Idle";
        }
        _beacon.BackColor = color;
        _tips.SetToolTip(_beacon, tip);
    }

    private void ShowBanner(Color background, Color title, Color detail, string heading, string body)
    {
        _resultBanner.Visible = true;
        _resultBanner.BackColor = background;
        _resultTitle.Text = heading;
        _resultTitle.ForeColor = title;
        _resultDetail.Text = body;
        _resultDetail.ForeColor = detail;
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

    private void OnHeldLog(DiagnosticLogEntry _)
    {
        void Handle()
        {
            if (_heldSession is { IsAlive: false })
            {
                _heldSession = null;
                _heldProfile = null;
                _regState = "fail";
                _status.Text = "Registration Dropped";
                RefreshResultBanner();
            }
        }

        if (IsDisposed)
            return;
        if (InvokeRequired)
            BeginInvoke(Handle);
        else
            Handle();
    }

    private static void PaintChip(Panel dot, Label label, string state, string text)
    {
        label.Text = text;
        label.Font = new Font("Segoe UI Semibold", state is "ok" or "held" or "fail" or "partial" ? 9f : 9f,
            state is "ok" or "held" or "fail" or "partial" ? FontStyle.Bold : FontStyle.Regular);
        dot.BackColor = state switch
        {
            "ok" or "held" => Color.FromArgb(52, 211, 153),
            "partial" => Color.FromArgb(251, 191, 36),
            "fail" => Color.FromArgb(248, 113, 113),
            _ => Color.FromArgb(120, 138, 136)
        };
    }

    private void ApplyTheme()
    {
        var dark = _darkMode.Checked;
        _applyingTheme = true;
        try
        {
            _darkMode.Checked = dark;
            var formBg = dark ? Color.FromArgb(9, 13, 14) : Color.FromArgb(226, 233, 231);
            var card = dark ? Color.FromArgb(26, 34, 36) : Color.White;
            var muted = dark ? Color.FromArgb(140, 160, 158) : Color.FromArgb(100, 118, 116);
            var text = dark ? Color.FromArgb(236, 245, 243) : Color.FromArgb(12, 32, 34);
            var inputBg = dark ? Color.FromArgb(36, 47, 49) : Color.FromArgb(246, 249, 248);
            var inputFg = dark ? Color.FromArgb(232, 241, 239) : Color.FromArgb(20, 36, 38);

            BackColor = formBg;
            _header.BackColor = formBg;
            _leftCard.BackColor = card;
            _actionDock.BackColor = card;
            var advancedBg = dark ? Color.FromArgb(19, 25, 27) : Color.FromArgb(242, 246, 245);
            _advancedPanel.BackColor = advancedBg;
            _advancedToggle.BackColor = advancedBg;
            _rightCard.BackColor = card;
            _statusBar.BackColor = formBg;
            _title.ForeColor = text;
            _subtitle.ForeColor = muted;
            _status.ForeColor = muted;
            _darkMode.ForeColor = text;
            _darkMode.BackColor = formBg;
            _keepRegistered.ForeColor = dark ? Color.FromArgb(210, 230, 226) : Color.FromArgb(24, 42, 44);
            _keepRegistered.BackColor = card;
            _relayToPbx.ForeColor = _keepRegistered.ForeColor;
            _relayToPbx.BackColor = card;
            _forceTls12.ForeColor = text;
            _forceTls12.BackColor = _advancedPanel.BackColor;
            _ignoreCertificateErrors.BackColor = advancedBg;

            _railLine1.BackColor = dark ? Color.FromArgb(42, 54, 55) : Color.FromArgb(214, 224, 221);
            _railLine2.BackColor = _railLine1.BackColor;
            foreach (var label in _mutedLabels)
                label.ForeColor = muted;
            foreach (var icon in _infoIcons)
            {
                icon.ForeColor = muted;
                icon.Invalidate();
            }

            foreach (var input in _inputs)
            {
                input.BackColor = inputBg;
                input.ForeColor = inputFg;
            }

            foreach (var eye in _eyeButtons)
            {
                eye.ForeColor = muted;
                eye.BackColor = inputBg;
            }

            StyleAction(_runRegister, "Test SIP Registration",
                "Sends one authenticated REGISTER with these credentials. Tick Keep Registered On The PBX so you can confirm it in Yeastar.", true, dark);
            StyleAction(_runMatrix, "Test Path",
                "Tries UDP, TCP and TLS without the password. A 401 means the PBX is reachable. Safe first step — it will not lock the extension.", false, dark);
            StyleAction(_loadCfg, _configLoaded ? "✓  Load Phone Config" : "Load Phone Config",
                "Reads a Yealink .cfg and fills the fields. The password stays in memory and is never logged.", false, dark);
            StyleAction(_checkPbx, "Check PBX Status",
                "Looks up this extension on the Yeastar: online or not, assigned phone, and blocked IPs. Needs Client ID and Secret under Advanced.", false, dark);
            StyleAction(_stop, "Stop", "Cancels the test that is currently running.", false, dark);
            StyleAction(_capture, _captureListener is null ? "Listen For Handset" : "Stop Listening", CaptureTip, false, dark);
            StyleAction(_unregister, "Unregister Now",
                "Removes the diagnostic registration from the PBX so the extension is free again.", false, dark);
            _unregister.BackColor = dark ? Color.FromArgb(57, 45, 41) : Color.FromArgb(249, 238, 236);
            _unregister.ForeColor = Color.FromArgb(214, 118, 88);
            StyleGhost(_clear, "Clear", dark);
            StyleGhost(_export, "Export", dark);
        }
        finally
        {
            _applyingTheme = false;
        }
    }

    private Control Track(Control control)
    {
        _inputs.Add(control);
        return control;
    }

    private Control Labeled(string title, Control field, string tip)
    {
        var text = new Label
        {
            Text = title,
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 9f),
            Margin = new Padding(0, 0, 0, 0),
            TextAlign = ContentAlignment.MiddleLeft,
            Height = 18
        };
        _mutedLabels.Add(text);
        var caption = new FlowLayoutPanel
        {
            AutoSize = true,
            WrapContents = false,
            FlowDirection = FlowDirection.LeftToRight,
            Height = 18,
            Margin = new Padding(0, 0, 0, 4)
        };
        var info = InfoIcon(tip);
        caption.Controls.Add(text);
        caption.Controls.Add(info);

        var stack = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Margin = new Padding(0, 0, 0, 16)
        };
        if (field is not ComboBox and not NumericUpDown)
            field.Height = 32;
        field.Width = 160;
        field.Margin = new Padding(0);
        stack.Controls.Add(caption);
        stack.Controls.Add(field);
        stack.Resize += (_, _) =>
        {
            var width = Math.Max(80, stack.ClientSize.Width);
            field.Width = width;
            caption.Width = width;
        };
        _tips.SetToolTip(field, tip);
        return stack;
    }

    private Control InfoIcon(string tip)
    {
        var icon = new Label
        {
            Text = "i",
            AutoSize = false,
            Size = new Size(14, 14),
            Font = new Font("Segoe UI", 7f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleCenter,
            Margin = new Padding(6, 2, 0, 0),
            Cursor = Cursors.Help
        };
        icon.Paint += (_, e) =>
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var pen = new Pen(icon.ForeColor, 1.15f);
            e.Graphics.DrawEllipse(pen, 0.6f, 0.6f, 12.2f, 12.2f);
        };
        _infoIcons.Add(icon);
        _tips.SetToolTip(icon, tip);
        return icon;
    }

    private Label SectionTitle(string text)
    {
        var label = new Label
        {
            Text = text.ToUpperInvariant(),
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 9.5f),
            Margin = new Padding(0, 6, 0, 2),
            ForeColor = Accent
        };
        return label;
    }

    private Label Muted(string text)
    {
        var block = new Label
        {
            Text = text,
            AutoSize = true,
            MaximumSize = new Size(360, 0),
            Font = new Font("Segoe UI", 9f),
            Margin = new Padding(0, 0, 0, 8)
        };
        _mutedLabels.Add(block);
        return block;
    }

    private static Control FullWidth(Control child)
    {
        child.Margin = new Padding(0, 0, 0, 16);
        if (child is FlowLayoutPanel panel)
        {
            foreach (Control inner in panel.Controls)
            {
                if (inner is TextBox or Panel)
                    inner.Width = 360;
            }
        }
        return child;
    }

    private static Control TwoCol(Control left, Control right)
    {
        var grid = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 3,
            Margin = new Padding(0, 0, 0, 0)
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 14));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        left.Dock = DockStyle.Fill;
        right.Dock = DockStyle.Fill;
        grid.Controls.Add(left, 0, 0);
        grid.Controls.Add(right, 2, 0);
        return grid;
    }

    private static Control ThreeCol(Control a, Control b, Control c)
    {
        var grid = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 5,
            Margin = new Padding(0, 0, 0, 0)
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 12));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 12));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
        a.Dock = DockStyle.Fill;
        b.Dock = DockStyle.Fill;
        c.Dock = DockStyle.Fill;
        grid.Controls.Add(a, 0, 0);
        grid.Controls.Add(b, 2, 0);
        grid.Controls.Add(c, 4, 0);
        return grid;
    }

    private static Panel DotPanel()
    {
        var dot = new Panel { Size = new Size(9, 9), Margin = new Padding(0) };
        RoundCorners(dot, 5);
        return dot;
    }

    private static Label RailLabel(string text) => new()
    {
        Text = text,
        AutoSize = true,
        Margin = new Padding(0),
        Font = new Font("Segoe UI Semibold", 9f)
    };

    private static void RoundCorners(Control control, int radius)
    {
        void Apply()
        {
            if (control.Width <= 1 || control.Height <= 1)
                return;
            using var path = RoundedRectPath(new Rectangle(0, 0, control.Width, control.Height), radius);
            var previous = control.Region;
            control.Region = new Region(path);
            previous?.Dispose();
        }

        control.Resize += (_, _) => Apply();
        Apply();
    }

    private static GraphicsPath RoundedRectPath(Rectangle bounds, int radius)
    {
        var path = new GraphicsPath();
        var diameter = Math.Min(radius * 2, Math.Min(bounds.Width, bounds.Height));
        if (diameter <= 0)
        {
            path.AddRectangle(bounds);
            return path;
        }
        var arc = new Rectangle(bounds.Location, new Size(diameter, diameter));
        path.AddArc(arc, 180, 90);
        arc.X = bounds.Right - diameter;
        path.AddArc(arc, 270, 90);
        arc.Y = bounds.Bottom - diameter;
        path.AddArc(arc, 0, 90);
        arc.X = bounds.Left;
        path.AddArc(arc, 90, 90);
        path.CloseFigure();
        return path;
    }

    private void StyleAction(Button button, string title, string tip, bool primary, bool dark = false)
    {
        button.Text = title;
        button.Height = primary ? 46 : 40;
        button.FlatStyle = FlatStyle.Flat;
        button.Cursor = Cursors.Hand;
        button.Font = new Font("Segoe UI Semibold", 9.5f);
        button.Padding = new Padding(8, 0, 8, 0);
        button.FlatAppearance.BorderSize = 0;
        if (primary)
        {
            button.BackColor = Accent;
            button.ForeColor = Color.White;
        }
        else
        {
            button.BackColor = dark ? Color.FromArgb(40, 52, 54) : Color.FromArgb(236, 242, 241);
            button.ForeColor = dark ? Color.FromArgb(232, 241, 239) : Color.FromArgb(24, 42, 44);
        }
        _tips.SetToolTip(button, tip);
    }

    private void StyleGhost(Button button, string title, bool dark = false)
    {
        button.Text = title;
        button.FlatStyle = FlatStyle.Flat;
        button.Cursor = Cursors.Hand;
        button.Height = 32;
        button.AutoSize = true;
        button.BackColor = Color.FromArgb(16, 28, 30);
        button.ForeColor = dark ? Color.FromArgb(186, 210, 206) : Color.FromArgb(210, 230, 226);
        button.FlatAppearance.BorderSize = 0;
        button.Font = new Font("Segoe UI Semibold", 9f);
    }

    private static NumericUpDown NumberField(decimal min, decimal max, decimal value) => new()
    {
        Minimum = min,
        Maximum = max,
        Value = value,
        ThousandsSeparator = false,
        BorderStyle = BorderStyle.FixedSingle
    };

    private static bool SystemPrefersDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is 0;
        }
        catch
        {
            return false;
        }
    }

    private static Color Accent => Color.FromArgb(14, 122, 122);

    private const string InterpretationText =
        "TEST PATH — tries UDP, TCP and TLS without a password.\n" +
        "A 401/407 is success: the PBX is reachable and return traffic works.\n\n" +
        "TEST SIP REGISTRATION — one authenticated REGISTER.\n" +
        "Tick Keep Registered On The PBX to leave it visible in Yeastar, then Unregister Now.\n" +
        "200 OK means credentials work from this computer.\n\n" +
        "CHECK PBX STATUS — Yeastar API: extension online, assigned phone, blocked IPs.\n" +
        "This is not a SIP REGISTER. It needs Client ID and Secret under Advanced.\n\n" +
        "DNS fails — wrong hostname or DNS policy.\n" +
        "TCP/TLS connect fails — firewall, ISP, wrong port, or service down.\n" +
        "TLS handshake fails — certificate, clock, or TLS inspection.\n" +
        "Via sent-by rewritten — SIP ALG. received=/rport= alone is normal NAT.\n" +
        "Clock vs certificate — fix NTP (no private 172.19.x.x) before blaming TLS.";
}
