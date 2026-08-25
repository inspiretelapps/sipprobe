using System.Diagnostics;
using System.ComponentModel;
using System.Drawing.Drawing2D;
using InspireTel.SipProbe.Core;

namespace InspireTel.SipProbe.App;

public sealed class MainForm : Form
{
    private readonly TextBox _server = new() { PlaceholderText = "pbx.example.com" };
    private readonly NumericUpDown _port = NumberField(1, 65535, 5061);
    private readonly ComboBox _transport = new() { DropDownStyle = ComboBoxStyle.DropDownList };
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
        ForeColor = Color.FromArgb(170, 60, 45)
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
        BackColor = Color.FromArgb(20, 25, 31),
        ForeColor = Color.FromArgb(226, 232, 240),
        Font = new Font("Cascadia Mono", 9.25f),
        DetectUrls = false,
        WordWrap = false
    };

    private readonly Button _runRegister = PrimaryButton("Run authenticated REGISTER");
    private readonly Button _runMatrix = SecondaryButton("Run transport matrix (no auth)");
    private readonly Button _checkPbx = SecondaryButton("Check PBX status");
    private readonly Button _loadCfg = SecondaryButton("Load Yealink .cfg");
    private readonly Button _stop = SecondaryButton("Stop");
    private readonly Button _clear = SecondaryButton("Clear log");
    private readonly Button _export = SecondaryButton("Export log");
    private readonly Label _status = new()
    {
        Text = "Ready",
        AutoSize = false,
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleLeft,
        ForeColor = Color.FromArgb(71, 85, 105),
        Padding = new Padding(10, 0, 0, 0)
    };

    private readonly List<DiagnosticLogEntry> _allEntries = new();
    private CancellationTokenSource? _activeRun;

    public MainForm()
    {
        Text = "InspireTel SIP Probe";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1050, 720);
        Size = new Size(1260, 820);
        BackColor = Color.FromArgb(241, 245, 249);
        Font = new Font("Segoe UI", 9.5f);

        _transport.Items.AddRange(Enum.GetNames<SipTransport>());
        _transport.SelectedItem = SipTransport.Tls.ToString();
        _transport.SelectedIndexChanged += (_, _) =>
        {
            _port.Value = MatrixPortFor(SelectedTransport());
            _forceTls12.Enabled = SelectedTransport() == SipTransport.Tls;
            _ignoreCertificateErrors.Enabled = SelectedTransport() == SipTransport.Tls;
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
        _loadCfg.Click += (_, _) => LoadYealinkConfig();
        _stop.Click += (_, _) => _activeRun?.Cancel();
        _clear.Click += (_, _) => ClearLog();
        _export.Click += (_, _) => ExportLog();
        _stop.Enabled = false;

        Controls.Add(BuildRoot());
        AppendWelcome();
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
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 96));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        root.Controls.Add(BuildHeader(), 0, 0);
        root.Controls.Add(BuildBody(), 0, 1);
        root.Controls.Add(BuildStatusBar(), 0, 2);
        return root;
    }

    private Control BuildHeader()
    {
        var header = new GradientPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(30, 18, 30, 12),
            StartColor = Color.FromArgb(8, 86, 91),
            EndColor = Color.FromArgb(13, 116, 122)
        };
        var title = new Label
        {
            Text = "InspireTel SIP Probe",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 21f),
            AutoSize = true,
            Location = new Point(28, 15)
        };
        var subtitle = new Label
        {
            Text = "Prove DNS, firewall, TLS and SIP registration independently of the handset",
            ForeColor = Color.FromArgb(204, 251, 241),
            Font = new Font("Segoe UI", 10.5f),
            AutoSize = true,
            Location = new Point(31, 57)
        };
        var version = new Label
        {
            Text = "v1.2  •  Passwords and digest values are never logged",
            ForeColor = Color.FromArgb(153, 246, 228),
            TextAlign = ContentAlignment.MiddleRight,
            Dock = DockStyle.Right,
            Width = 350,
            Padding = new Padding(0, 0, 0, 4)
        };
        header.Controls.Add(title);
        header.Controls.Add(subtitle);
        header.Controls.Add(version);
        return header;
    }

    private Control BuildBody()
    {
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            FixedPanel = FixedPanel.Panel1,
            SplitterDistance = 395,
            SplitterWidth = 6,
            BackColor = Color.FromArgb(203, 213, 225),
            Padding = new Padding(18)
        };
        split.Panel1.BackColor = Color.White;
        split.Panel2.BackColor = Color.FromArgb(20, 25, 31);
        split.Panel1.Padding = new Padding(22, 18, 22, 18);
        split.Panel2.Padding = new Padding(0);
        split.Panel1.Controls.Add(BuildConfigurationPanel());
        split.Panel2.Controls.Add(BuildLogPanel());
        return split;
    }

    private Control BuildConfigurationPanel()
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4
        };
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        panel.Controls.Add(new Label
        {
            Text = "Probe configuration",
            Font = new Font("Segoe UI Semibold", 14f),
            ForeColor = Color.FromArgb(15, 23, 42),
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 5)
        }, 0, 0);
        panel.Controls.Add(new Label
        {
            Text = "Use the same SIP values as the endpoint. The matrix uses the UDP/TCP/TLS ports on the Matrix tab.",
            ForeColor = Color.FromArgb(71, 85, 105),
            AutoSize = true,
            MaximumSize = new Size(340, 0),
            Margin = new Padding(0, 0, 0, 14)
        }, 0, 1);
        panel.Controls.Add(BuildTabs(), 0, 2);
        panel.Controls.Add(BuildActionPanel(), 0, 3);
        return panel;
    }

    private Control BuildTabs()
    {
        var tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Padding = new Point(8, 8)
        };
        tabs.TabPages.Add(WrapTab("SIP", BuildFields()));
        tabs.TabPages.Add(WrapTab("Matrix", BuildMatrixFields()));
        tabs.TabPages.Add(WrapTab("PBX API", BuildApiFields()));
        return tabs;
    }

    private static TabPage WrapTab(string title, Control content)
    {
        var page = new TabPage(title) { Padding = new Padding(8, 10, 8, 8), UseVisualStyleBackColor = true };
        content.Dock = DockStyle.Fill;
        page.Controls.Add(content);
        return page;
    }

    private Control BuildFields()
    {
        var fields = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 2,
            RowCount = 11,
            Margin = new Padding(0)
        };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        AddField(fields, 0, "PBX hostname", _server);
        AddField(fields, 1, "Transport", _transport);
        AddField(fields, 2, "Destination port", _port);
        AddField(fields, 3, "SIP user", _sipUser);
        AddField(fields, 4, "Auth name", _authName);
        AddField(fields, 5, "Password", BuildPasswordField());
        AddField(fields, 6, "Local port", _localPort);
        AddField(fields, 7, "Register expiry", _expiry);
        AddField(fields, 8, "Timeout", _timeout);

        var tlsOptions = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Margin = new Padding(0, 3, 0, 3)
        };
        tlsOptions.Controls.Add(_forceTls12);
        tlsOptions.Controls.Add(_ignoreCertificateErrors);
        AddField(fields, 9, "TLS options", tlsOptions);

        var hints = new Label
        {
            Text = "Local port 0 = automatic. Destination port is for authenticated REGISTER. Matrix ports are on the Matrix tab.",
            ForeColor = Color.FromArgb(100, 116, 139),
            AutoSize = true,
            MaximumSize = new Size(205, 0),
            Margin = new Padding(0, 7, 0, 0)
        };
        fields.Controls.Add(hints, 1, 10);
        return fields;
    }

    private Control BuildMatrixFields()
    {
        var fields = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 2,
            RowCount = 4,
            Margin = new Padding(0)
        };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        AddField(fields, 0, "UDP port", _udpPort);
        AddField(fields, 1, "TCP port", _tcpPort);
        AddField(fields, 2, "TLS port", _tlsPort);
        var hints = new Label
        {
            Text = "The no-auth matrix tests these three listeners. If Destination port on the SIP tab is different, that custom target is added as a fourth probe.",
            ForeColor = Color.FromArgb(100, 116, 139),
            AutoSize = true,
            MaximumSize = new Size(205, 0),
            Margin = new Padding(0, 7, 0, 0)
        };
        fields.Controls.Add(hints, 1, 3);
        return fields;
    }

    private Control BuildApiFields()
    {
        var fields = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 2,
            RowCount = 4,
            Margin = new Padding(0)
        };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        AddField(fields, 0, "API URL", _apiUrl);
        AddField(fields, 1, "Client ID", _apiClientId);
        AddField(fields, 2, "Client secret", _apiSecret);
        var hints = new Label
        {
            Text = "Settings → Integrations → API. Checks extension online status, assigned phone, transport, and blocked IPs when the OpenAPI exposes them. Leave URL blank to use https:// plus the SIP hostname.",
            ForeColor = Color.FromArgb(100, 116, 139),
            AutoSize = true,
            MaximumSize = new Size(205, 0),
            Margin = new Padding(0, 7, 0, 0)
        };
        fields.Controls.Add(hints, 1, 3);
        return fields;
    }

    private Control BuildPasswordField()
    {
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Margin = new Padding(0) };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 36));
        var show = new Button
        {
            Text = "👁",
            FlatStyle = FlatStyle.Flat,
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 0, 0, 0),
            TabStop = false,
            BackColor = Color.FromArgb(241, 245, 249)
        };
        show.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
        show.MouseDown += (_, _) => _password.UseSystemPasswordChar = false;
        show.MouseUp += (_, _) => _password.UseSystemPasswordChar = true;
        show.MouseLeave += (_, _) => _password.UseSystemPasswordChar = true;
        panel.Controls.Add(_password, 0, 0);
        panel.Controls.Add(show, 1, 0);
        return panel;
    }

    private Control BuildActionPanel()
    {
        var actions = new TableLayoutPanel
        {
            Dock = DockStyle.Bottom,
            AutoSize = true,
            ColumnCount = 1,
            Margin = new Padding(0, 12, 0, 0)
        };
        _runRegister.Dock = DockStyle.Top;
        _runMatrix.Dock = DockStyle.Top;
        _checkPbx.Dock = DockStyle.Top;
        _loadCfg.Dock = DockStyle.Top;
        _stop.Dock = DockStyle.Top;
        _runRegister.Margin = new Padding(0, 0, 0, 7);
        _runMatrix.Margin = new Padding(0, 0, 0, 7);
        _checkPbx.Margin = new Padding(0, 0, 0, 7);
        _loadCfg.Margin = new Padding(0, 0, 0, 7);
        _stop.Margin = new Padding(0);
        actions.Controls.Add(_loadCfg);
        actions.Controls.Add(_runRegister);
        actions.Controls.Add(_runMatrix);
        actions.Controls.Add(_checkPbx);
        actions.Controls.Add(_stop);
        return actions;
    }

    private Control BuildLogPanel()
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Color.FromArgb(20, 25, 31)
        };
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Padding = new Padding(12, 8, 12, 6),
            BackColor = Color.FromArgb(30, 41, 50)
        };
        _clear.AutoSize = true;
        _export.AutoSize = true;
        _clear.Margin = new Padding(6, 0, 0, 0);
        toolbar.Controls.Add(_export);
        toolbar.Controls.Add(_clear);
        toolbar.Controls.Add(new Label
        {
            Text = "Diagnostic log",
            ForeColor = Color.FromArgb(226, 232, 240),
            Font = new Font("Segoe UI Semibold", 11f),
            AutoSize = true,
            Margin = new Padding(0, 7, 18, 0)
        });
        panel.Controls.Add(toolbar, 0, 0);
        panel.Controls.Add(_log, 0, 1);
        return panel;
    }

    private Control BuildStatusBar()
    {
        var bar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            BackColor = Color.White,
            Padding = new Padding(18, 0, 18, 0)
        };
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var help = new LinkLabel
        {
            Text = "Interpretation guide",
            AutoSize = true,
            LinkColor = Color.FromArgb(13, 116, 122),
            Margin = new Padding(10, 11, 0, 0)
        };
        help.LinkClicked += (_, _) => ShowInterpretationGuide();
        bar.Controls.Add(_status, 0, 0);
        bar.Controls.Add(help, 1, 0);
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
            MessageBox.Show(this, ex.Message, "Check the probe configuration", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
            MessageBox.Show(this, ex.Message, "Check the probe configuration", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
            SetRunning(false, _status.Text);
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
            MessageBox.Show(this, "Enter the Yeastar OpenAPI Client ID and Client Secret on the PBX API tab.",
                "Check the probe configuration", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var apiUrl = string.IsNullOrWhiteSpace(_apiUrl.Text)
            ? "https://" + _server.Text.Trim()
            : _apiUrl.Text.Trim();

        AppendSeparator("YEASTAR PBX API STATUS");
        SetRunning(true, "Checking PBX API...");
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
        _stop.Enabled = running;
        _transport.Enabled = !running;
        _status.Text = status;
        UseWaitCursor = running;
    }

    private void AppendWelcome()
    {
        AppendLocal(DiagnosticLevel.Info, "Ready. Start with the no-auth matrix to compare UDP, TCP and TLS on the configured ports.");
        AppendLocal(DiagnosticLevel.Detail, "A 401/407 challenge is a positive reachability result; Via rewrite is reported as SIP ALG. Use Check PBX status when OpenAPI credentials are available.");
    }

    private void AppendSeparator(string title)
    {
        var line = Environment.NewLine + new string('═', Math.Min(82, title.Length + 8)) + Environment.NewLine +
                   $"   {title}" + Environment.NewLine + new string('═', Math.Min(82, title.Length + 8)) + Environment.NewLine;
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
            "InspireTel SIP Probe v1.2",
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
            var settings = YealinkConfigParser.Parse(File.ReadLines(dialog.FileName));
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
                $"Loaded Yealink config '{Path.GetFileName(dialog.FileName)}': {string.Join(", ", loaded)}.");
            AppendLocal(DiagnosticLevel.Detail,
                "The file remains local. Its password is held only in the password field and is never logged or exported.");
            foreach (var finding in ClockCertificateCheck.AnalyzeNtpServers(_ntpServers))
                AppendLocal(finding.Level, finding.Message);
            _status.Text = $"Loaded {Path.GetFileName(dialog.FileName)}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            MessageBox.Show(this, ex.Message, "Could not load Yealink configuration", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ShowInterpretationGuide()
    {
        MessageBox.Show(
            this,
            "RESULT INTERPRETATION\n\n" +
            "DNS fails — wrong hostname or DNS policy.\n\n" +
            "TCP/TLS connection fails — firewall, router, ISP policy, wrong port, or service not listening.\n\n" +
            "TLS handshake fails — certificate trust/hostname/time/TLS-version issue, or TLS inspection.\n\n" +
            "401/407 challenge — positive result: the PBX is reachable and return traffic works.\n\n" +
            "200 OK — network, PBX and credentials work from this laptop; focus on the handset.\n\n" +
            "Repeated 401 or 403 — credentials, extension transport policy, registration security or blocked IP.\n\n" +
            "Via sent-by rewritten — SIP ALG on the customer router. received=/rport= alone is normal NAT.\n\n" +
            "Clock behind/ahead of certificate dates — fix handset NTP (avoid private 172.19.x.x) before blaming TLS.\n\n" +
            "No SIP response after connection — SIP-aware firewall/ALG, proxy interference, or PBX service problem.",
            "SIP Probe interpretation guide",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private static void AddField(TableLayoutPanel table, int row, string label, Control control)
    {
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var caption = new Label
        {
            Text = label,
            AutoSize = true,
            ForeColor = Color.FromArgb(51, 65, 85),
            Margin = new Padding(0, 9, 8, 0)
        };
        control.Dock = DockStyle.Top;
        control.Margin = new Padding(0, 3, 0, 3);
        control.MinimumSize = new Size(0, 28);
        table.Controls.Add(caption, 0, row);
        table.Controls.Add(control, 1, row);
    }

    private static NumericUpDown NumberField(decimal min, decimal max, decimal value) => new()
    {
        Minimum = min,
        Maximum = max,
        Value = value,
        ThousandsSeparator = false
    };

    private static Button PrimaryButton(string text)
    {
        var button = new Button
        {
            Text = text,
            Height = 38,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(13, 116, 122),
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 9.5f),
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderSize = 0;
        return button;
    }

    private static Button SecondaryButton(string text)
    {
        var button = new Button
        {
            Text = text,
            Height = 34,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(241, 245, 249),
            ForeColor = Color.FromArgb(30, 41, 59),
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
        return button;
    }

    private sealed class GradientPanel : Panel
    {
        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        public Color StartColor { get; init; }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        public Color EndColor { get; init; }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            using var brush = new LinearGradientBrush(ClientRectangle, StartColor, EndColor, 0f);
            e.Graphics.FillRectangle(brush, ClientRectangle);
        }
    }
}
