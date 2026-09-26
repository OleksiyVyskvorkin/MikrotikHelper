using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace MikrotikHelper;

public partial class RouterPanel : UserControl
{
    private static readonly SemaphoreSlim SettingsFileLock = new(1, 1);
    public sealed record SavedRouterSettings(string Router, string LocalIp, string DhcpRange,
        string WireGuardIp = "", string PublicKey = "", int ListenPort = 0, string WanEndpoint = "");
    private RouterOsApiClient? _routerClient;
    private string? _connectedHost;
    private readonly DispatcherTimer _connectionTimer;
    private bool _healthCheckRunning;
    private bool _autoReconnect;
    private string _savedHost = "";
    private string _savedLogin = "";
    private string _savedPassword = "";
    private string _selectedPrivateKey = "";
    private IReadOnlyList<RouterOsApiClient.IpAddressRecord> _ipAddresses = [];
    private RouterOsApiClient.IpAddressRecord? _localAddress;
    private RouterOsApiClient.DhcpServerRecord? _dhcpServer;
    private RouterOsApiClient.IpPoolRecord? _dhcpPool;
    private readonly List<string> _wanAddresses = [];
    private string _externalValidationError = "";
    private int _consecutiveHealthFailures;
    private bool _editorCollapsed;
    private bool _quickSetCollapsed;
    public bool IsRouterConnected => _routerClient != null;
    public string ConnectionHost => _connectedHost ?? "";
    public string LocalNetworkAddress => _localAddress?.Address ?? "";
    public bool HasWireGuardInterface { get; private set; }
    public event EventHandler? StateChanged;
    public event EventHandler? QuickSetChanged;
    public string ProposedLocalAddress => LocalIpBox?.Text.Trim() ?? "";
    public sealed record WireGuardSummary(string Name, string PublicKey, int ListenPort, string Address);

    public async Task<WireGuardSummary> GetPrimaryWireGuardAsync(CancellationToken cancellationToken)
    {
        if (_routerClient == null) throw new InvalidOperationException("MikroTik не підключено.");
        var item = (await _routerClient.GetWireGuardInterfacesAsync(cancellationToken)).FirstOrDefault()
            ?? throw new InvalidOperationException("WireGuard-інтерфейс не знайдено.");
        if (!int.TryParse(item.GetValueOrDefault("listen-port"), out var port)) throw new InvalidOperationException("Некоректний Listen Port WireGuard.");
        var publicKey = item.GetValueOrDefault("public-key") ?? "";
        if (string.IsNullOrWhiteSpace(publicKey)) throw new InvalidOperationException("Public Key WireGuard недоступний.");
        var interfaceName = item.GetValueOrDefault("name") ?? "";
        var address = await _routerClient.GetInterfaceAddressAsync(interfaceName, cancellationToken);
        if (string.IsNullOrWhiteSpace(address)) throw new InvalidOperationException($"На WireGuard-інтерфейсі {interfaceName} не призначено IP-адресу.");
        var summary = new WireGuardSummary(interfaceName, publicKey, port, address);
        await SaveWireGuardAsync(summary);
        return summary;
    }

    public SavedRouterSettings? GetSavedSettings() => LoadSavedSettings().FirstOrDefault(item =>
        item.Router.Equals(GetRouterStorageName(), StringComparison.OrdinalIgnoreCase));

    public async Task SaveWanEndpointAsync(string endpoint)
    {
        await SettingsFileLock.WaitAsync();
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "quickset-settings.json");
            var settings = LoadSavedSettings(); var router = GetRouterStorageName();
            var previous = settings.FirstOrDefault(item => item.Router.Equals(router, StringComparison.OrdinalIgnoreCase));
            settings.RemoveAll(item => item.Router.Equals(router, StringComparison.OrdinalIgnoreCase));
            settings.Add(previous == null ? new SavedRouterSettings(router, "", "", WanEndpoint: endpoint) : previous with { WanEndpoint = endpoint });
            settings.Sort((a, b) => string.Compare(a.Router, b.Router, StringComparison.OrdinalIgnoreCase));
            var temporaryPath = path + ".tmp";
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporaryPath, path, true);
        }
        finally { SettingsFileLock.Release(); }
    }

    public async Task CreatePeerAsync(string name, string interfaceName, string remotePublicKey,
        string? endpointAddress, int? endpointPort, string allowedAddress, int keepaliveSeconds,
        CancellationToken cancellationToken)
    {
        if (_routerClient == null) throw new InvalidOperationException("MikroTik не підключено.");
        await _routerClient.CreateWireGuardPeerAsync(name, interfaceName, remotePublicKey,
            endpointAddress, endpointPort, allowedAddress, keepaliveSeconds, cancellationToken);
    }
    public async Task<IReadOnlyList<RouterOsApiClient.WireGuardPeerRecord>> GetPeersAsync(CancellationToken cancellationToken)
    {
        if (_routerClient == null) throw new InvalidOperationException("MikroTik не підключено.");
        return await _routerClient.GetWireGuardPeersAsync(cancellationToken);
    }
    public async Task RemovePeerAsync(string id, CancellationToken cancellationToken)
    {
        if (_routerClient == null) throw new InvalidOperationException("MikroTik не підключено.");
        await _routerClient.RemoveWireGuardPeerAsync(id, cancellationToken);
    }
    public async Task ConfigureRoutesAsync(string remoteLocalAddress, string wireGuardInterface, CancellationToken cancellationToken)
    {
        if (_routerClient == null) throw new InvalidOperationException("MikroTik не підключено.");
        foreach (var client in await _routerClient.GetDhcpClientsAsync(cancellationToken))
            await _routerClient.SetDhcpClientRouteDistanceAsync(client.Id, 2, cancellationToken);
        await _routerClient.UpsertStaticRouteAsync(ToNetworkCidr(remoteLocalAddress), wireGuardInterface, 1, cancellationToken);
    }

    public async Task ConfigureWireGuardFirewallAsync(int listenPort, string localLan, string remoteLan, bool acceptIncomingUdp,
        CancellationToken cancellationToken)
    {
        if (_routerClient == null) throw new InvalidOperationException("MikroTik не підключено.");
        if (acceptIncomingUdp)
            await _routerClient.EnsureFirewallRuleAsync("input", "MikrotikHelper: allow WireGuard UDP",
                new Dictionary<string, string> { ["protocol"] = "udp", ["dst-port"] = listenPort.ToString() }, cancellationToken);
        await _routerClient.EnsureFirewallRuleAsync("forward", "MikrotikHelper: LAN to remote LAN",
            new Dictionary<string, string> { ["src-address"] = ToNetworkCidr(localLan), ["dst-address"] = ToNetworkCidr(remoteLan) }, cancellationToken);
        await _routerClient.EnsureFirewallRuleAsync("forward", "MikrotikHelper: remote LAN to LAN",
            new Dictionary<string, string> { ["src-address"] = ToNetworkCidr(remoteLan), ["dst-address"] = ToNetworkCidr(localLan) }, cancellationToken);
    }

    private static string ToNetworkCidr(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork
            || !int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 32)
            throw new InvalidOperationException($"Некоректна локальна мережа: {cidr}.");
        var bytes = ip.GetAddressBytes();
        var value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var network = value & mask;
        return $"{(network >> 24) & 255}.{(network >> 16) & 255}.{(network >> 8) & 255}.{network & 255}/{prefix}";
    }
    public static readonly DependencyProperty RouterTitleProperty = DependencyProperty.Register(nameof(RouterTitle), typeof(string), typeof(RouterPanel));
    public static readonly DependencyProperty RouterNumberProperty = DependencyProperty.Register(nameof(RouterNumber), typeof(string), typeof(RouterPanel));
    public static readonly DependencyProperty DefaultInterfaceNameProperty = DependencyProperty.Register(nameof(DefaultInterfaceName), typeof(string), typeof(RouterPanel), new PropertyMetadata("wg1"));
    public string RouterTitle { get => (string)GetValue(RouterTitleProperty); set => SetValue(RouterTitleProperty, value); }
    public string RouterNumber { get => (string)GetValue(RouterNumberProperty); set => SetValue(RouterNumberProperty, value); }
    public string DefaultInterfaceName { get => (string)GetValue(DefaultInterfaceNameProperty); set => SetValue(DefaultInterfaceNameProperty, value); }

    public RouterPanel()
    {
        InitializeComponent();
        _connectionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _connectionTimer.Tick += ConnectionTimer_Tick;
        Loaded += (_, _) => Reset();
        Unloaded += async (_, _) => await DisconnectAsync("", false, false);
    }
    private void Name_Changed(object sender, TextChangedEventArgs e) { }
    private void WireGuardIp_Changed(object sender, TextChangedEventArgs e) => ValidateWireGuardIp();

    private void ValidateWireGuardIp()
    {
        if (CreateInterfaceButton == null || WireGuardIpError == null || WireGuardIpBox == null) return;
        var value = WireGuardIpBox.Text.Trim();
        string error = "";
        if (!TryGetNetwork(value, out _)) error = "Введіть коректний WireGuard IP Address з префіксом.";
        else
        {
            var other = GetOtherRouterSavedSettings()?.WireGuardIp;
            if (!string.IsNullOrWhiteSpace(other) && SameHostAddress(value, other))
                error = "WireGuard IP не може збігатися з адресою іншого MikroTik.";
        }
        WireGuardIpError.Text = error;
        CreateInterfaceButton.IsEnabled = string.IsNullOrEmpty(error) && _routerClient != null;
    }

    private static bool SameHostAddress(string first, string second)
        => IPAddress.TryParse(first.Split('/')[0], out var firstIp) && IPAddress.TryParse(second.Split('/')[0], out var secondIp)
            && firstIp.Equals(secondIp);
    private async Task LoadQuickSetAsync()
    {
        if (_routerClient == null) return;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            _ipAddresses = await _routerClient.GetStaticIpAddressesAsync(timeout.Token);
            _localAddress = _ipAddresses.FirstOrDefault(item => item.Interface.Equals("bridge", StringComparison.OrdinalIgnoreCase))
                ?? _ipAddresses.FirstOrDefault();
            if (_localAddress == null)
            {
                LocalIpBox.Text = ""; DhcpServerCheck.IsChecked = false; DhcpServerCheck.IsEnabled = false;
                QuickSetStatus.Text = "Статичну локальну IP-адресу не знайдено."; return;
            }
            LocalIpBox.Text = _localAddress.Address;
            var servers = await _routerClient.GetDhcpServersAsync(timeout.Token);
            _dhcpServer = servers.FirstOrDefault(item => item.Interface.Equals(_localAddress.Interface, StringComparison.OrdinalIgnoreCase));
            DhcpServerCheck.IsChecked = _dhcpServer?.Enabled == true;
            DhcpServerCheck.IsEnabled = _dhcpServer != null;
            _dhcpPool = _dhcpServer == null ? null : await _routerClient.GetIpPoolAsync(_dhcpServer.AddressPool, timeout.Token);
            DhcpRangeBox.Text = _dhcpPool?.Ranges ?? "";
            DhcpRangeBox.IsEnabled = _dhcpPool != null;
            QuickSetStatus.Text = _dhcpServer == null ? $"DHCP-сервер для {_localAddress.Interface} не знайдено."
                : _dhcpPool == null ? "DHCP Server Range недоступний: пул адрес не знайдено." : "";
            _wanAddresses.Clear();
            foreach (var wanInterface in await _routerClient.GetDhcpClientInterfacesAsync(timeout.Token))
            {
                var wanAddress = await _routerClient.GetInterfaceAddressAsync(wanInterface, timeout.Token);
                if (!string.IsNullOrWhiteSpace(wanAddress)) _wanAddresses.Add(wanAddress);
            }
            ValidateQuickSet();
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex) { QuickSetStatus.Text = $"Не вдалося завантажити адреси: {ex.Message}"; }
    }
    private void LocalIp_Changed(object sender, TextChangedEventArgs e)
    {
        ValidateQuickSet();
        QuickSetChanged?.Invoke(this, EventArgs.Empty);
    }

    public void SetOtherRouterLocalAddress(string address)
    {
        _externalValidationError = "";
        if (TryGetNetwork(ProposedLocalAddress, out var own) && TryGetNetwork(address, out var other) && NetworksOverlap(own, other))
            _externalValidationError = "Локальні підмережі MikroTik 1 і MikroTik 2 не повинні перетинатися.";
        ValidateQuickSet();
    }

    private void ValidateQuickSet()
    {
        if (ApplyQuickSetButton == null || QuickSetStatus == null) return;
        string error = "";
        if (!TryGetNetwork(ProposedLocalAddress, out var local)) error = "Введіть коректну Local IP адресу з префіксом.";
        else if (TryGetNetwork("192.168.88.0/24", out var factoryNetwork) && NetworksOverlap(local, factoryNetwork))
            error = "Підмережа 192.168.88.0/24 використовується для початкового підключення та не може бути новою локальною підмережею.";
        else if (_wanAddresses.Any(wan => TryGetNetwork(wan, out var provider) && NetworksOverlap(local, provider)))
            error = "Локальна підмережа не повинна збігатися або перетинатися з підмережею інтернет-провайдера (WAN).";
        else if (!string.IsNullOrEmpty(_externalValidationError)) error = _externalValidationError;
        ApplyQuickSetButton.IsEnabled = string.IsNullOrEmpty(error) && _routerClient != null && _localAddress != null;
        if (!string.IsNullOrEmpty(error)) QuickSetStatus.Text = error;
        else if (QuickSetStatus.Text.Contains("підмереж", StringComparison.OrdinalIgnoreCase)
            || QuickSetStatus.Text.Contains("Local IP", StringComparison.OrdinalIgnoreCase)) QuickSetStatus.Text = "";
    }

    private static bool TryGetNetwork(string cidr, out (uint Start, uint End) network)
    {
        network = default; var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork
            || !int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 32) return false;
        var value = ((uint)ip.GetAddressBytes()[0] << 24) | ((uint)ip.GetAddressBytes()[1] << 16)
            | ((uint)ip.GetAddressBytes()[2] << 8) | ip.GetAddressBytes()[3];
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        network = (value & mask, (value & mask) | ~mask); return true;
    }
    private static bool NetworksOverlap((uint Start, uint End) first, (uint Start, uint End) second)
        => first.Start <= second.End && second.Start <= first.End;
    private void CollapseQuickSet_Click(object sender, RoutedEventArgs e)
    {
        _quickSetCollapsed = !_quickSetCollapsed;
        QuickSetContentRow.Height = _quickSetCollapsed ? new GridLength(0) : GridLength.Auto;
        QuickSetContent.Visibility = _quickSetCollapsed ? Visibility.Collapsed : Visibility.Visible;
        CollapseQuickSetButton.Content = _quickSetCollapsed ? "+" : "−";
        CollapseQuickSetButton.ToolTip = _quickSetCollapsed ? "Розгорнути" : "Згорнути";
    }
    private async void ApplyLocalIp_Click(object sender, RoutedEventArgs e)
    {
        if (_routerClient == null || _localAddress == null) return;
        var selected = _localAddress;
        var value = LocalIpBox.Text.Trim(); var parts = value.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address) || address.AddressFamily != AddressFamily.InterNetwork
            || !int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 32)
        { QuickSetStatus.Text = "Введіть коректну IPv4-адресу з префіксом, наприклад 192.168.89.1/24."; return; }
        var range = DhcpRangeBox.Text.Trim();
        if (_dhcpPool != null && !IsValidDhcpRange(range))
        { QuickSetStatus.Text = "Введіть DHCP Range у форматі 192.168.89.10-192.168.89.254."; return; }
        if (_dhcpPool != null && (!TryGetNetwork(value, out var targetNetwork) || !DhcpRangeBelongsToNetwork(range, targetNetwork)))
        { QuickSetStatus.Text = "DHCP Range має належати новій локальній підмережі."; return; }
        var newPassword = NewPasswordBox.Text;
        if (!string.IsNullOrEmpty(newPassword) && newPassword != ConfirmPasswordBox.Text)
        { QuickSetStatus.Text = "Новий пароль і підтвердження не збігаються."; return; }
        var oldIp = selected.Address.Split('/')[0]; var newIp = parts[0];
        var addressChanged = !selected.Address.Equals(value, StringComparison.OrdinalIgnoreCase);
        if (MessageBox.Show($"Змінити IP інтерфейсу {selected.Interface}:\n{selected.Address} → {value}?\n\nЗ'єднання буде тимчасово розірвано, після чого програма підключиться до {newIp}.",
            "Зміна локального IP", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        try
        {
            QuickSetStatus.Text = "Застосування нової IP-адреси…";
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            if (_dhcpPool != null) await _routerClient.SetIpPoolRangesAsync(_dhcpPool.Id, range, timeout.Token);
            var dhcpNetwork = (await _routerClient.GetDhcpNetworksAsync(timeout.Token))
                .FirstOrDefault(item => item.Gateway.Equals(oldIp, StringComparison.OrdinalIgnoreCase)
                    || (TryGetNetwork(item.Address, out var network) && TryGetNetwork(selected.Address, out var oldNetwork)
                        && NetworksOverlap(network, oldNetwork)));
            var networkAddress = NetworkCidr(value);
            if (dhcpNetwork != null && networkAddress != null)
                await _routerClient.SetDhcpNetworkAsync(dhcpNetwork.Id, networkAddress, newIp, newIp, timeout.Token);
            if (_dhcpServer != null)
                await _routerClient.SetDhcpServerEnabledAsync(_dhcpServer.Id, DhcpServerCheck.IsChecked == true, timeout.Token);

            // Verify DHCP changes while the current API session is still valid.
            var verifiedServers = await _routerClient.GetDhcpServersAsync(timeout.Token);
            var verifiedServer = _dhcpServer == null ? null : verifiedServers.FirstOrDefault(item => item.Id == _dhcpServer.Id);
            if (_dhcpServer != null && verifiedServer?.Enabled != (DhcpServerCheck.IsChecked == true))
                throw new InvalidOperationException("RouterOS не підтвердив зміну стану DHCP Server.");
            if (_dhcpPool != null)
            {
                var verifiedPool = await _routerClient.GetIpPoolAsync(_dhcpPool.Name, timeout.Token);
                if (verifiedPool == null || !verifiedPool.Ranges.Equals(range, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("RouterOS не підтвердив зміну DHCP Range.");
            }
            if (dhcpNetwork != null)
            {
                var verifiedNetwork = (await _routerClient.GetDhcpNetworksAsync(timeout.Token)).FirstOrDefault(item => item.Id == dhcpNetwork.Id);
                if (verifiedNetwork == null || verifiedNetwork.Address != networkAddress || verifiedNetwork.Gateway != newIp
                    || !verifiedNetwork.DnsServer.Split(',', StringSplitOptions.TrimEntries).Contains(newIp, StringComparer.OrdinalIgnoreCase))
                    throw new InvalidOperationException("RouterOS не підтвердив зміну DHCP Network.");
            }

            if (!string.IsNullOrEmpty(newPassword))
            {
                await _routerClient.SetUserPasswordAsync(LoginBox.Text.Trim(), newPassword, timeout.Token);
                if (!await VerifyCredentialsAsync(oldIp, LoginBox.Text.Trim(), newPassword))
                    throw new InvalidOperationException("Новий пароль не пройшов перевірку входу.");
                PasswordInput.Password = newPassword;
                _savedPassword = newPassword;
                NewPasswordBox.Text = ConfirmPasswordBox.Text = "";
            }
        }
        catch (Exception ex) { QuickSetStatus.Text = $"Не вдалося застосувати Quick Set: {ex.Message}"; return; }

        if (addressChanged)
        {
            try
            {
                using var addressTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                await _routerClient.SetIpAddressAsync(selected.Id, value, addressTimeout.Token);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
            catch (Exception ex) { QuickSetStatus.Text = $"Не вдалося змінити IP: {ex.Message}"; return; }

            try
            {
                await SaveQuickSetAsync(value, range);
            }
            catch (Exception ex)
            {
                QuickSetStatus.Text = $"IP змінено, але не вдалося зберегти дані: {ex.Message}";
            }
        }
        if (!addressChanged) { QuickSetStatus.Text = "Налаштування DHCP Server застосовано."; await LoadQuickSetAsync(); return; }
        if (IpBox.Text.Trim() == oldIp || _connectedHost == oldIp) { IpBox.Text = newIp; _savedHost = newIp; }
        await DisconnectAsync($"IP змінено на {newIp}. Виконується повторне підключення…", true, true);
    }

    private async Task SaveQuickSetAsync(string localIp, string dhcpRange)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "quickset-settings.json");
        await SettingsFileLock.WaitAsync();
        try
        {
            List<SavedRouterSettings> settings = [];
            if (File.Exists(path))
            {
                var existingJson = await File.ReadAllTextAsync(path);
                if (!string.IsNullOrWhiteSpace(existingJson))
                    settings = JsonSerializer.Deserialize<List<SavedRouterSettings>>(existingJson) ?? [];
            }

            var router = GetRouterStorageName();
            var previous = settings.FirstOrDefault(item => item.Router.Equals(router, StringComparison.OrdinalIgnoreCase));
            settings.RemoveAll(item => item.Router.Equals(router, StringComparison.OrdinalIgnoreCase));
            settings.Add(new SavedRouterSettings(router, localIp, dhcpRange, previous?.WireGuardIp ?? "",
                previous?.PublicKey ?? "", previous?.ListenPort ?? 0, previous?.WanEndpoint ?? ""));
            settings.Sort((left, right) => string.Compare(left.Router, right.Router, StringComparison.OrdinalIgnoreCase));

            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            var temporaryPath = path + ".tmp";
            await File.WriteAllTextAsync(temporaryPath, json);
            File.Move(temporaryPath, path, true);
        }
        finally
        {
            SettingsFileLock.Release();
        }
    }

    private async Task SaveWireGuardAsync(WireGuardSummary summary)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "quickset-settings.json");
        await SettingsFileLock.WaitAsync();
        try
        {
            var settings = LoadSavedSettings();
            var router = GetRouterStorageName();
            var previous = settings.FirstOrDefault(item => item.Router.Equals(router, StringComparison.OrdinalIgnoreCase));
            settings.RemoveAll(item => item.Router.Equals(router, StringComparison.OrdinalIgnoreCase));
            settings.Add(new SavedRouterSettings(router, previous?.LocalIp ?? LocalNetworkAddress,
                previous?.DhcpRange ?? DhcpRangeBox.Text.Trim(), summary.Address, summary.PublicKey, summary.ListenPort,
                previous?.WanEndpoint ?? ""));
            settings.Sort((left, right) => string.Compare(left.Router, right.Router, StringComparison.OrdinalIgnoreCase));
            var temporaryPath = path + ".tmp";
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporaryPath, path, true);
        }
        finally { SettingsFileLock.Release(); }
    }

    private static List<SavedRouterSettings> LoadSavedSettings()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "quickset-settings.json");
            if (!File.Exists(path)) return [];
            return JsonSerializer.Deserialize<List<SavedRouterSettings>>(File.ReadAllText(path)) ?? [];
        }
        catch { return []; }
    }

    private string GetRouterStorageName()
        => string.IsNullOrWhiteSpace(RouterNumber) ? RouterTitle : $"MikroTik {RouterNumber.TrimStart('0')}";

    private SavedRouterSettings? GetOtherRouterSavedSettings()
    {
        var otherName = RouterNumber.TrimStart('0') == "1" ? "MikroTik 2" : "MikroTik 1";
        return LoadSavedSettings().FirstOrDefault(item => item.Router.Equals(otherName, StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<bool> VerifyCredentialsAsync(string host, string login, string password)
    {
        var client = new RouterOsApiClient();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(host, login, password, timeout.Token);
            await client.GetSystemResourceAsync(timeout.Token);
            return true;
        }
        catch { return false; }
        finally { await client.DisposeAsync(); }
    }
    private static bool IsValidDhcpRange(string value)
    {
        var parts = value.Split('-', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var start) || !IPAddress.TryParse(parts[1], out var end)
            || start.AddressFamily != AddressFamily.InterNetwork || end.AddressFamily != AddressFamily.InterNetwork) return false;
        var startBytes = start.GetAddressBytes(); var endBytes = end.GetAddressBytes();
        for (var i = 0; i < 4; i++) { if (startBytes[i] < endBytes[i]) return true; if (startBytes[i] > endBytes[i]) return false; }
        return true;
    }
    private static bool DhcpRangeBelongsToNetwork(string range, (uint Start, uint End) network)
    {
        var parts = range.Split('-', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var start) || !IPAddress.TryParse(parts[1], out var end)) return false;
        static uint ToUInt(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        }
        var first = ToUInt(start); var last = ToUInt(end);
        return first >= network.Start && last <= network.End;
    }
    private static string? NetworkCidr(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !TryGetNetwork(cidr, out var network)) return null;
        var bytes = new[] { (byte)(network.Start >> 24), (byte)(network.Start >> 16), (byte)(network.Start >> 8), (byte)network.Start };
        return $"{new IPAddress(bytes)}/{parts[1]}";
    }
    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (_routerClient != null)
        {
            ConnectButton.IsEnabled = false;
            await DisconnectAsync("З'єднання розірвано користувачем.", true, false);
            return;
        }
        var host = IpBox.Text.Trim(); var login = LoginBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(login)) { ShowConnectionError("Вкажіть IP-адресу та логін."); return; }
        if (host.Contains('/') || host.Contains('@') || host.Contains('?') || host.Contains('#')) { ShowConnectionError("Введіть IP-адресу або ім'я без протоколу та шляху."); return; }
        if (!IPAddress.TryParse(host, out var parsedAddress) || parsedAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            ShowConnectionError("Invalid IP address.");
            return;
        }

        ConnectButton.IsEnabled = false; ConnectButton.Content = "Connecting…"; ConnectionMessage.Text = $"Підключення до {host}…";
        var client = new RouterOsApiClient();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            await client.ConnectAsync(host, login, PasswordInput.Password, timeout.Token);
            var resource = await client.GetSystemResourceAsync(timeout.Token);
            _routerClient = client; _connectedHost = host;
            _savedHost = host; _savedLogin = login; _savedPassword = PasswordInput.Password; _autoReconnect = true;
            ConnectButton.Content = "Disconnect"; ConnectButton.Background = (System.Windows.Media.Brush)FindResource("AccentBrush");
            SetEditorStatus("");
            ConnectionMessage.Text = "";
            IpBox.IsEnabled = LoginBox.IsEnabled = PasswordInput.IsEnabled = false;
            EditorCard.Visibility = IsFactoryAddress(host) ? Visibility.Collapsed : Visibility.Visible;
            QuickSetCard.Visibility = Visibility.Visible;
            DisconnectedPopup.Visibility = Visibility.Collapsed;
            ConnectButton.IsEnabled = true;
            InternetCheckButton.IsEnabled = true;
            InternetCheckButton.Content = "Перевірити з'єднання";
            ValidateWireGuardIp();
            _connectionTimer.Start();
            await RefreshCompletionStateAsync();
            if (!IsFactoryAddress(host)) await OpenInitialWireGuardTabAsync();
            await LoadQuickSetAsync();
            return;
        }
        catch (SocketException) { ShowConnectionError("Invalid IP address or device is unavailable."); }
        catch (OperationCanceledException) { ShowConnectionError("Invalid IP address or device is unavailable."); }
        catch (Exception ex) { ShowConnectionError(ex.Message); }
        await client.DisposeAsync(); ConnectButton.Content = "Connect";
        ConnectButton.IsEnabled = true;
    }
    private async void Keys_Click(object sender, RoutedEventArgs e) => await GenerateKeys();
    private async void Create_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(MtuBox.Text, out var mtu) || mtu is < 576 or > 65535 || !int.TryParse(PortBox.Text, out var port) || port is < 1 or > 65535 || string.IsNullOrWhiteSpace(NameBox.Text)) { SetEditorStatus("Перевірте Name, MTU та Listen Port."); return; }
        var wireGuardIp = WireGuardIpBox.Text.Trim();
        if (!TryGetNetwork(wireGuardIp, out _)) { SetEditorStatus("Введіть коректний WireGuard IP Address з префіксом, наприклад 192.168.33.1/24."); return; }
        var otherSaved = GetOtherRouterSavedSettings();
        if (otherSaved != null && SameHostAddress(otherSaved.WireGuardIp, wireGuardIp))
        { SetEditorStatus("WireGuard IP Address має бути унікальним для кожного MikroTik."); return; }
        if (string.IsNullOrEmpty(PrivateKeyBox.Password) && !await GenerateKeys()) return;
        if (_routerClient == null) { SetEditorStatus("Спочатку підключіться до MikroTik кнопкою Connect."); return; }
        try
        {
            SetEditorStatus($"Створення {NameBox.Text} на {_connectedHost}…");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            var interfaceName = NameBox.Text.Trim();
            await _routerClient.CreateWireGuardAsync(interfaceName, mtu, port, PrivateKeyBox.Password, timeout.Token);
            await _routerClient.AddIpAddressAsync(interfaceName, wireGuardIp, timeout.Token);
            await SaveWireGuardAsync(new WireGuardSummary(interfaceName, PublicKeyBox.Text.Trim(), port, wireGuardIp));
            SetEditorStatus($"Інтерфейс {NameBox.Text} успішно створено на {_connectedHost}.");
            await LoadInterfacesAsync();
        }
        catch (IOException ex) { await DisconnectAsync($"Связь с MikroTik потеряна: {ex.Message}", true, true); }
        catch (Exception ex) { SetEditorStatus(ex.Message); }
    }
    private async Task<bool> GenerateKeys()
    {
        try
        {
            SetEditorStatus("Генерування ключів…");
            var privateKey = (await RunWg("genkey", null)).Trim();
            var publicKey = (await RunWg("pubkey", privateKey)).Trim();
            PrivateKeyBox.Password = privateKey; PublicKeyBox.Text = publicKey; SetEditorStatus("Нову пару ключів WireGuard створено."); return true;
        }
        catch (Exception ex) { SetEditorStatus($"Не вдалося створити ключі: {ex.Message}"); return false; }
    }
    private static async Task<string> RunWg(string arguments, string? input)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wg.exe");
        if (!File.Exists(path)) throw new FileNotFoundException("Встановіть WireGuard for Windows.");
        var process = Process.Start(new ProcessStartInfo(path, arguments) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true })!;
        if (input != null) { await process.StandardInput.WriteLineAsync(input); process.StandardInput.Close(); }
        var output = await process.StandardOutput.ReadToEndAsync(); var error = await process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new InvalidOperationException(error.Trim()); return output;
    }
    private void Reset_Click(object sender, RoutedEventArgs e) => Reset();
    private void CreateTab_Click(object sender, RoutedEventArgs e)
        => ShowCreateTab();
    private void ShowCreateTab()
    {
        CreateView.Visibility = Visibility.Visible; InterfacesView.Visibility = Visibility.Collapsed; DeleteView.Visibility = Visibility.Collapsed; CreateActions.Visibility = Visibility.Visible;
        CreateTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 53, 54));
        InterfacesTabButton.Background = DeleteTabButton.Background = System.Windows.Media.Brushes.Transparent;
    }
    private async void InterfacesTab_Click(object sender, RoutedEventArgs e)
        => await ShowInterfacesTabAsync();
    private async Task ShowInterfacesTabAsync()
    {
        CreateView.Visibility = Visibility.Collapsed; InterfacesView.Visibility = Visibility.Visible; DeleteView.Visibility = Visibility.Collapsed; CreateActions.Visibility = Visibility.Collapsed;
        InterfacesTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 53, 54));
        CreateTabButton.Background = DeleteTabButton.Background = System.Windows.Media.Brushes.Transparent;
        await LoadInterfacesAsync();
    }
    private async Task OpenInitialWireGuardTabAsync()
    {
        if (HasWireGuardInterface) await ShowInterfacesTabAsync();
        else ShowCreateTab();
    }
    private async void CollapseEditor_Click(object sender, RoutedEventArgs e)
    {
        _editorCollapsed = !_editorCollapsed;
        if (_editorCollapsed)
        {
            TabsRow.Height = new GridLength(0);
            EditorContentRow.Height = new GridLength(0);
            ActionsRow.Height = new GridLength(0);
            TabsBar.Visibility = CreateView.Visibility = InterfacesView.Visibility = DeleteView.Visibility = CreateActions.Visibility = Visibility.Collapsed;
            CollapseEditorButton.Content = "+";
            CollapseEditorButton.ToolTip = "Розгорнути";
        }
        else
        {
            TabsRow.Height = new GridLength(32);
            EditorContentRow.Height = new GridLength(1, GridUnitType.Star);
            ActionsRow.Height = new GridLength(46);
            TabsBar.Visibility = Visibility.Visible;
            CollapseEditorButton.Content = "−";
            CollapseEditorButton.ToolTip = "Згорнути";
            await OpenInitialWireGuardTabAsync();
        }
    }
    private async void DeleteTab_Click(object sender, RoutedEventArgs e)
    {
        CreateView.Visibility = Visibility.Collapsed; InterfacesView.Visibility = Visibility.Collapsed; DeleteView.Visibility = Visibility.Visible; CreateActions.Visibility = Visibility.Collapsed;
        DeleteTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(58, 35, 40));
        CreateTabButton.Background = InterfacesTabButton.Background = System.Windows.Media.Brushes.Transparent;
        await LoadDeleteListAsync();
    }
    private async Task LoadInterfacesAsync()
    {
        if (_routerClient == null) return;
        try
        {
            InterfacesList.Children.Clear();
            InterfaceDetails.Visibility = Visibility.Collapsed;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var interfaces = await _routerClient.GetWireGuardInterfacesAsync(timeout.Token);
            HasWireGuardInterface = interfaces.Count > 0;
            StateChanged?.Invoke(this, EventArgs.Empty);
            if (interfaces.Count == 0)
            {
                InterfacesList.Children.Add(new TextBlock { Text = "WireGuard-інтерфейси ще не створено.", Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush"), Margin = new Thickness(0, 10, 0, 0) });
                return;
            }
            foreach (var item in interfaces) InterfacesList.Children.Add(CreateInterfaceRow(item));
        }
        catch (Exception ex) { SetEditorStatus($"Не вдалося завантажити інтерфейси: {ex.Message}"); }
    }
    private UIElement CreateInterfaceRow(IReadOnlyDictionary<string, string> item)
    {
        var grid = new Grid { Margin = new Thickness(0, 0, 0, 5), Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(16, 23, 33)) };
        grid.ColumnDefinitions.Add(new ColumnDefinition()); grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) }); grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(90) }); grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
        AddCell(grid, item.GetValueOrDefault("name") ?? "—", 0);
        AddCell(grid, item.GetValueOrDefault("mtu") ?? "—", 1);
        AddCell(grid, item.GetValueOrDefault("listen-port") ?? "—", 2);
        var running = item.GetValueOrDefault("running") == "true" && item.GetValueOrDefault("disabled") != "true";
        AddCell(grid, running ? "Running" : "Inactive", 3, running ? "#39D394" : "#8F9BAD");
        grid.Cursor = System.Windows.Input.Cursors.Hand;
        grid.ToolTip = "Натисніть, щоб переглянути ключі";
        grid.MouseLeftButtonUp += (_, _) => ShowInterfaceDetails(item);
        return grid;
    }
    private async void InternetCheck_Click(object sender, RoutedEventArgs e) => await CheckInternetAsync(InternetCheckButton);
    private async Task CheckInternetAsync(Button button)
    {
        if (_routerClient == null) { button.Content = "Немає підключення"; return; }
        button.IsEnabled = false; button.Content = "Перевірка…";
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            var available = await _routerClient.PingAsync("1.1.1.1", timeout.Token)
                || await _routerClient.PingAsync("8.8.8.8", timeout.Token);
            button.Content = available ? "Інтернет є" : "Немає інтернету";
            button.Background = new System.Windows.Media.SolidColorBrush(available
                ? System.Windows.Media.Color.FromRgb(57, 211, 148) : System.Windows.Media.Color.FromRgb(158, 52, 64));
            button.Foreground = available ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(7, 21, 15)) : System.Windows.Media.Brushes.White;
        }
        catch { button.Content = "Помилка перевірки"; button.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(158, 52, 64)); }
        finally { button.IsEnabled = true; }
    }
    private void ShowInterfaceDetails(IReadOnlyDictionary<string, string> item)
    {
        DetailsTitle.Text = $"Interface › {item.GetValueOrDefault("name") ?? "—"}";
        DetailsPublicKey.Text = item.GetValueOrDefault("public-key") ?? "";
        _selectedPrivateKey = item.GetValueOrDefault("private-key") ?? "";
        DetailsPrivateKey.Password = _selectedPrivateKey;
        DetailsPrivateKeyVisible.Text = _selectedPrivateKey;
        DetailsPrivateKey.Visibility = Visibility.Visible;
        DetailsPrivateKeyVisible.Visibility = Visibility.Collapsed;
        ShowPrivateKeyButton.Content = "Показати";
        InterfaceDetails.Visibility = Visibility.Visible;
    }
    private void ShowPrivateKey_Click(object sender, RoutedEventArgs e)
    {
        var show = DetailsPrivateKeyVisible.Visibility != Visibility.Visible;
        DetailsPrivateKeyVisible.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        DetailsPrivateKey.Visibility = show ? Visibility.Collapsed : Visibility.Visible;
        ShowPrivateKeyButton.Content = show ? "Сховати" : "Показати";
    }
    private void CopyPublicKey_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(DetailsPublicKey.Text)) Clipboard.SetText(DetailsPublicKey.Text);
    }
    private void CopyPrivateKey_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_selectedPrivateKey)) Clipboard.SetText(_selectedPrivateKey);
    }
    private static void AddCell(Grid grid, string text, int column, string color = "#F1F5F9")
    {
        var cell = new TextBlock { Text = text, Foreground = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(color)), FontSize = 11, Padding = new Thickness(8, 7, 5, 7), TextTrimming = TextTrimming.CharacterEllipsis };
        Grid.SetColumn(cell, column); grid.Children.Add(cell);
    }
    private async Task LoadDeleteListAsync()
    {
        if (_routerClient == null) return;
        DeleteList.Children.Clear();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var interfaces = await _routerClient.GetWireGuardInterfacesAsync(timeout.Token);
            if (interfaces.Count == 0)
            {
                DeleteList.Children.Add(new TextBlock { Text = "Немає інтерфейсів для видалення.", Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush"), Margin = new Thickness(0, 8, 0, 0) });
                return;
            }
            foreach (var item in interfaces) DeleteList.Children.Add(CreateDeleteRow(item));
        }
        catch (Exception ex) { SetEditorStatus($"Не вдалося завантажити інтерфейси: {ex.Message}"); }
    }
    private UIElement CreateDeleteRow(IReadOnlyDictionary<string, string> item)
    {
        var row = new Grid { Margin = new Thickness(0, 0, 0, 6), Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(16, 23, 33)) };
        row.ColumnDefinitions.Add(new ColumnDefinition()); row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var name = item.GetValueOrDefault("name") ?? "—";
        var id = item.GetValueOrDefault(".id") ?? "";
        var label = new TextBlock { Text = name, Foreground = (System.Windows.Media.Brush)FindResource("TextBrush"), Padding = new Thickness(10, 8, 5, 8), VerticalAlignment = VerticalAlignment.Center };
        var button = new Button { Content = "Видалити", Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 187, 195)), Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(78, 38, 45)), Margin = new Thickness(5, 4, 5, 4), Padding = new Thickness(11, 5, 11, 5) };
        button.Click += async (_, _) => await DeleteInterfaceAsync(id, name);
        Grid.SetColumn(button, 1); row.Children.Add(label); row.Children.Add(button); return row;
    }
    private async Task DeleteInterfaceAsync(string id, string name)
    {
        if (_routerClient == null || string.IsNullOrEmpty(id)) return;
        var confirmation = MessageBox.Show($"Видалити WireGuard-інтерфейс «{name}»?\n\nЦю зміну буде негайно застосовано на MikroTik.", "Підтвердження видалення", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (confirmation != MessageBoxResult.Yes) return;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            await _routerClient.RemoveWireGuardAsync(id, timeout.Token);
            SetEditorStatus($"Інтерфейс {name} видалено.");
            InterfaceDetails.Visibility = Visibility.Collapsed;
            await LoadDeleteListAsync();
            await RefreshCompletionStateAsync();
        }
        catch (Exception ex) { SetEditorStatus($"Не вдалося видалити {name}: {ex.Message}"); }
    }
    private async Task DisconnectAsync(string message, bool showPopup, bool autoReconnect)
    {
        _connectionTimer.Stop();
        _autoReconnect = autoReconnect;
        var client = _routerClient;
        _routerClient = null; _connectedHost = null;
        HasWireGuardInterface = false;
        if (client != null)
        {
            try { await client.DisposeAsync(); } catch { }
        }
        IpBox.IsEnabled = LoginBox.IsEnabled = PasswordInput.IsEnabled = true;
        ConnectButton.IsEnabled = true; ConnectButton.Content = "Connect";
        InternetCheckButton.IsEnabled = false; InternetCheckButton.Content = "Перевірити з'єднання";
        EditorCard.Visibility = Visibility.Collapsed;
        QuickSetCard.Visibility = Visibility.Collapsed;
        SetEditorStatus("");
        if (showPopup) ShowDisconnected(message);
        if (_autoReconnect) _connectionTimer.Start();
        StateChanged?.Invoke(this, EventArgs.Empty);
    }
    private async void ConnectionTimer_Tick(object? sender, EventArgs e)
    {
        if (_healthCheckRunning) return;
        _healthCheckRunning = true;
        try
        {
            if (_routerClient == null)
            {
                if (_autoReconnect) await TryAutoReconnectAsync();
                return;
            }
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await _routerClient.GetSystemResourceAsync(timeout.Token);
            _consecutiveHealthFailures = 0;
        }
        catch
        {
            _consecutiveHealthFailures++;
            if (_consecutiveHealthFailures >= 2)
            {
                _consecutiveHealthFailures = 0;
                await DisconnectAsync("З'єднання з MikroTik розірвано. Виконується автоматичне повторне підключення…", true, true);
            }
        }
        finally
        {
            _healthCheckRunning = false;
        }
    }
    private async Task TryAutoReconnectAsync()
    {
        if (string.IsNullOrEmpty(_savedHost) || string.IsNullOrEmpty(_savedLogin)) return;
        var client = new RouterOsApiClient();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await client.ConnectAsync(_savedHost, _savedLogin, _savedPassword, timeout.Token);
            await client.GetSystemResourceAsync(timeout.Token);
            _routerClient = client; _connectedHost = _savedHost;
            IpBox.IsEnabled = LoginBox.IsEnabled = PasswordInput.IsEnabled = false;
            ConnectButton.Content = "Disconnect"; ConnectButton.IsEnabled = true;
            InternetCheckButton.IsEnabled = true; InternetCheckButton.Content = "Перевірити з'єднання";
            ConnectionMessage.Text = "";
            DisconnectedPopup.Visibility = Visibility.Collapsed;
            EditorCard.Visibility = IsFactoryAddress(_savedHost) ? Visibility.Collapsed : Visibility.Visible;
            QuickSetCard.Visibility = Visibility.Visible;
            await RefreshCompletionStateAsync();
            if (!IsFactoryAddress(_savedHost)) await OpenInitialWireGuardTabAsync();
            await LoadQuickSetAsync();
        }
        catch
        {
            await client.DisposeAsync();
            PopupMessage.Text = "З'єднання розірвано. Очікування доступності пристрою…";
            DisconnectedPopup.Visibility = Visibility.Visible;
        }
    }
    private async Task RefreshCompletionStateAsync()
    {
        if (_routerClient == null)
        {
            HasWireGuardInterface = false;
            StateChanged?.Invoke(this, EventArgs.Empty);
            return;
        }
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            HasWireGuardInterface = (await _routerClient.GetWireGuardInterfacesAsync(timeout.Token)).Count > 0;
        }
        catch { HasWireGuardInterface = false; }
        StateChanged?.Invoke(this, EventArgs.Empty);
    }
    private void ShowConnectionError(string message)
    {
        ConnectionMessage.Text = message;
        DisconnectedPopup.Visibility = Visibility.Visible;
        PopupMessage.Text = "Підключіться до MikroTik, щоб продовжити налаштування.";
        EditorCard.Visibility = Visibility.Collapsed;
    }
    private void ShowDisconnected(string message)
    {
        PopupMessage.Text = message;
        DisconnectedPopup.Visibility = Visibility.Visible;
        EditorCard.Visibility = Visibility.Collapsed;
    }
    private void SetEditorStatus(string message)
    {
        StatusText.Text = message;
        StatusText.Visibility = string.IsNullOrWhiteSpace(message) ? Visibility.Collapsed : Visibility.Visible;
    }
    private static bool IsFactoryAddress(string host) => host.Trim().Equals("192.168.88.1", StringComparison.OrdinalIgnoreCase);
    private void Reset() { NameBox.Text = DefaultInterfaceName; MtuBox.Text = "1420"; PortBox.Text = "13231"; WireGuardIpBox.Text = RouterNumber.TrimStart('0') == "2" ? "192.168.33.2/24" : "192.168.33.1/24"; PrivateKeyBox.Password = ""; PublicKeyBox.Text = ""; SetEditorStatus(""); ConnectionMessage.Text = ""; QuickSetStatus.Text = ""; QuickSetCard.Visibility = Visibility.Collapsed; EditorCard.Visibility = Visibility.Collapsed; DisconnectedPopup.Visibility = Visibility.Visible; ValidateWireGuardIp(); }
}
