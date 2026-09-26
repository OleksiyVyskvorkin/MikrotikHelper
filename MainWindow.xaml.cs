using System.Windows;
using System.IO;
using System.Text.Json;

namespace MikrotikHelper;

public partial class MainWindow : Window
{
    private const string DefaultPublicEndpoint = "74.244.126.127";
    private sealed record EndpointSettings(string PublicEndpoint);
    private RouterPanel.WireGuardSummary? _leftWireGuard;
    private RouterPanel.WireGuardSummary? _rightWireGuard;
    private bool _loadingPeerAddresses;
    private bool _peersCollapsed;
    private bool _rightPeersCollapsed;
    public MainWindow()
    {
        InitializeComponent();
        LeftRouter.StateChanged += Router_StateChanged;
        RightRouter.StateChanged += Router_StateChanged;
        LeftRouter.QuickSetChanged += QuickSet_Changed;
        RightRouter.QuickSetChanged += QuickSet_Changed;
        PublicEndpointBox.Text = LoadPublicEndpoint();
        _ = UpdateInstructionAsync();
    }

    private async void Router_StateChanged(object? sender, EventArgs e) => await UpdateInstructionAsync();
    private void QuickSet_Changed(object? sender, EventArgs e) => ValidateRouterSubnets();

    private void Instruction_Click(object sender, RoutedEventArgs e)
    {
        new InstructionWindow { Owner = this }.ShowDialog();
    }

    private void DeleteSavedSettings_Click(object sender, RoutedEventArgs e)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "quickset-settings.json");
        if (MessageBox.Show("Видалити всі збережені налаштування MikroTik?\n\nЦю дію неможливо скасувати.",
            "Видалення налаштувань", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        try
        {
            if (File.Exists(path)) File.Delete(path);
            MessageBox.Show("Збережені налаштування видалено.", "Видалення налаштувань", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Не вдалося видалити налаштування: {ex.Message}", "Помилка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ShowPublicEndpoint_Click(object sender, RoutedEventArgs e)
    {
        var window = new EndpointWindow(PublicEndpointBox.Text.Trim()) { Owner = this };
        if (window.ShowDialog() != true) return;
        PublicEndpointBox.Text = window.Endpoint;
        SavePublicEndpoint();
    }

    private void PublicEndpointBox_LostFocus(object sender, RoutedEventArgs e) => SavePublicEndpoint();

    private static string EndpointSettingsPath => Path.Combine(AppContext.BaseDirectory, "endpoint-settings.json");

    private static string LoadPublicEndpoint()
    {
        try
        {
            if (!File.Exists(EndpointSettingsPath)) return DefaultPublicEndpoint;
            return JsonSerializer.Deserialize<EndpointSettings>(File.ReadAllText(EndpointSettingsPath))?.PublicEndpoint
                ?? DefaultPublicEndpoint;
        }
        catch { return DefaultPublicEndpoint; }
    }

    private void SavePublicEndpoint()
    {
        var endpoint = PublicEndpointBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(endpoint)) return;
        var temporaryPath = EndpointSettingsPath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(new EndpointSettings(endpoint), new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temporaryPath, EndpointSettingsPath, true);
    }

    private void ValidateRouterSubnets()
    {
        LeftRouter.SetOtherRouterLocalAddress(RightRouter.ProposedLocalAddress);
        RightRouter.SetOtherRouterLocalAddress(LeftRouter.ProposedLocalAddress);
    }

    private async Task UpdateInstructionAsync()
    {
        var leftReady = LeftRouter.IsRouterConnected && LeftRouter.HasWireGuardInterface;
        var rightReady = RightRouter.IsRouterConnected && RightRouter.HasWireGuardInterface;
        PeersCard.Visibility = leftReady ? Visibility.Visible : Visibility.Collapsed;
        RightPeersCard.Visibility = rightReady ? Visibility.Visible : Visibility.Collapsed;
        CreateLeftPeerButton.IsEnabled = leftReady;
        CreateRightPeerButton.IsEnabled = rightReady;
        if (leftReady || rightReady) await LoadPeerAddressesAsync();
        else
        {
            _leftWireGuard = _rightWireGuard = null;
            LeftAllowedAddress.Text = RightAllowedAddress.Text = "";
            PeerStatus.Text = "";
        }
        ValidateRouterSubnets();
    }

    private async Task LoadPeerAddressesAsync()
    {
        if (_loadingPeerAddresses) return;
        _loadingPeerAddresses = true;
        try
        {
            PeerStatus.Text = "Отримання адрес WireGuard-інтерфейсів…";
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            _leftWireGuard = LeftRouter.IsRouterConnected ? await LeftRouter.GetPrimaryWireGuardAsync(timeout.Token) : SavedWireGuard(LeftRouter);
            _rightWireGuard = RightRouter.IsRouterConnected ? await RightRouter.GetPrimaryWireGuardAsync(timeout.Token) : SavedWireGuard(RightRouter);
            if (_leftWireGuard == null || _rightWireGuard == null)
                throw new InvalidOperationException("Для відключеного MikroTik немає збережених параметрів WireGuard.");
            LeftAllowedAddress.Text = CombineAllowedAddresses(_rightWireGuard.Address, SavedOrCurrentLocal(RightRouter));
            RightAllowedAddress.Text = CombineAllowedAddresses(_leftWireGuard.Address, SavedOrCurrentLocal(LeftRouter));
            if (string.IsNullOrWhiteSpace(PublicEndpointBox.Text)) PublicEndpointBox.Text = LoadPublicEndpoint();
            PeerStatus.Text = "";
        }
        catch (Exception ex)
        {
            _leftWireGuard = _rightWireGuard = null;
            LeftAllowedAddress.Text = RightAllowedAddress.Text = "";
            PeerStatus.Text = $"Не вдалося отримати Allowed Address: {ex.Message}";
        }
        finally { _loadingPeerAddresses = false; }
    }

    private async void CreateLeftPeer_Click(object sender, RoutedEventArgs e) => await CreatePeerForRouterAsync(true);
    private async void CreateRightPeer_Click(object sender, RoutedEventArgs e) => await CreatePeerForRouterAsync(false);

    private async Task CreatePeerForRouterAsync(bool createOnLeft)
    {
        var targetRouter = createOnLeft ? LeftRouter : RightRouter;
        if (!targetRouter.IsRouterConnected || !targetRouter.HasWireGuardInterface)
        {
            PeerStatus.Text = $"{(createOnLeft ? "MikroTik 1" : "MikroTik 2")} має бути підключений і мати WireGuard-інтерфейс.";
            return;
        }
        var peerName = createOnLeft ? LeftPeerName.Text.Trim() : RightPeerName.Text.Trim();
        if (string.IsNullOrWhiteSpace(peerName)) { PeerStatus.Text = "Заповніть Name для peer."; return; }
        var keepaliveText = createOnLeft ? KeepaliveBox.Text : "25";
        if (!int.TryParse(keepaliveText, out var keepalive) || keepalive is < 0 or > 65535)
        {
            PeerStatus.Text = "Keepalive має бути числом від 0 до 65535 секунд.";
            return;
        }
        try
        {
            PeerStatus.Text = $"Створення peer на {(createOnLeft ? "MikroTik 1" : "MikroTik 2")}…";
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var leftInterface = LeftRouter.IsRouterConnected ? await LeftRouter.GetPrimaryWireGuardAsync(timeout.Token) : SavedWireGuard(LeftRouter);
            var rightInterface = RightRouter.IsRouterConnected ? await RightRouter.GetPrimaryWireGuardAsync(timeout.Token) : SavedWireGuard(RightRouter);
            if (leftInterface == null || rightInterface == null)
                throw new InvalidOperationException("Немає збережених параметрів WireGuard для відключеного MikroTik.");
            var leftAllowed = CombineAllowedAddresses(ToHostCidr(rightInterface.Address), SavedOrCurrentLocal(RightRouter));
            var rightAllowed = CombineAllowedAddresses(ToHostCidr(leftInterface.Address), SavedOrCurrentLocal(LeftRouter));
            LeftAllowedAddress.Text = leftAllowed;
            RightAllowedAddress.Text = rightAllowed;
            if (createOnLeft)
            {
                await LeftRouter.CreatePeerAsync(peerName, leftInterface.Name,
                    rightInterface.PublicKey, null, null, leftAllowed, 0, timeout.Token);
                await LeftRouter.ConfigureRoutesAsync(SavedOrCurrentLocal(RightRouter), leftInterface.Name, timeout.Token);
                await LeftRouter.ConfigureWireGuardFirewallAsync(leftInterface.ListenPort, SavedOrCurrentLocal(LeftRouter),
                    SavedOrCurrentLocal(RightRouter), true, timeout.Token);
            }
            else
            {
                var endpoint = PublicEndpointBox.Text.Trim();
                if (string.IsNullOrWhiteSpace(endpoint)) throw new InvalidOperationException("Вкажіть публічний Endpoint MikroTik 1.");
                SavePublicEndpoint();
                await RightRouter.SaveWanEndpointAsync(endpoint);
                await RightRouter.CreatePeerAsync(peerName, rightInterface.Name,
                    leftInterface.PublicKey, endpoint, leftInterface.ListenPort, rightAllowed, 25, timeout.Token);
                await RightRouter.ConfigureRoutesAsync(SavedOrCurrentLocal(LeftRouter), rightInterface.Name, timeout.Token);
                await RightRouter.ConfigureWireGuardFirewallAsync(rightInterface.ListenPort, SavedOrCurrentLocal(RightRouter),
                    SavedOrCurrentLocal(LeftRouter), false, timeout.Token);
            }
            SetPeerStatus(createOnLeft, $"Peer і маршрут успішно створено на {(createOnLeft ? "MikroTik 1" : "MikroTik 2")}.");
        }
        catch (Exception ex) { SetPeerStatus(createOnLeft, $"Не вдалося створити peer: {ex.Message}"); }
    }

    private void SetPeerStatus(bool left, string text) { if (left) PeerStatus.Text = text; else RightPeerStatus.Text = text; }

    private static RouterPanel.WireGuardSummary? SavedWireGuard(RouterPanel router)
    {
        var saved = router.GetSavedSettings();
        return saved == null || string.IsNullOrWhiteSpace(saved.WireGuardIp) || string.IsNullOrWhiteSpace(saved.PublicKey) || saved.ListenPort <= 0
            ? null : new RouterPanel.WireGuardSummary("", saved.PublicKey, saved.ListenPort, saved.WireGuardIp);
    }

    private static string SavedOrCurrentLocal(RouterPanel router)
        => !string.IsNullOrWhiteSpace(router.LocalNetworkAddress) ? router.LocalNetworkAddress : router.GetSavedSettings()?.LocalIp ?? "";

    private static string HostWithoutPrefix(RouterPanel router)
        => (router.IsRouterConnected ? router.ConnectionHost : router.GetSavedSettings()?.LocalIp ?? "").Split('/')[0];

    private static string ToHostCidr(string cidr) => $"{cidr.Split('/')[0]}/32";

    private void CreatePeersTab_Click(object sender, RoutedEventArgs e)
    {
        CreatePeersView.Visibility = Visibility.Visible;
        ExistingPeersView.Visibility = Visibility.Collapsed;
        DeletePeersView.Visibility = Visibility.Collapsed;
        PeersActions.Visibility = Visibility.Visible;
        CreatePeersTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 53, 54));
        ExistingPeersTabButton.Background = DeletePeersTabButton.Background = System.Windows.Media.Brushes.Transparent;
    }

    private async void ExistingPeersTab_Click(object sender, RoutedEventArgs e)
    {
        CreatePeersView.Visibility = Visibility.Collapsed;
        ExistingPeersView.Visibility = Visibility.Visible;
        DeletePeersView.Visibility = Visibility.Collapsed;
        PeersActions.Visibility = Visibility.Collapsed;
        ExistingPeersTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 53, 54));
        CreatePeersTabButton.Background = DeletePeersTabButton.Background = System.Windows.Media.Brushes.Transparent;
        await LoadExistingPeersAsync();
    }

    private async void DeletePeersTab_Click(object sender, RoutedEventArgs e)
    {
        CreatePeersView.Visibility = Visibility.Collapsed;
        ExistingPeersView.Visibility = Visibility.Collapsed;
        DeletePeersView.Visibility = Visibility.Visible;
        PeersActions.Visibility = Visibility.Collapsed;
        DeletePeersTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(58, 35, 40));
        CreatePeersTabButton.Background = ExistingPeersTabButton.Background = System.Windows.Media.Brushes.Transparent;
        await LoadDeletePeersAsync();
    }

    private async Task LoadExistingPeersAsync()
    {
        LeftPeersList.Children.Clear();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            var left = await LeftRouter.GetPeersAsync(timeout.Token);
            FillPeersList(LeftPeersList, left);
        }
        catch (Exception ex) { PeerStatus.Text = $"Не вдалося завантажити peers: {ex.Message}"; }
    }

    private void FillPeersList(System.Windows.Controls.StackPanel panel, IReadOnlyList<RouterOsApiClient.WireGuardPeerRecord> peers)
    {
        if (peers.Count == 0)
        {
            panel.Children.Add(new System.Windows.Controls.TextBlock { Text = "Peers ещё не созданы.", Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush"), Margin = new Thickness(4, 8, 0, 0) });
            return;
        }
        foreach (var peer in peers)
        {
            var border = new System.Windows.Controls.Border { Background = (System.Windows.Media.Brush)FindResource("FieldBrush"), BorderBrush = (System.Windows.Media.Brush)FindResource("BorderBrush"), BorderThickness = new Thickness(1), Margin = new Thickness(0, 0, 0, 6), Padding = new Thickness(10, 7, 10, 7) };
            var stack = new System.Windows.Controls.StackPanel();
            stack.Children.Add(new System.Windows.Controls.TextBlock { Text = peer.Name, Foreground = (System.Windows.Media.Brush)FindResource("TextBrush"), FontWeight = FontWeights.Bold });
            stack.Children.Add(new System.Windows.Controls.TextBlock { Text = $"Interface: {peer.Interface}   Allowed: {peer.AllowedAddress}", Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush"), FontSize = 10, Margin = new Thickness(0, 3, 0, 0), TextWrapping = TextWrapping.Wrap });
            stack.Children.Add(new System.Windows.Controls.TextBlock { Text = $"Endpoint: {peer.EndpointAddress}:{peer.EndpointPort}   Handshake: {peer.LastHandshake}", Foreground = peer.Disabled ? System.Windows.Media.Brushes.IndianRed : (System.Windows.Media.Brush)FindResource("AccentBrush"), FontSize = 10, Margin = new Thickness(0, 2, 0, 0) });
            stack.Children.Add(new System.Windows.Controls.TextBlock { Text = $"Rx: {peer.Rx}   Tx: {peer.Tx}" + (peer.LastHandshake is "never" or "" ? "   Немає handshake: перевірте Endpoint, проброс UDP-порту, firewall та інтернет MikroTik 2." : ""), Foreground = peer.LastHandshake is "never" or "" ? System.Windows.Media.Brushes.Orange : (System.Windows.Media.Brush)FindResource("MutedBrush"), FontSize = 10, Margin = new Thickness(0, 2, 0, 0), TextWrapping = TextWrapping.Wrap });
            border.Child = stack; panel.Children.Add(border);
        }
    }

    private async Task LoadDeletePeersAsync()
    {
        LeftDeletePeersList.Children.Clear();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            FillDeletePeersList(LeftDeletePeersList, await LeftRouter.GetPeersAsync(timeout.Token), LeftRouter, "MikroTik 1");
        }
        catch (Exception ex) { PeerStatus.Text = $"Не вдалося завантажити peers: {ex.Message}"; }
    }

    private void RightCreatePeersTab_Click(object sender, RoutedEventArgs e)
    {
        RightCreatePeersView.Visibility = Visibility.Visible; RightExistingPeersView.Visibility = RightDeletePeersView.Visibility = Visibility.Collapsed;
        RightPeersActions.Visibility = Visibility.Visible;
        RightCreatePeersTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 53, 54));
        RightExistingPeersTabButton.Background = RightDeletePeersTabButton.Background = System.Windows.Media.Brushes.Transparent;
    }

    private async void RightExistingPeersTab_Click(object sender, RoutedEventArgs e)
    {
        RightCreatePeersView.Visibility = RightDeletePeersView.Visibility = Visibility.Collapsed; RightExistingPeersView.Visibility = Visibility.Visible;
        RightPeersActions.Visibility = Visibility.Collapsed;
        RightExistingPeersTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 53, 54));
        RightCreatePeersTabButton.Background = RightDeletePeersTabButton.Background = System.Windows.Media.Brushes.Transparent;
        RightPeersList.Children.Clear();
        try { using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8)); FillPeersList(RightPeersList, await RightRouter.GetPeersAsync(timeout.Token)); }
        catch (Exception ex) { RightPeerStatus.Text = $"Не вдалося завантажити peers: {ex.Message}"; }
    }

    private async void RightDeletePeersTab_Click(object sender, RoutedEventArgs e)
    {
        RightCreatePeersView.Visibility = RightExistingPeersView.Visibility = Visibility.Collapsed; RightDeletePeersView.Visibility = Visibility.Visible;
        RightPeersActions.Visibility = Visibility.Collapsed;
        RightDeletePeersTabButton.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(58, 35, 40));
        RightCreatePeersTabButton.Background = RightExistingPeersTabButton.Background = System.Windows.Media.Brushes.Transparent;
        RightDeletePeersList.Children.Clear();
        try { using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8)); FillDeletePeersList(RightDeletePeersList, await RightRouter.GetPeersAsync(timeout.Token), RightRouter, "MikroTik 2"); }
        catch (Exception ex) { RightPeerStatus.Text = $"Не вдалося завантажити peers: {ex.Message}"; }
    }

    private void CollapseRightPeers_Click(object sender, RoutedEventArgs e)
    {
        _rightPeersCollapsed = !_rightPeersCollapsed;
        RightPeersTabsRow.Height = _rightPeersCollapsed ? new GridLength(0) : new GridLength(32);
        RightPeersContentRow.Height = _rightPeersCollapsed ? new GridLength(0) : GridLength.Auto;
        RightPeersActionsRow.Height = _rightPeersCollapsed ? new GridLength(0) : GridLength.Auto;
        RightPeersTabsBar.Visibility = RightCreatePeersView.Visibility = RightPeersActions.Visibility = _rightPeersCollapsed ? Visibility.Collapsed : Visibility.Visible;
        RightExistingPeersView.Visibility = RightDeletePeersView.Visibility = Visibility.Collapsed;
        CollapseRightPeersButton.Content = _rightPeersCollapsed ? "+" : "−";
        if (!_rightPeersCollapsed) RightCreatePeersTab_Click(sender, e);
    }

    private void FillDeletePeersList(System.Windows.Controls.StackPanel panel,
        IReadOnlyList<RouterOsApiClient.WireGuardPeerRecord> peers, RouterPanel router, string routerName)
    {
        if (peers.Count == 0)
        {
            panel.Children.Add(new System.Windows.Controls.TextBlock { Text = "Немає peers для видалення.", Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush"), Margin = new Thickness(4, 8, 0, 0) });
            return;
        }
        foreach (var peer in peers)
        {
            var row = new System.Windows.Controls.Grid { Background = (System.Windows.Media.Brush)FindResource("FieldBrush"), Margin = new Thickness(0, 0, 0, 6) };
            row.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition());
            row.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = GridLength.Auto });
            row.Children.Add(new System.Windows.Controls.TextBlock { Text = $"{peer.Name}\n{peer.AllowedAddress}", Foreground = (System.Windows.Media.Brush)FindResource("TextBrush"), FontSize = 11, Padding = new Thickness(10, 6, 5, 6) });
            var button = new System.Windows.Controls.Button { Content = "Видалити", Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 187, 195)), Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(78, 38, 45)), Margin = new Thickness(5, 5, 6, 5), Padding = new Thickness(10, 5, 10, 5) };
            button.Click += async (_, _) => await DeletePeerAsync(router, routerName, peer);
            System.Windows.Controls.Grid.SetColumn(button, 1); row.Children.Add(button); panel.Children.Add(row);
        }
    }

    private async Task DeletePeerAsync(RouterPanel router, string routerName, RouterOsApiClient.WireGuardPeerRecord peer)
    {
        if (string.IsNullOrEmpty(peer.Id)) return;
        if (MessageBox.Show($"Видалити peer «{peer.Name}» з {routerName}?\n\nЗміну буде негайно застосовано на пристрої.",
            "Підтвердження видалення", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            await router.RemovePeerAsync(peer.Id, timeout.Token);
            PeerStatus.Text = $"Peer {peer.Name} видалено з {routerName}.";
            await LoadDeletePeersAsync();
        }
        catch (Exception ex) { PeerStatus.Text = $"Не вдалося видалити peer: {ex.Message}"; }
    }

    private async void CollapsePeers_Click(object sender, RoutedEventArgs e)
    {
        _peersCollapsed = !_peersCollapsed;
        PeersTabsRow.Height = _peersCollapsed ? new GridLength(0) : new GridLength(32);
        PeersContentRow.Height = _peersCollapsed ? new GridLength(0) : GridLength.Auto;
        PeersActionsRow.Height = _peersCollapsed ? new GridLength(0) : GridLength.Auto;
        PeersTabsBar.Visibility = _peersCollapsed ? Visibility.Collapsed : Visibility.Visible;
        CreatePeersView.Visibility = _peersCollapsed ? Visibility.Collapsed : Visibility.Visible;
        ExistingPeersView.Visibility = Visibility.Collapsed;
        DeletePeersView.Visibility = Visibility.Collapsed;
        PeersActions.Visibility = _peersCollapsed ? Visibility.Collapsed : Visibility.Visible;
        CollapsePeersButton.Content = _peersCollapsed ? "+" : "−";
        CollapsePeersButton.ToolTip = _peersCollapsed ? "Розгорнути" : "Згорнути";
        if (!_peersCollapsed) CreatePeersTab_Click(sender, e);
        await Task.CompletedTask;
    }

    private static string CombineAllowedAddresses(string wireGuardAddress, string localAddress) =>
        string.Join(",", new[] { wireGuardAddress, localAddress }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase));
}
