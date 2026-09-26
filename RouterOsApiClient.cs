using System.IO;
using System.Net.Sockets;
using System.Text;

namespace MikrotikHelper;

public sealed class RouterOsApiClient : IAsyncDisposable
{
    public sealed record IpAddressRecord(string Id, string Address, string Interface);
    public sealed record DhcpServerRecord(string Id, string Name, string Interface, string AddressPool, bool Enabled);
    public sealed record DhcpNetworkRecord(string Id, string Address, string Gateway, string DnsServer);
    public sealed record IpPoolRecord(string Id, string Name, string Ranges);
    public sealed record WireGuardPeerRecord(string Id, string Name, string Interface, string PublicKey, string AllowedAddress,
        string EndpointAddress, string EndpointPort, string LastHandshake, string Rx, string Tx, bool Disabled);
    public sealed record DhcpClientRecord(string Id, string Interface);
    public sealed record RouteRecord(string Id, string DstAddress, string Gateway, bool Dynamic);
    public sealed record UserRecord(string Id, string Name);
    private readonly TcpClient _tcpClient = new();
    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private NetworkStream? _stream;

    public bool IsConnected => _tcpClient.Connected && _stream != null;

    public async Task ConnectAsync(string host, string username, string password, CancellationToken cancellationToken)
    {
        await _tcpClient.ConnectAsync(host, 8728, cancellationToken);
        _stream = _tcpClient.GetStream();
        var login = await ExecuteAsync(["/login", $"=name={username}", $"=password={password}"], cancellationToken);
        ThrowIfError(login);
    }

    public async Task<IReadOnlyDictionary<string, string>> GetSystemResourceAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/system/resource/print", "=.proplist=board-name,platform,version"], cancellationToken);
        ThrowIfError(response);
        return response.FirstOrDefault(sentence => sentence.Type == "!re")?.Attributes
               ?? new Dictionary<string, string>();
    }

    public async Task<bool> PingAsync(string address, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ping", $"=address={address}", "=count=3", "=interval=300ms"], cancellationToken);
        ThrowIfError(response);
        return response.Any(sentence => sentence.Type == "!re"
            && sentence.Attributes.TryGetValue("time", out var time) && !string.IsNullOrWhiteSpace(time));
    }

    public async Task<string?> CreateWireGuardAsync(string name, int mtu, int listenPort, string privateKey, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync([
            "/interface/wireguard/add", $"=name={name}", $"=mtu={mtu}",
            $"=listen-port={listenPort}", $"=private-key={privateKey}"
        ], cancellationToken);
        ThrowIfError(response);
        var done = response.LastOrDefault(sentence => sentence.Type == "!done");
        return done?.Attributes.GetValueOrDefault("ret") ?? done?.Attributes.GetValueOrDefault(".id");
    }

    public async Task<IReadOnlyList<IReadOnlyDictionary<string, string>>> GetWireGuardInterfacesAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync([
            "/interface/wireguard/print", "=.proplist=.id,name,mtu,listen-port,private-key,public-key,running,disabled"
        ], cancellationToken);
        ThrowIfError(response);
        return response.Where(sentence => sentence.Type == "!re")
            .Select(sentence => (IReadOnlyDictionary<string, string>)sentence.Attributes).ToList();
    }

    public async Task RemoveWireGuardAsync(string id, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(id)) throw new ArgumentException("RouterOS interface ID is missing.", nameof(id));
        var response = await ExecuteAsync(["/interface/wireguard/remove", $"=.id={id}"], cancellationToken);
        ThrowIfError(response);
    }

    public async Task CreateWireGuardPeerAsync(string name, string interfaceName, string publicKey,
        string? endpointAddress, int? endpointPort, string allowedAddress, int keepaliveSeconds,
        CancellationToken cancellationToken)
    {
        var existing = (await GetWireGuardPeersAsync(cancellationToken)).FirstOrDefault(peer =>
            peer.PublicKey.Equals(publicKey, StringComparison.Ordinal));
        var words = new List<string> {
            existing == null ? "/interface/wireguard/peers/add" : "/interface/wireguard/peers/set"
        };
        if (existing != null) words.Add($"=.id={existing.Id}");
        words.AddRange([$"=name={name}", $"=interface={interfaceName}", $"=public-key={publicKey}",
            $"=allowed-address={allowedAddress}"]);
        if (!string.IsNullOrWhiteSpace(endpointAddress) && endpointPort is > 0)
        {
            words.Add($"=endpoint-address={endpointAddress}");
            words.Add($"=endpoint-port={endpointPort}");
        }
        if (keepaliveSeconds > 0) words.Add($"=persistent-keepalive={keepaliveSeconds}s");
        var response = await ExecuteAsync(words, cancellationToken);
        ThrowIfError(response);
    }

    public async Task EnsureFirewallRuleAsync(string chain, string comment, IReadOnlyDictionary<string, string> properties,
        CancellationToken cancellationToken)
    {
        var printed = await ExecuteAsync(["/ip/firewall/filter/print", "=.proplist=.id,comment", $"?comment={comment}"], cancellationToken);
        ThrowIfError(printed);
        if (printed.Any(sentence => sentence.Type == "!re")) return;
        var words = new List<string> { "/ip/firewall/filter/add", $"=chain={chain}", "=action=accept", $"=comment={comment}", "=place-before=0" };
        words.AddRange(properties.Select(item => $"={item.Key}={item.Value}"));
        var response = await ExecuteAsync(words, cancellationToken);
        ThrowIfError(response);
    }

    public async Task<IReadOnlyList<WireGuardPeerRecord>> GetWireGuardPeersAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/interface/wireguard/peers/print",
            "=.proplist=.id,name,interface,public-key,allowed-address,endpoint-address,endpoint-port,last-handshake,rx,tx,disabled"], cancellationToken);
        ThrowIfError(response);
        return response.Where(sentence => sentence.Type == "!re").Select(sentence => new WireGuardPeerRecord(
            sentence.Attributes.GetValueOrDefault(".id") ?? "", sentence.Attributes.GetValueOrDefault("name") ?? "—", sentence.Attributes.GetValueOrDefault("interface") ?? "—",
            sentence.Attributes.GetValueOrDefault("public-key") ?? "",
            sentence.Attributes.GetValueOrDefault("allowed-address") ?? "—", sentence.Attributes.GetValueOrDefault("endpoint-address") ?? "—",
            sentence.Attributes.GetValueOrDefault("endpoint-port") ?? "—", sentence.Attributes.GetValueOrDefault("last-handshake") ?? "never",
            sentence.Attributes.GetValueOrDefault("rx") ?? "0", sentence.Attributes.GetValueOrDefault("tx") ?? "0",
            sentence.Attributes.GetValueOrDefault("disabled") == "true")).ToList();
    }

    public async Task RemoveWireGuardPeerAsync(string id, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(id)) throw new ArgumentException("RouterOS peer ID is missing.", nameof(id));
        var response = await ExecuteAsync(["/interface/wireguard/peers/remove", $"=.id={id}"], cancellationToken);
        ThrowIfError(response);
    }

    public async Task<string?> GetInterfaceAddressAsync(string interfaceName, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync([
            "/ip/address/print", "=.proplist=address,interface,disabled,invalid", $"?interface={interfaceName}"
        ], cancellationToken);
        ThrowIfError(response);
        return response.FirstOrDefault(sentence => sentence.Type == "!re"
            && sentence.Attributes.GetValueOrDefault("disabled") != "true"
            && sentence.Attributes.GetValueOrDefault("invalid") != "true")?.Attributes.GetValueOrDefault("address");
    }

    public async Task<IReadOnlyList<IpAddressRecord>> GetStaticIpAddressesAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/address/print", "=.proplist=.id,address,interface,dynamic,disabled,invalid"], cancellationToken);
        ThrowIfError(response);
        return response.Where(sentence => sentence.Type == "!re"
            && sentence.Attributes.GetValueOrDefault("dynamic") != "true"
            && sentence.Attributes.GetValueOrDefault("disabled") != "true"
            && sentence.Attributes.GetValueOrDefault("invalid") != "true")
            .Select(sentence => new IpAddressRecord(sentence.Attributes.GetValueOrDefault(".id") ?? "",
                sentence.Attributes.GetValueOrDefault("address") ?? "", sentence.Attributes.GetValueOrDefault("interface") ?? ""))
            .Where(item => item.Id.Length > 0 && item.Address.Length > 0).ToList();
    }

    public async Task SetIpAddressAsync(string id, string address, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/address/set", $"=.id={id}", $"=address={address}"], cancellationToken);
        ThrowIfError(response);
    }

    public async Task AddIpAddressAsync(string interfaceName, string address, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/address/add", $"=interface={interfaceName}", $"=address={address}"], cancellationToken);
        ThrowIfError(response);
    }

    public async Task<IReadOnlyList<DhcpServerRecord>> GetDhcpServersAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/dhcp-server/print", "=.proplist=.id,name,interface,address-pool,disabled,invalid"], cancellationToken);
        ThrowIfError(response);
        return response.Where(sentence => sentence.Type == "!re" && sentence.Attributes.GetValueOrDefault("invalid") != "true")
            .Select(sentence => new DhcpServerRecord(sentence.Attributes.GetValueOrDefault(".id") ?? "",
                sentence.Attributes.GetValueOrDefault("name") ?? "", sentence.Attributes.GetValueOrDefault("interface") ?? "",
                sentence.Attributes.GetValueOrDefault("address-pool") ?? "",
                sentence.Attributes.GetValueOrDefault("disabled") != "true")).Where(item => item.Id.Length > 0).ToList();
    }

    public async Task SetDhcpServerEnabledAsync(string id, bool enabled, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/dhcp-server/set", $"=.id={id}", $"=disabled={(enabled ? "no" : "yes")}"], cancellationToken);
        ThrowIfError(response);
    }

    public async Task<IpPoolRecord?> GetIpPoolAsync(string name, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(name) || name == "static-only") return null;
        var response = await ExecuteAsync(["/ip/pool/print", "=.proplist=.id,name,ranges", $"?name={name}"], cancellationToken);
        ThrowIfError(response);
        var item = response.FirstOrDefault(sentence => sentence.Type == "!re");
        return item == null ? null : new IpPoolRecord(item.Attributes.GetValueOrDefault(".id") ?? "",
            item.Attributes.GetValueOrDefault("name") ?? "", item.Attributes.GetValueOrDefault("ranges") ?? "");
    }

    public async Task SetIpPoolRangesAsync(string id, string ranges, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/pool/set", $"=.id={id}", $"=ranges={ranges}"], cancellationToken);
        ThrowIfError(response);
    }

    public async Task<IReadOnlyList<DhcpNetworkRecord>> GetDhcpNetworksAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/dhcp-server/network/print", "=.proplist=.id,address,gateway,dns-server"], cancellationToken);
        ThrowIfError(response);
        return response.Where(sentence => sentence.Type == "!re")
            .Select(sentence => new DhcpNetworkRecord(sentence.Attributes.GetValueOrDefault(".id") ?? "",
                sentence.Attributes.GetValueOrDefault("address") ?? "", sentence.Attributes.GetValueOrDefault("gateway") ?? "",
                sentence.Attributes.GetValueOrDefault("dns-server") ?? ""))
            .Where(item => item.Id.Length > 0).ToList();
    }

    public async Task SetDhcpNetworkAsync(string id, string address, string gateway, string dnsServer, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/dhcp-server/network/set", $"=.id={id}", $"=address={address}",
            $"=gateway={gateway}", $"=dns-server={dnsServer}"], cancellationToken);
        ThrowIfError(response);
    }

    public async Task<IReadOnlyList<string>> GetDhcpClientInterfacesAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/dhcp-client/print", "=.proplist=interface,disabled,status"], cancellationToken);
        ThrowIfError(response);
        return response.Where(sentence => sentence.Type == "!re"
            && sentence.Attributes.GetValueOrDefault("disabled") != "true")
            .Select(sentence => sentence.Attributes.GetValueOrDefault("interface") ?? "")
            .Where(value => value.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<IReadOnlyList<DhcpClientRecord>> GetDhcpClientsAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/dhcp-client/print", "=.proplist=.id,interface,disabled"], cancellationToken);
        ThrowIfError(response);
        return response.Where(sentence => sentence.Type == "!re" && sentence.Attributes.GetValueOrDefault("disabled") != "true")
            .Select(sentence => new DhcpClientRecord(sentence.Attributes.GetValueOrDefault(".id") ?? "",
                sentence.Attributes.GetValueOrDefault("interface") ?? ""))
            .Where(item => item.Id.Length > 0).ToList();
    }

    public async Task SetDhcpClientRouteDistanceAsync(string id, int distance, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/dhcp-client/set", $"=.id={id}", $"=default-route-distance={distance}"], cancellationToken);
        ThrowIfError(response);
    }

    public async Task<IReadOnlyList<RouteRecord>> GetRoutesAsync(CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/ip/route/print", "=.proplist=.id,dst-address,gateway,dynamic"], cancellationToken);
        ThrowIfError(response);
        return response.Where(sentence => sentence.Type == "!re").Select(sentence => new RouteRecord(
            sentence.Attributes.GetValueOrDefault(".id") ?? "", sentence.Attributes.GetValueOrDefault("dst-address") ?? "",
            sentence.Attributes.GetValueOrDefault("gateway") ?? "", sentence.Attributes.GetValueOrDefault("dynamic") == "true")).ToList();
    }

    public async Task UpsertStaticRouteAsync(string dstAddress, string gateway, int distance, CancellationToken cancellationToken)
    {
        var existing = (await GetRoutesAsync(cancellationToken)).FirstOrDefault(route => !route.Dynamic
            && route.DstAddress.Equals(dstAddress, StringComparison.OrdinalIgnoreCase));
        IReadOnlyList<string> words = existing == null
            ? ["/ip/route/add", $"=dst-address={dstAddress}", $"=gateway={gateway}", $"=distance={distance}", "=disabled=no"]
            : ["/ip/route/set", $"=.id={existing.Id}", $"=gateway={gateway}", $"=distance={distance}", "=disabled=no"];
        var response = await ExecuteAsync(words, cancellationToken);
        ThrowIfError(response);
    }

    public async Task SetUserPasswordAsync(string userName, string password, CancellationToken cancellationToken)
    {
        var response = await ExecuteAsync(["/user/print", "=.proplist=.id,name", $"?name={userName}"], cancellationToken);
        ThrowIfError(response);
        var id = response.FirstOrDefault(sentence => sentence.Type == "!re")?.Attributes.GetValueOrDefault(".id");
        if (string.IsNullOrWhiteSpace(id)) throw new InvalidOperationException($"Користувача {userName} не знайдено.");
        response = await ExecuteAsync(["/user/set", $"=.id={id}", $"=password={password}"], cancellationToken);
        ThrowIfError(response);
    }

    private async Task<List<ApiSentence>> ExecuteAsync(IReadOnlyList<string> words, CancellationToken cancellationToken)
    {
        if (_stream == null) throw new InvalidOperationException("API-сесію не підключено.");
        await _requestLock.WaitAsync(cancellationToken);
        try
        {
            foreach (var word in words) await WriteWordAsync(_stream, word, cancellationToken);
            await WriteLengthAsync(_stream, 0, cancellationToken);
            await _stream.FlushAsync(cancellationToken);

            var result = new List<ApiSentence>();
            while (true)
            {
                var sentence = await ReadSentenceAsync(_stream, cancellationToken);
                if (sentence.Count == 0) continue;
                var parsed = ParseSentence(sentence);
                result.Add(parsed);
                if (parsed.Type is "!done" or "!fatal") return result;
            }
        }
        catch (IOException ex) { throw new InvalidOperationException("З'єднання з RouterOS було закрито.", ex); }
        finally { _requestLock.Release(); }
    }

    private static void ThrowIfError(IEnumerable<ApiSentence> response)
    {
        var error = response.FirstOrDefault(sentence => sentence.Type is "!trap" or "!fatal");
        if (error == null) return;
        throw new InvalidOperationException(error.Attributes.GetValueOrDefault("message") ?? "RouterOS відхилив команду.");
    }

    private static ApiSentence ParseSentence(IReadOnlyList<string> words)
    {
        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var word in words.Skip(1))
        {
            if (!word.StartsWith('=')) continue;
            var separator = word.IndexOf('=', 1);
            if (separator > 1) attributes[word[1..separator]] = word[(separator + 1)..];
        }
        return new ApiSentence(words[0], attributes);
    }

    private static async Task WriteWordAsync(Stream stream, string word, CancellationToken cancellationToken)
    {
        var bytes = Encoding.UTF8.GetBytes(word);
        await WriteLengthAsync(stream, bytes.Length, cancellationToken);
        await stream.WriteAsync(bytes, cancellationToken);
    }

    private static async Task WriteLengthAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        byte[] bytes = length switch
        {
            < 0x80 => [(byte)length],
            < 0x4000 => [(byte)((length >> 8) | 0x80), (byte)length],
            < 0x200000 => [(byte)((length >> 16) | 0xC0), (byte)(length >> 8), (byte)length],
            < 0x10000000 => [(byte)((length >> 24) | 0xE0), (byte)(length >> 16), (byte)(length >> 8), (byte)length],
            _ => [0xF0, (byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length]
        };
        await stream.WriteAsync(bytes, cancellationToken);
    }

    private static async Task<List<string>> ReadSentenceAsync(Stream stream, CancellationToken cancellationToken)
    {
        var words = new List<string>();
        while (true)
        {
            var length = await ReadLengthAsync(stream, cancellationToken);
            if (length == 0) return words;
            var bytes = new byte[length];
            await stream.ReadExactlyAsync(bytes, cancellationToken);
            words.Add(Encoding.UTF8.GetString(bytes));
        }
    }

    private static async Task<int> ReadLengthAsync(Stream stream, CancellationToken cancellationToken)
    {
        var first = await ReadByteAsync(stream, cancellationToken);
        if ((first & 0x80) == 0) return first;
        if ((first & 0xC0) == 0x80) return ((first & 0x3F) << 8) | await ReadByteAsync(stream, cancellationToken);
        if ((first & 0xE0) == 0xC0) return ((first & 0x1F) << 16) | await ReadByteAsync(stream, cancellationToken) << 8 | await ReadByteAsync(stream, cancellationToken);
        if ((first & 0xF0) == 0xE0) return ((first & 0x0F) << 24) | await ReadByteAsync(stream, cancellationToken) << 16 | await ReadByteAsync(stream, cancellationToken) << 8 | await ReadByteAsync(stream, cancellationToken);
        if (first == 0xF0) return await ReadByteAsync(stream, cancellationToken) << 24 | await ReadByteAsync(stream, cancellationToken) << 16 | await ReadByteAsync(stream, cancellationToken) << 8 | await ReadByteAsync(stream, cancellationToken);
        throw new InvalidDataException("RouterOS вернул некорректную длину API-слова.");
    }

    private static async Task<int> ReadByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        if (await stream.ReadAsync(buffer, cancellationToken) != 1) throw new EndOfStreamException();
        return buffer[0];
    }

    public async ValueTask DisposeAsync()
    {
        if (_stream != null) await _stream.DisposeAsync();
        _tcpClient.Dispose(); _requestLock.Dispose();
    }

    private sealed record ApiSentence(string Type, Dictionary<string, string> Attributes);
}
