using System.Net;
using System.Net.Sockets;
using System.Windows;

namespace MikrotikHelper;

public partial class EndpointWindow : Window
{
    public string Endpoint { get; private set; }

    public EndpointWindow(string endpoint)
    {
        InitializeComponent();
        Endpoint = endpoint;
        EndpointBox.Text = endpoint;
        Loaded += (_, _) => { EndpointBox.Focus(); EndpointBox.SelectAll(); };
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var value = EndpointBox.Text.Trim();
        if (!IPAddress.TryParse(value, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
        {
            ErrorText.Text = "Введіть коректну публічну IPv4-адресу.";
            return;
        }
        Endpoint = value;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
