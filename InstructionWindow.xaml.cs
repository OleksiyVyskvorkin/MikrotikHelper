using System.Windows;

namespace MikrotikHelper;

public partial class InstructionWindow : Window
{
    public InstructionWindow() => InitializeComponent();

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
