using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace CryptoTool.Dialogues
{
    /// <summary>
    /// Interaction logic for PasswordDialogue.xaml
    /// </summary>
    public partial class PasswordDialogue : Window
    {
        public string Result { get { return textBoxPassword.Text; } }

        public PasswordDialogue()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}