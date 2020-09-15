using CryptoHelpers;
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
    /// Interaction logic for KeyImportDialogue.xaml
    /// </summary>
    public partial class KeyImportDialogue : Window
    {
        public RsaKeyPair Result = null;

        public KeyImportDialogue()
        {
            InitializeComponent();
        }

        private void cancelButton_Click(object sender, RoutedEventArgs e)
        {
            Result = null;
            this.Close();
        }

        private void importButton_Click(object sender, RoutedEventArgs e)
        {
            RsaKeyPair result = new RsaKeyPair()
            {
                PublicKey = publicTextBox.Text,
                PrivateKey = privateTextBox.Text,
                Timestamp = (int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds
            };

            bool error = false;

            if (Crypto.PublicKeyFromPem(result.PublicKey) == null)
            {
                Result = null;
                error = true;
                errorTextBlock.Visibility = Visibility.Visible;
            }

            if (!result.PublicOnly && Crypto.PrivateKeyFromPem(result.PrivateKey) == null)
            {
                Result = null;
                error = true;
                errorTextBlock.Visibility = Visibility.Visible;
            }

            if (!error)
            {
                Result = result;
                this.Close();
            }
        }

        private void publicTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            Result = null;
            errorTextBlock.Visibility = Visibility.Hidden;
        }

        private void privateTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            Result = null;
            errorTextBlock.Visibility = Visibility.Hidden;
        }
    }
}