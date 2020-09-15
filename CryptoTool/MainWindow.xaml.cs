using CryptoHelpers;
using CryptoTool.Dialogues;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace CryptoTool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            PasswordDialogue d = new PasswordDialogue();
            d.ShowDialog();
            KeyManager.Initialize(d.Result);

            if (KeyManager.Keys.Count > 0)
            {
                MessageBox.Show($"Loaded {KeyManager.Keys.Count} keys");
            }
            else
            {
                MessageBox.Show("Loaded no keys");
            }

            identityComboBox.Items.Clear();

            foreach (var key in KeyManager.Keys)
            {
                if (string.IsNullOrWhiteSpace(key.Note))
                {
                    identityComboBox.Items.Add(key.Hash.Substring(0, 16) + (key.PublicOnly ? " (Public Only)" : ""));
                }
                else
                {
                    identityComboBox.Items.Add(key.Note + (key.PublicOnly ? " (Public Only) " : " ") + key.Hash.Substring(0, 16));
                }
            }

            keysDataGrid.ItemsSource = KeyManager.Keys;
        }

        private void manageKeysButton_Click(object sender, RoutedEventArgs e)
        {
        }

        private void keysSaveButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (RsaKeyPair key in KeyManager.Keys)
            {
                KeyManager.SaveKey(key);
            }
            keysDataGrid.ItemsSource = null;
            keysDataGrid.ItemsSource = KeyManager.Keys;

            identityComboBox.Items.Clear();

            foreach (var key in KeyManager.Keys)
            {
                if (string.IsNullOrWhiteSpace(key.Note))
                {
                    identityComboBox.Items.Add(key.Hash.Substring(0, 16) + (key.PublicOnly ? " (Public Only)" : ""));
                }
                else
                {
                    identityComboBox.Items.Add(key.Note + (key.PublicOnly ? " (Public Only) " : " ") + key.Hash.Substring(0, 16));
                }
            }
        }

        private void keysImportButton_Click(object sender, RoutedEventArgs e)
        {
            KeyImportDialogue d = new KeyImportDialogue();
            d.ShowDialog();
            if (d.Result != null)
            {
                KeyManager.Keys.Add(d.Result);
            }
            keysSaveButton_Click(null, null);
        }

        private void keysGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            var newKey = Crypto.RsaGenerateKeyPair(null);
            KeyManager.Keys.Add(newKey);
            keysSaveButton_Click(null, null);
        }

        private void messageTabItem_GotFocus(object sender, RoutedEventArgs e)
        {
        }

        private void mainTabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
        }

        private bool editingPlaintext = false;
        private bool editingCiphertext = false;
        private bool lastPlaintext = true;

        private void plaintextTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!editingCiphertext && !string.IsNullOrWhiteSpace(plaintextTextBox.Text))
            {
                lastPlaintext = true;
                editingPlaintext = true;
                if (identityComboBox.SelectedIndex != -1)
                {
                    RsaKeyPair selectedKey = KeyManager.Keys[identityComboBox.SelectedIndex];

                    byte[] buffer = Crypto.RsaEncrypt(selectedKey.PublicCsp, System.Text.Encoding.UTF8.GetBytes(plaintextTextBox.Text));

                    string cipher = $"[{selectedKey.Hash.Substring(0, 16)}]\n{Convert.ToBase64String(buffer)}";

                    ciphertextTextBox.Text = cipher;
                    arrowRight.Visibility = Visibility.Visible;
                    arrowLeft.Visibility = Visibility.Collapsed;
                }
            }

            editingPlaintext = false;
        }

        private void ciphertextTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!editingPlaintext && !string.IsNullOrWhiteSpace(ciphertextTextBox.Text))
            {
                lastPlaintext = false;
                editingCiphertext = true;

                if (identityComboBox.SelectedIndex != -1)
                {
                    RsaKeyPair selectedKey = KeyManager.Keys[identityComboBox.SelectedIndex];

                    if (!selectedKey.PublicOnly)
                    {
                        string cipher = ciphertextTextBox.Text.Split(new char[] { ']', '[' }, StringSplitOptions.RemoveEmptyEntries).Last();
                        cipher = cipher.Replace("\n", "");

                        string error = string.Empty;
                        byte[] cipherBytes = null;
                        try
                        {
                            cipherBytes = Convert.FromBase64String(cipher);
                        }
                        catch
                        {
                            error = "Invalid Base64";
                        }

                        string plain = "";
                        if (string.IsNullOrWhiteSpace(error))
                        {
                            try
                            {
                                plain = System.Text.Encoding.UTF8.GetString(Crypto.RsaDecrypt(selectedKey.PrivateCsp, cipherBytes));
                            }
                            catch
                            {
                                error = "Decryption Failure";
                            }
                        }

                        if (string.IsNullOrWhiteSpace(error))
                        {
                            plaintextTextBox.Text = plain;
                            arrowRight.Visibility = Visibility.Collapsed;
                            arrowLeft.Visibility = Visibility.Visible;
                            errorTextBlock.Visibility = Visibility.Collapsed;
                        }
                        else
                        {
                            errorTextBlock.Visibility = Visibility.Visible;
                            errorTextBlock.Text = error;
                        }
                    }
                }
            }

            editingCiphertext = false;
        }

        private void identityComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (lastPlaintext)
            {
                plaintextTextBox_TextChanged(null, null);
            }
            else
            {
                ciphertextTextBox_TextChanged(null, null);
            }
        }

        private void exportButton_Click(object sender, RoutedEventArgs e)
        {
            RsaKeyPair key = ((Button)e.OriginalSource).DataContext as RsaKeyPair;

            Microsoft.Win32.SaveFileDialog dlg = new Microsoft.Win32.SaveFileDialog();
            dlg.FileName = MakeValidFileName((string.IsNullOrWhiteSpace(key.Note) ? "" : key.Note + ".") + (key.PublicOnly ? "Public." : "") + key.Hash.Substring(0, 16));//key.Hash.Substring(0,16);
            dlg.Filter = "JSON (.json)|*.json|plain text (*.txt)|*.txt|All files (*.*)|*.*";
            dlg.FilterIndex = 1;
            dlg.RestoreDirectory = true;
            dlg.Title = "Export Key";

            if (dlg.ShowDialog() == true)
            {
                try
                {
                    if (System.IO.File.Exists(dlg.FileName))
                    {
                        System.IO.File.Delete(dlg.FileName);
                    }

                    if (dlg.FileName.EndsWith(".JSON", StringComparison.InvariantCultureIgnoreCase))
                    {
                        System.IO.File.WriteAllText(dlg.FileName, key.ToJson());
                    }
                    else
                    {
                        string text = key.PublicKey;
                        if (!key.PublicOnly)
                        {
                            text += "\n" + key.PrivateKey;
                        }
                        text += "\n";
                        System.IO.File.WriteAllText(dlg.FileName, text);
                    }

                    MessageBox.Show("File saved", "Success", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Encountered an error while trying to write to\n{dlg.FileName}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private static string MakeValidFileName(string name)
        {
            string invalidChars = System.Text.RegularExpressions.Regex.Escape(new string(System.IO.Path.GetInvalidFileNameChars()));
            string invalidRegStr = string.Format(@"([{0}]*\.+$)|([{0}]+)", invalidChars);

            return System.Text.RegularExpressions.Regex.Replace(name, invalidRegStr, "_");
        }
    }
}