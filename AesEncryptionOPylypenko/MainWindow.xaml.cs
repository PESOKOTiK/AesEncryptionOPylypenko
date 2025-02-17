using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
namespace AesEncryptionOPylypenko
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string plaintext = PlaintextInput.Text;
            string key = KeyInput.Text;
            string mode = ModeSelection.Text;
            string IV = IVInput.Text;
            byte[] encrypted = Encrypt(plaintext, key, mode, IV);
            File.WriteAllBytes("encrypted.txt", encrypted);
            ResultField.Text = Convert.ToBase64String(encrypted);
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            string key = KeyInput.Text;
            string mode = ModeSelection.Text;
            string IV = IVInput.Text;
            if (!File.Exists("encrypted.txt"))
            {
                MessageBox.Show("No encrypted file found.");
                return;
            }

            byte[] encrypted = File.ReadAllBytes("encrypted.txt");
            string decrypted = Decrypt(encrypted, key, mode, IV);
            ResultField.Text = decrypted;
        }

        private byte[] Encrypt(string plaintext, string key, string mode, string IV)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = GenerateKey(key);
                aes.IV = ConvertStringToByteArray(IV);
                MessageBox.Show("IV=  "+Convert.ToBase64String(aes.IV));
                aes.Mode = GetCipherMode(mode);

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(plaintext);
                    return encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                }
            }
        }

        private string Decrypt(byte[] cipherText, string key, string mode, string IV)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = GenerateKey(key);
                aes.IV = ConvertStringToByteArray(IV);
                aes.Mode = GetCipherMode(mode);

                using (var decryptor = aes.CreateDecryptor())
                {
                    try {
                        byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                    catch (CryptographicException)
                    {
                        MessageBox.Show("Decryption failed. Make sure you are using the correct key and mode.");
                        return "error";
                    }
                    
                }
            }
        }

        private CipherMode GetCipherMode(string mode)
        {
            return mode switch
            {
                "ECB" => CipherMode.ECB,
                "CBC" => CipherMode.CBC,
                "CFB" => CipherMode.CFB,
                _ => CipherMode.CBC
            };
        }

        private byte[] GenerateKey(string key)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            }
        }
        private byte[] ConvertStringToByteArray(string input)
        {
            byte[] byteArray = new byte[16];
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            Array.Copy(inputBytes, byteArray, Math.Min(byteArray.Length, inputBytes.Length));
            return byteArray;
        }
    }
}