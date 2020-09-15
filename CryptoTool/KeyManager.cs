using CryptoHelpers;
using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;

namespace CryptoTool
{
    internal static class KeyManager
    {
        public static bool Initialized = false;

        public readonly static List<RsaKeyPair> Keys = new List<RsaKeyPair>();

        private static string path;
        private static RsaKeyPair masterKey = null;
        private static byte[] salt = null;

        public static void Initialize(string Password)
        {
            if (Initialized) { return; }

            path = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData) + @"\OradeTech\CryptoTool\Keys";

            if (!System.IO.Directory.Exists(path))
            {
                System.IO.Directory.CreateDirectory(path);
            }

            salt = System.Text.Encoding.UTF8.GetBytes(Password);
            masterKey = Crypto.RsaKeysFromPassword(Password, salt);

            var files = System.IO.Directory.GetFiles(path);

            foreach (string keyFile in files)
            {
                try
                {
                    byte[] buffer = System.IO.File.ReadAllBytes(keyFile);
                    byte[] decrypted = Crypto.RsaDecrypt(masterKey.PrivateCsp, buffer);
                    string json = System.Text.Encoding.UTF8.GetString(decrypted);
                    RsaKeyPair key = RsaKeyPair.FromJson(json);
                    Keys.Add(key);
                }
                catch
                {
                    Console.WriteLine("Failed to load key");
                }
            }

            Initialized = true;
        }

        public static void GenerateKey()
        {
            string seed = new Random().Next().ToString();
            var newKey = Crypto.RsaGenerateKeyPair(null);
            SaveKey(newKey);
        }

        public static void SaveKey(RsaKeyPair Key)
        {
            string json = Key.ToJson();
            byte[] bytes = Crypto.RsaEncrypt(masterKey.PublicCsp, System.Text.Encoding.UTF8.GetBytes(json));

            string filename = $"{path}\\{Key.Hash.Replace("+", "").Replace("=", "").Replace("/", "").Substring(0, 16)}.key";
            if (System.IO.File.Exists(filename))
            {
                System.IO.File.Delete(filename);
            }
            System.IO.File.WriteAllBytes(filename, bytes);
        }
    }
}