using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoHelpers
{
    public static class Crypto
    {
        public static RsaKeyPair RsaKeysFromPassword(string Password, byte[] Salt)
        {
            byte[] pass = System.Text.Encoding.UTF32.GetBytes(Password);

            if (Salt == null)
            {
                RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
                byte[] salt = new byte[24];
                provider.GetBytes(salt);
                Salt = salt;
            }
            else if (Salt.Length < 24) // Pad the salt with 0x00
            {
                byte[] salt = new byte[24];
                Array.Copy(Salt, salt, Salt.Length);
                Salt = salt;
            }
            else if (Salt.Length > 24) // Truncate the salt to 24 bytes
            {
                byte[] salt = new byte[24];
                Array.Copy(Salt, salt, salt.Length);
                Salt = salt;
            }

            // Generate the hash
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(pass, Salt, 100000);
            pass = pbkdf2.GetBytes(24);

            RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
            var rng = new Org.BouncyCastle.Security.SecureRandom(pass);
            rsaGenerator.Init(new KeyGenerationParameters(rng, 2048));
            var keyPair = rsaGenerator.GenerateKeyPair();
            string privatePem = "";
            string publicPem = "";

            using (TextWriter privateKeyTextWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(privateKeyTextWriter);
                pemWriter.WriteObject(keyPair.Private);
                pemWriter.Writer.Flush();
                privatePem = privateKeyTextWriter.ToString();
            }

            using (TextWriter publicKeyTextWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(publicKeyTextWriter);
                pemWriter.WriteObject(keyPair.Public);
                pemWriter.Writer.Flush();
                publicPem = publicKeyTextWriter.ToString();
            }

            return new RsaKeyPair()
            {
                PublicKey = publicPem,
                PrivateKey = privatePem,
                Timestamp = (int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds
            };
        }

        public static RsaKeyPair RsaGenerateKeyPair(byte[] Seed)
        {
            RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
            string privatePem = "";
            string publicPem = "";
            var rng = new SecureRandom();
            byte[] seed = Seed;
            if (seed == null) { seed = rng.GenerateSeed(4096); }
            //rng.SetSeed(seed);
            rng = new SecureRandom(seed);
            rsaGenerator.Init(new KeyGenerationParameters(rng, 2048));
            var keyPair = rsaGenerator.GenerateKeyPair();

            //if (!Directory.Exists(privateKeyFilePath)) { Directory.CreateDirectory(privateKeyFilePath); }
            using (TextWriter privateKeyTextWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(privateKeyTextWriter);
                pemWriter.WriteObject(keyPair.Private);
                pemWriter.Writer.Flush();
                //File.WriteAllText(privateKeyFilePath + hash + ".private.pem", privateKeyTextWriter.ToString());
                privatePem = privateKeyTextWriter.ToString();
            }

            //if (!Directory.Exists(publicKeyFilePath)) { Directory.CreateDirectory(publicKeyFilePath); }
            using (TextWriter publicKeyTextWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(publicKeyTextWriter);
                pemWriter.WriteObject(keyPair.Public);
                pemWriter.Writer.Flush();

                //File.WriteAllText(publicKeyFilePath + hash + ".public.pem", publicKeyTextWriter.ToString());
                publicPem = publicKeyTextWriter.ToString();
            }

            return new RsaKeyPair()
            {
                PublicKey = publicPem,
                PrivateKey = privatePem,
                Timestamp = (int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds
            };
        }

        public static RSACryptoServiceProvider PrivateKeyFromPem(string PrivatePem)
        {
            using (TextReader privateKeyTextReader = new StringReader(PrivatePem))
            {
                AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair)new PemReader(privateKeyTextReader).ReadObject();
                if (readKeyPair == null) { return null; }

                RsaPrivateCrtKeyParameters privateKeyParams = (RsaPrivateCrtKeyParameters)readKeyPair.Private;
                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned();
                parms.P = privateKeyParams.P.ToByteArrayUnsigned();
                parms.Q = privateKeyParams.Q.ToByteArrayUnsigned();
                parms.DP = privateKeyParams.DP.ToByteArrayUnsigned();
                parms.DQ = privateKeyParams.DQ.ToByteArrayUnsigned();
                parms.InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned();
                parms.D = privateKeyParams.Exponent.ToByteArrayUnsigned();
                parms.Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned();

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }

        public static RSACryptoServiceProvider PublicKeyFromPem(string PrivatePem)
        {
            using (TextReader publicKeyTextReader = new StringReader(PrivatePem))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();
                if (publicKeyParam == null) { return null; }

                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
                parms.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }

        public static RSACryptoServiceProvider KeyPairFromPem(string PublicPem, string PrivatePem)
        {
            RSAParameters parms = new RSAParameters();
            RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();

            using (TextReader privateKeyTextReader = new StringReader(PrivatePem))
            {
                AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair)new PemReader(privateKeyTextReader).ReadObject();
                if (readKeyPair == null) { return null; }

                RsaPrivateCrtKeyParameters privateKeyParams = ((RsaPrivateCrtKeyParameters)readKeyPair.Private);

                parms.Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned();
                parms.P = privateKeyParams.P.ToByteArrayUnsigned();
                parms.Q = privateKeyParams.Q.ToByteArrayUnsigned();
                parms.DP = privateKeyParams.DP.ToByteArrayUnsigned();
                parms.DQ = privateKeyParams.DQ.ToByteArrayUnsigned();
                parms.InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned();
                parms.D = privateKeyParams.Exponent.ToByteArrayUnsigned();
                parms.Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned();
            }

            using (TextReader publicKeyTextReader = new StringReader(PublicPem))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();

                parms.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
                parms.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();
            }

            cryptoServiceProvider.ImportParameters(parms);

            return cryptoServiceProvider;
        }

        public static byte[] RsaEncrypt(RSACryptoServiceProvider PublicKey, byte[] Plaintext)
        {
            int segmentLength = ((PublicKey.KeySize - 384) / 8) + 37;
            int offset = 0;
            int encryptedLength = 0;
            Queue<byte[]> segments = new Queue<byte[]>();

            while (offset < Plaintext.Length)
            {
                byte[] segment = new byte[Math.Min(segmentLength, Plaintext.Length - offset)];
                Array.Copy(Plaintext, offset, segment, 0, segment.Length);
                offset += segmentLength;

                segment = PublicKey.Encrypt(segment, false);
                encryptedLength += segment.Length;

                segments.Enqueue(segment);
            }

            byte[] cyphertext = new byte[encryptedLength];
            offset = 0;
            while (segments.Count > 0)
            {
                byte[] segment = segments.Dequeue();
                Array.Copy(segment, 0, cyphertext, offset, segment.Length);
                offset += segment.Length;
            }

            return cyphertext;
        }

        public static byte[] RsaDecrypt(RSACryptoServiceProvider PrivateKey, byte[] Cyphertext)
        {
            Console.WriteLine(Convert.ToBase64String(PrivateKey.ExportRSAPrivateKey()));
            int segmentLength = 256;
            int offset = 0;
            int decryptedLength = 0;
            Queue<byte[]> segments = new Queue<byte[]>();

            while (offset < Cyphertext.Length)
            {
                byte[] segment = new byte[256];
                Array.Copy(Cyphertext, offset, segment, 0, segment.Length);
                offset += segmentLength;

                segment = PrivateKey.Decrypt(segment, false);
                decryptedLength += segment.Length;

                segments.Enqueue(segment);
            }

            byte[] plaintext = new byte[decryptedLength];
            offset = 0;
            while (segments.Count > 0)
            {
                byte[] segment = segments.Dequeue();
                Array.Copy(segment, 0, plaintext, offset, segment.Length);
                offset += segment.Length;
            }

            return plaintext;
        }

        public static HybridCryptoDocument HybridEncrypt(RSACryptoServiceProvider PublicKey, byte[] Plaintext)
        {
            byte[] aesKey;
            byte[] aesIv;
            byte[] aesCiphertext;

            using (AesCryptoServiceProvider myAes = new AesCryptoServiceProvider())
            {
                myAes.KeySize = 256;
                myAes.GenerateKey();
                myAes.GenerateIV();
                aesKey = myAes.Key;
                aesIv = myAes.IV;
                ICryptoTransform encryptor = myAes.CreateEncryptor(myAes.Key, myAes.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(Plaintext);
                        aesCiphertext = msEncrypt.ToArray();
                    }
                }
            }

            byte[] encryptedKey = PublicKey.Encrypt(aesKey, false);
            byte[] encryptedIv = PublicKey.Encrypt(aesIv, false);

            return new HybridCryptoDocument()
            {
                EncryptedKey = encryptedKey,
                EncryptedIV = encryptedIv,
                Payload = aesCiphertext
            };
        }

        public static byte[] HybridDecrypt(RSACryptoServiceProvider PrivateKey, HybridCryptoDocument Ciphertext)
        {
            byte[] aesKey = PrivateKey.Decrypt(Ciphertext.EncryptedKey, false);
            byte[] aesIv = PrivateKey.Decrypt(Ciphertext.EncryptedIV, false);
            byte[] plaintext;

            using (AesCryptoServiceProvider myAes = new AesCryptoServiceProvider())
            {
                myAes.Key = aesKey;
                myAes.IV = aesIv;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = myAes.CreateDecryptor(myAes.Key, myAes.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(Ciphertext.Payload))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        csDecrypt.Write(Ciphertext.Payload, 0, Ciphertext.Payload.Length);
                        plaintext = msDecrypt.ToArray();
                    }
                }
            }

            return plaintext;
        }

        public struct HybridCryptoDocument
        {
            public byte[] EncryptedKey;
            public byte[] EncryptedIV;
            public byte[] Payload;
            public static byte[] SOP = new byte[] { 0x13, 0x37, 0x42, 0x42 };
            public static byte[] EOP = new byte[] { 0xB1, 0x6B, 0x00, 0xB5 };
        }
    }

    public class RsaKeyPair
    {
        public string PublicKey { get; set; } = "";
        public string PrivateKey { get; set; } = "";
        public int Timestamp { get; set; } = -1;
        public bool Outdated { get; set; } = false;
        public string Note { get; set; } = "";

        [JsonIgnore]
        public byte[] HashBytes
        {
            get
            {
                using (SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider())
                {
                    return sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(PublicKey));
                }
            }
        }

        public string Hash
        {
            get
            {
                return Convert.ToBase64String(HashBytes);
            }
        }

        [JsonIgnore]
        public RSACryptoServiceProvider PublicCsp
        {
            get { return Crypto.PublicKeyFromPem(PublicKey); }
        }

        [JsonIgnore]
        public RSACryptoServiceProvider PrivateCsp
        {
            get { return Crypto.PrivateKeyFromPem(PrivateKey); }
        }

        [JsonIgnore]
        public RSACryptoServiceProvider KeyPairCsp
        {
            get { return Crypto.KeyPairFromPem(PublicKey, PrivateKey); }
        }

        [JsonIgnore]
        public bool PublicOnly
        {
            get
            {
                return string.IsNullOrWhiteSpace(PrivateKey);
            }
            set { }
        }

        public string ToJson()
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            return JsonSerializer.Serialize(this, this.GetType(), options);
        }

        public static RsaKeyPair FromJson(string Json)
        {
            return JsonSerializer.Deserialize(Json, typeof(RsaKeyPair)) as RsaKeyPair;
        }
    }
}