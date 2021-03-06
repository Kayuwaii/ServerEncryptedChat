﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ServerEncryptedChat
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                IPAddress ipAd = IPAddress.Parse("172.17.1.241");
                // use local m/c IP address, and 
                // use the same in the client

                string EncryptionKey = GetHashedKey("Alexandros");
                //create Encryption Key to encrypt and Decrypt

                /* Initializes the Listener */
                TcpListener myList = new TcpListener(ipAd, 8001);

                /* Start Listeneting at the specified port */
                myList.Start();

                Console.WriteLine("The server is running at port 8001...");
                Console.WriteLine("The local End point is  :" +
                                  myList.LocalEndpoint);
                Console.WriteLine("Waiting for a connection.....");

                Socket s = myList.AcceptSocket();
                Console.WriteLine("Connection accepted from " + s.RemoteEndPoint);
                bool cntrl = true;
                while (cntrl)
                {
                    byte[] b = new byte[s.ReceiveBufferSize];
                    int k = s.Receive(b);
                    string msg = "";
                    Console.Write("Other:\t");
                    for (int i = 0; i < k; i++)
                    {
                        msg += Convert.ToChar(b[i]);
                    }
                    Console.WriteLine(TxtDecrypt(msg, EncryptionKey));

                    Console.Write("Me:\t");
                    string toSend = TxtEncrypt(Console.ReadLine(), EncryptionKey);
                    s.Send(Encoding.UTF8.GetBytes(toSend));
                }
                /* clean up */
                s.Close();
                myList.Stop();

            }
            catch (Exception e)
            {
                Console.WriteLine("Error..... " + e.StackTrace);
            }
            Console.ReadLine();
        }

        public static string GetHashedKey(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            string hashString = string.Empty;
            int cntr = 0;
            foreach (byte x in hash)
            {
                if (cntr == 1)
                {
                    cntr = 0;
                }
                else
                {
                    hashString += String.Format("{0:x2}", x);
                    cntr++;
                }
            }
            return hashString;
        }

        //Encrypting a string
        public static string TxtEncrypt(string inText, string key)
        {
            byte[] bytesBuff = Encoding.UTF8.GetBytes(inText);
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes crypto = new Rfc2898DeriveBytes(key, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                aes.Key = crypto.GetBytes(32);
                aes.IV = crypto.GetBytes(16);
                using (MemoryStream mStream = new MemoryStream())
                {
                    using (CryptoStream cStream = new CryptoStream(mStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cStream.Write(bytesBuff, 0, bytesBuff.Length);
                        cStream.Close();
                    }
                    inText = Convert.ToBase64String(mStream.ToArray());
                }
            }
            return inText;
        }

        //Decrypting a string
        public static string TxtDecrypt(string cryptTxt, string key)
        {
            cryptTxt = cryptTxt.Replace(" ", "+");
            cryptTxt = cryptTxt.Replace("\0", "");
            byte[] bytesBuff = Convert.FromBase64String(cryptTxt);
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes crypto = new Rfc2898DeriveBytes(key, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                aes.Key = crypto.GetBytes(32);
                aes.IV = crypto.GetBytes(16);
                using (MemoryStream mStream = new MemoryStream())
                {
                    using (CryptoStream cStream = new CryptoStream(mStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cStream.Write(bytesBuff, 0, bytesBuff.Length);
                        cStream.Close();
                    }
                    cryptTxt = Encoding.UTF8.GetString(mStream.ToArray());
                }
            }
            return cryptTxt;
        }
    }
}