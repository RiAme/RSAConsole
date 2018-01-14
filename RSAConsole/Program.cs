using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.IO;

namespace RSAConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            //Byte block size for decryption
            List<int> blockSizeList = new List<int>();

            BigInteger p = RSA.GenerateKey(64);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Число p:\n {0}", p);

            BigInteger q = RSA.GenerateKey(64);
            Console.WriteLine("Число q:\n {0}", q);

            BigInteger r = RSA.GetR(p,q);
            Console.WriteLine("Число r:\n {0}", r);
            Console.WriteLine();
            BigInteger e = RSA.GenerateOpenKey(p, q);
            Console.WriteLine("Число e:\n {0}", e);
            Console.WriteLine();

            Console.ResetColor();
            Console.WriteLine("Число p длина: {0} bit", (p.ToByteArray().Length * 8));
            Console.WriteLine("Число q длина: {0} bit", (q.ToByteArray().Length * 8));
            Console.WriteLine("Число r длина: {0} bit", (r.ToByteArray().Length * 8));
            Console.WriteLine("Число e длина: {0} bit", (e.ToByteArray().Length * 8));
            Console.WriteLine();

            //encrypt text
            Console.WriteLine("Enter a path to *.txt file to be encrypted:");
            string ToBeEncrypted = Console.ReadLine();
            string EncryptedFile = "..\\debug\\encrypted.txt";

            byte[] textdata = null;

            using (FileStream stream = new FileStream(ToBeEncrypted, FileMode.Open, FileAccess.Read))
            {
                textdata =RSA.EncryptSreamBytes(stream, p, q, e, r, blockSizeList);
            }

            //write encrypted text to file
            File.WriteAllBytes(EncryptedFile, textdata);

            Console.WriteLine();
            Console.WriteLine("Path to the encrypted file: {0}", Path.GetFullPath(EncryptedFile));
            Console.WriteLine();
            Console.WriteLine("Encrypted content:\n");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(textdata, 0, textdata.Length));
            Console.ResetColor();
            Console.WriteLine();

            //decrypt text
            string DecryptedFile = "..\\debug\\decrypted.txt";

            byte[] decrypted = null;
            using (FileStream stream = new FileStream(EncryptedFile, FileMode.Open, FileAccess.Read))
            {
                decrypted = RSA.DecruptStreamBytes(stream, p, q,e,r, blockSizeList);
            }

            //write encrypted text to file
            File.WriteAllBytes(DecryptedFile, decrypted);

            Console.WriteLine("Path to the decrypted file: {0}", Path.GetFullPath(DecryptedFile));
            Console.WriteLine();
            Console.WriteLine("Decrypted content:\n");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(decrypted, 0, decrypted.Length));
            Console.ResetColor();

            Console.ReadKey();
        }
    }
}
