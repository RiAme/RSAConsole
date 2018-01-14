using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Numerics;
using System.Threading;
using System.IO;
using System.Collections;

namespace RSAConsole
{
   public class RSA
    {

        public static BigInteger GenerateNumbers(int size)
        {
            //создать массив (64 byte)
            var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[size];
            //заполнить массив 
            rng.GetBytes(bytes);
            //создать число из массива
            BigInteger number = new BigInteger(bytes);
            //проверка на отрицательность
            if (number.Sign < 0)
            {
                number = GenerateNumbers(size);
            }

            return number;
        }

  
        public static BigInteger GenerateKey(int size)
        {
            BigInteger key = GenerateNumbers(size);

            //проверка на простоту
            while (!MillerRabinTest(key))
            {
                key = GenerateNumbers(size);
            }

            return key;
        }

        public static BigInteger EllerFunction(BigInteger p, BigInteger q)
        {
            var _ef = (p - 1) * (q - 1);
            return _ef;
        }

        public static BigInteger GetR(BigInteger p, BigInteger q)
        {
            BigInteger r = p * q;
            return r;
        }

  
        public static BigInteger GenerateOpenKey(BigInteger p, BigInteger q)
        {

            //число r
            BigInteger r = p * q;

            //функция эллера
            BigInteger ef = EllerFunction(p, q);

            bool b = true;
            var size = ef.ToByteArray().Length;
            BigInteger e = new Random().Next(1, size);
            while (b)
            {
                if (BigInteger.GreatestCommonDivisor(ef, e) != 1)
                    e = new Random().Next(1, size);
                else { b = false; }
            }
            return e;
        }

        public static BigInteger GeneratePrivateKey(BigInteger p, BigInteger q, BigInteger e)
        {
            //число r
            BigInteger r = p * q;

            //функция жллера 
            BigInteger ef = EllerFunction(p, q);

            //d - private key
            BigInteger d = ExtendedEuclidean(e, ef);

            return d;
        }


        #region Encryption

        public static byte[] EncryptSreamBytes(FileStream stream, BigInteger p, BigInteger q, BigInteger e, BigInteger r,  List<int> blockSizeList)
        {
            //список для массивов
            List<byte> outputBytes = new List<byte>();
            int offset = 0;
            stream.Position = 0;

            //чтение из файла
            while (true)
            {
                byte[] buffer = new byte[16];
                stream.Position = offset;
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0)
                {
                    break;
                }
                else
                {
                    BigInteger t = new BigInteger(buffer);

                    //зашифровать массив бит
                    buffer = Encrypt(p, q,e, r, buffer);

                    blockSizeList.Add(buffer.Length);

                    //добавить массив в список
                    outputBytes.AddRange(buffer);
                }

                //отступ
                offset += bytesRead;
            }
            return outputBytes.ToArray();
        }


        public static byte[] Encrypt(BigInteger p, BigInteger q, BigInteger e, BigInteger r,  byte[] arr)
        {
            //шифрование
            BigInteger bivalue = new BigInteger(arr);
            BigInteger result = BigInteger.ModPow(bivalue, e, r);
            return result.ToByteArray();
        }

        #endregion

        #region Decryption

        /// <returns></returns>
        public static byte[] DecruptStreamBytes(FileStream stream, BigInteger p, BigInteger q, BigInteger e, BigInteger r, List<int> blockSizeList)
        {
            //список для массива
            List<byte> outputBytes = new List<byte>();
            int offset = 0;
            stream.Position = 0;
            int i = 0;

            while (i != blockSizeList.Count)
            {
                byte[] buffer = new byte[blockSizeList.ElementAt(i)];
                stream.Position = offset;
                int bytesRead = stream.Read(buffer, 0, buffer.Length);

                if (bytesRead == 0)
                {
                    break;
                }
                else
                {

                    //дешифрование
                    BigInteger BIntbuffer = new BigInteger(buffer);

                   var result = Decrypt(BIntbuffer, p, q, e, r);
                    buffer = result.ToByteArray();

                    outputBytes.AddRange(buffer);
                }

                offset += bytesRead;
                i++;
            }
            return outputBytes.ToArray();
        }

        public static BigInteger Decrypt(BigInteger c, BigInteger p, BigInteger q, BigInteger e, BigInteger r)
        {
            BigInteger d = GeneratePrivateKey(p, q, e);

            BigInteger text = BigInteger.ModPow(c, d,r);

            return text;
        }



        /// расширенный алгоритм эвклида
        static BigInteger ExtendedEuclidean(BigInteger e, BigInteger ef)
        {

            BigInteger i = ef, d = 0, nod = 1;
            while (e > 0)
            {
                BigInteger t = i / e, x = e;
                e = i % x;
                i = x;
                x = nod;
                nod = d - t * x;
                d = x;
            }
            d %= ef;
            if (d < 0)
            {
                d = (d + ef) % ef;
            }              
            return d;
        }

        #endregion


        #region Corre Methods

        //проверка на простоту
        public static bool MillerRabinTest(BigInteger Number)
        {
            if (Number <= 2)
                throw new Exception("The number is less than 3");

            if (BigInteger.ModPow(Number, 1, 2) == 0)
                return false;

            int X = 1;
            BigInteger pow = 2;
            do
            {
                if (X < pow * 2 && pow >= X)
                    break;
                pow *= 2;
                X++;
            } while (true);

            BigInteger S, T;

            Step2(Number, out T, out S);

            //A cycle
            for (int i = 0; i < X; i++)
            {
                bool flagtoCycleA = false;
                BigInteger a = Rand(Number - 1);
                BigInteger x = BigInteger.ModPow(a, T, Number);
                if (x == 1 || x == Number - 1)
                    continue;
                //цикл Б
                for (int k = 0; k < (S - 1); k++)
                {
                    x = BigInteger.ModPow(x, 2, Number);
                    if (x == 1)
                        return false;
                    if (x == Number - 1)
                    {
                        flagtoCycleA = true;
                        break;
                    }


                }
                if (flagtoCycleA)
                    continue;
                return false;

            }

            return true;
        }


        /// <summary>
        /// Second step to find S and T
        /// </summary>
        /// <param name="P">A number</param>
        /// <param name="T">Remainder</param>
        /// <param name="S">The power of 2</param>
        static void Step2(BigInteger P, out BigInteger T, out BigInteger S)
        {
            BigInteger Pminus = P - 1;

            int Some2Pow = 0;

            do
            {
                if (Pminus % 2 == 0)
                {
                    Some2Pow++;
                    Pminus /= 2;
                }
                else
                {
                    T = Pminus;
                    S = Some2Pow;
                    return;
                }

            } while (true);

        }

        /// <summary>
        /// Gets rundom value from 1 to p
        /// </summary>
        /// <param name="p"></param>
        /// <returns>Returns a Biginteger value</returns>
        static BigInteger Rand(BigInteger p)
        {

            BigInteger result;
            string str = "";
            bool flag = true;

            int[] pio = (p + "").ToCharArray().Select(k => int.Parse(k + "")).ToArray();

            for (int i = 0; i < pio.Length; i++)
            {

                int x;
                if (flag)
                {
                    x = rnd.Next(1, pio[i] + 1);
                    if (x < pio[i])
                        flag = false;

                }
                else
                {
                    x = rnd.Next(1, 10);
                }

                str += x;
            }

            result = BigInteger.Parse(str);
            return result;
        }

        static Random rnd = new Random();

        #endregion
    }
}
