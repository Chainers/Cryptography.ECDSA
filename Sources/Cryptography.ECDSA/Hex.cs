using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace Cryptography.ECDSA
{
    public static class Hex
    {
        private static readonly string[] ByteToHex = new[]
        {
            "00", "01", "02", "03", "04", "05", "06", "07",
            "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
            "10", "11", "12", "13", "14", "15", "16", "17",
            "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
            "20", "21", "22", "23", "24", "25", "26", "27",
            "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
            "30", "31", "32", "33", "34", "35", "36", "37",
            "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
            "40", "41", "42", "43", "44", "45", "46", "47",
            "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
            "50", "51", "52", "53", "54", "55", "56", "57",
            "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
            "60", "61", "62", "63", "64", "65", "66", "67",
            "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
            "70", "71", "72", "73", "74", "75", "76", "77",
            "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
            "80", "81", "82", "83", "84", "85", "86", "87",
            "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
            "90", "91", "92", "93", "94", "95", "96", "97",
            "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
            "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
            "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
            "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
            "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
            "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
            "d8", "d9", "da", "db", "dc", "dd", "de", "df",
            "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
            "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
            "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
            "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"
        };

        private static readonly Dictionary<string, byte> HexToByte = new Dictionary<string, byte>();

        static Hex()
        {
            for (byte b = 0; b < 255; b++)
                HexToByte[ByteToHex[b]] = b;

            HexToByte["ff"] = 255;
        }

        public static string BigIntegerToHex(BigInteger value)
        {
            return BytesToHex(ToByteArrayUnsigned(value, true));
        }

        public static BigInteger HexToBigInteger(string hex)
        {
            if (NumberTheory.Mod(hex.Length, 2) != 0)
                hex = "0" + hex;

            hex = hex.ToLower();

            var bytes = new byte[hex.Length / 2 + 1];
            for (var i = 0; i < bytes.Length - 1; i++)
            {
                bytes[bytes.Length - 2 - i] = HexToByte[hex.Substring(i * 2, 2)];
            }

            return new BigInteger(bytes);
        }

        public static BigInteger HexToBigInteger(byte[] hex)
        {
            var bytes = new byte[hex.Length + 1];
            for (var i = 0; i < hex.Length; i++)
            {
                bytes[i] = hex[hex.Length - i - 1];
            }
            return new BigInteger(bytes);
        }

        public static int HexToInteger(byte[] hex)
        {
            var result = 0;
            for (var i = 0; i < hex.Length; i++)
            {
                result = (result << 8) | hex[i];
            }
            return result;
        }

        public static string BytesToHex(byte[] bytes)
        {
            var hex = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                hex.Append(ByteToHex[b]);
            }

            return hex.ToString();
        }

        public static byte[] HexToBytes(string hex)
        {
            if (NumberTheory.Mod(hex.Length, 2) != 0)
                hex = "0" + hex;

            hex = hex.ToLower();

            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < hex.Length / 2; i++)
            {
                bytes[i] = HexToByte[hex.Substring(i * 2, 2)];
            }

            return bytes;
        }

        public static string AsciiToHex(string ascii)
        {
            var chars = ascii.ToCharArray();
            var hex = new StringBuilder(ascii.Length);

            foreach (var currentChar in chars)
            {
                hex.Append(String.Format("{0:X}", Convert.ToInt32(currentChar)));
            }

            return hex.ToString();
        }

        public static byte[] Join(params byte[][] values)
        {
            var len = values.Sum(i => i.Length);
            var rez = new byte[len];
            var k = 0;
            for (var i = 0; i < values.Length; i++)
            {
                var source = values[i];
                if (source.Length == 0)
                    continue;
                Array.Copy(source, 0, rez, k, source.Length);
                k += source.Length;
            }
            return rez;
        }
        
        public static byte[] ToByteArrayUnsigned(BigInteger i, bool reverse)
        {
            var bytes = i.ToByteArray();
            if (bytes[bytes.Length - 1] == 0x00)
                Array.Resize(ref bytes, bytes.Length - 1);
            if (reverse)
                Array.Reverse(bytes, 0, bytes.Length);

            return bytes;
        }

        internal static byte[] IntToBytes(int n)
        { 
            //get array len
            var i = 1;
            var k = n;
            while (k >= 0x80)
            {
                k >>= 7;
                i++;
            }

            var data = new byte[i];
            i = 0;

            while (n >= 0x80)
            {
                data[i++] = (byte)(0x80 | (n & 0x7f));
                n >>= 7;
            }

            data[i] += (byte)n;
            return data;
        }

        public static byte[] ToByteArrayUnsigned(long value, bool reverse = true)
        {
            if (value == 0)
                return new byte[1];

            var s = BitConverter.GetBytes(value);
            var bLen = s.Length;

            for (var i = s.Length - 1; i >= 0; i--)
            {
                if (s[i] == 0)
                    bLen = i;
                else
                    break;
            }

            if (reverse)
            {
                var buf = new byte[bLen];
                for (var i = 0; i < buf.Length; i++)
                {
                    buf[buf.Length - i - 1] = s[i];
                }
                s = buf;
            }
            else
            {
                if (bLen < s.Length)
                {
                    var buf = new byte[bLen];
                    Array.Copy(s, buf, bLen);
                    s = buf;
                }
            }
            return s;
        }

        public static bool TestBit(BigInteger i, int n)
        {
            return !(i >> n).IsEven;
        }

        public static int BitLength(BigInteger i)
        {
            if (i.IsZero)
                return 0;

            var length = 0;
            do
            {
                length++;
            } while (!(i >>= 1).IsZero);
            return length;
        }

        public static int ByteLength(BigInteger i)
        {
            var length = 0;
            do
            {
                length++;
            } while (!(i >>= 8).IsZero);
            return length;
        }

        public static T[] SkipTake<T>(T[] value, int skip, int take)
        {
            take = Math.Min(value.Length - skip, take);
            var buf = new T[take];
            Array.Copy(value, skip, buf, 0, take);
            return buf;
        }

        public static byte[] Skip(byte[] value, int count)
        {
            return SkipTake(value, count, value.Length - count);
        }

        public static string ToString(byte[] hex)
        {
            return string.Join(string.Empty, hex.Select(i => i.ToString("x2")));
        }
    }
}