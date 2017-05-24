using System;
using System.Linq;
using System.Numerics;

namespace Cryptography.ECDSA
{
    /// <summary>
    /// Modified from CodesInChaos' public domain code
    /// https://gist.github.com/CodesInChaos/3175971
    /// </summary>
    public class Base58
    {
        public const int CheckSumSizeInBytes = 4;
        protected const string Hexdigits = "0123456789abcdefABCDEF";
        private const string Digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        public KnownPrefixes Prefix { get; set; }

        public byte[] Hex { get; set; }

        public enum KnownPrefixes
        {
            GPH,
            BTS,
            MUSE,
            TEST,
            STM,
            GLX,
            GLS,
        }


        public Base58(string data) : this(data, KnownPrefixes.GPH) { }

        public Base58(string data, KnownPrefixes prefix)
        {
            Prefix = prefix;
            if (data.All(Hexdigits.Contains))
            {
                Hex = ECDSA.Hex.HexToBytes(data);
            }
            else if (data[0] == '5' || data[0] == '6')
            {
                Hex = Base58CheckDecode(data);
            }
            else if (data[0] == 'K' || data[0] == 'L')
            {
                Hex = CutLastBytes(Base58CheckDecode(data), 1);
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        private byte[] CutLastBytes(byte[] source, int cutCount)
        {
            var rez = new byte[source.Length - cutCount];
            Array.Copy(source, rez, rez.Length);
            return rez;
        }

        private byte[] CutFirstBytes(byte[] source, int cutCount)
        {
            var rez = new byte[source.Length - cutCount];
            Array.Copy(source, cutCount, rez, 0, rez.Length);
            return rez;
        }

        private byte[] Base58CheckDecode(string data)
        {
            var s = Decode(data);
            var dec = CutLastBytes(s, 4);

            //var checksum = SHA256.Instance.DoubleHash(dec);
            //for (int i = 0; i < 4; i++)
            //    Assert.IsTrue(checksum[i] == s[s.Length - 4 + i]);

            return CutFirstBytes(dec, 1);
        }

        public static string EncodeWithCheckSum(byte[] data)
        {
            return Encode(AddCheckSum(data));
        }

        public static byte[] RemoveCheckSum(byte[] data)
        {
            var result = new byte[data.Length - CheckSumSizeInBytes];
            Buffer.BlockCopy(data, 0, result, 0, data.Length - CheckSumSizeInBytes);

            return result;
        }

        public static bool VerifyCheckSum(byte[] data)
        {
            var result = new byte[data.Length - CheckSumSizeInBytes];
            Buffer.BlockCopy(data, 0, result, 0, data.Length - CheckSumSizeInBytes);
            var correctCheckSum = GetCheckSum(result);
            for (var i = CheckSumSizeInBytes; i >= 1; i--)
            {
                if (data[data.Length - i] != correctCheckSum[CheckSumSizeInBytes - i])
                {
                    return false;
                }
            }
            return true;
        }

        public static bool DecodeWithCheckSum(string base58, out byte[] decoded)
        {
            var dataWithCheckSum = Decode(base58);
            var success = VerifyCheckSum(dataWithCheckSum);
            decoded = RemoveCheckSum(dataWithCheckSum);
            return success;
        }

        public static string Encode(byte[] data)
        {
            // Decode byte[] to BigInteger
            BigInteger intData = 0;
            for (var i = 0; i < data.Length; i++)
            {
                intData = intData * 256 + data[i];
            }

            // Encode BigInteger to Base58 string
            var result = "";
            while (intData > 0)
            {
                var remainder = (int)(NumberTheory.Mod(intData, 58));
                intData /= 58;
                result = Digits[remainder] + result;
            }

            // Append `1` for each leading 0 byte
            for (var i = 0; i < data.Length && data[i] == 0; i++)
            {
                result = '1' + result;
            }
            return result;
        }

        public static byte[] Decode(string base58)
        {
            // Decode Base58 string to BigInteger 
            BigInteger intData = 0;
            for (var i = 0; i < base58.Length; i++)
            {
                var digit = Digits.IndexOf(base58[i]); //Slow
                if (digit < 0)
                    throw new FormatException($"Invalid Base58 character `{base58[i]}` at position {i}");
                intData = intData * 58 + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading `1` characters
            var leadingZeroCount = base58.TakeWhile(c => c == '1').Count();
            var leadingZeros = Enumerable.Repeat((byte)0, leadingZeroCount);
            var bytesWithoutLeadingZeros =
                intData.ToByteArray()
                .Reverse()// to big endian
                .SkipWhile(b => b == 0);//strip sign byte
            var result = leadingZeros.Concat(bytesWithoutLeadingZeros).ToArray();
            return result;
        }


        public static byte[] AddCheckSum(byte[] data)
        {
            var checkSum = GetCheckSum(data);

            var result = new byte[checkSum.Length + data.Length];
            Buffer.BlockCopy(data, 0, result, 0, data.Length);
            Buffer.BlockCopy(checkSum, 0, result, data.Length, checkSum.Length);
            return result;
        }

        private static byte[] GetCheckSum(byte[] data)
        {
            var hash = SHA256.Instance.DoubleHash(data);
            Array.Resize(ref hash, CheckSumSizeInBytes);
            return hash;
        }
    }
}
