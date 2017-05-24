using System;
using System.Security.Cryptography;

namespace Cryptography.ECDSA
{
    internal class SHA256 : SHA256Managed
    {
        public static SHA256 Instance = new SHA256();

        public byte[] DoubleHash(byte[] data)
        {
            return ComputeHash(ComputeHash(data));
        }

        public byte[] DoubleHashCheckSum(byte[] data)
        {
            var checksum = DoubleHash(data);
            Array.Resize(ref checksum, 4);
            return checksum;
        }

        public byte[] ComputeHash(string hexData)
        {
            var bytes = Hex.HexToBytes(hexData);
            return ComputeHash(bytes);
        }

        public byte[] DoubleHash(string hexData)
        {
            var bytes = Hex.HexToBytes(hexData);
            return DoubleHash(bytes);
        }

        public byte[] DoubleHashCheckSum(string hexData)
        {
            var bytes = Hex.HexToBytes(hexData);
            return DoubleHashCheckSum(bytes);
        }

        public int DigestSize()
        {
            return 32;
        }
    }
}
