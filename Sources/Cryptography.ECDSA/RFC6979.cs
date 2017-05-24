using System.Numerics;
using System.Security.Cryptography;

namespace Cryptography.ECDSA
{
    internal class RFC6979
    {
        /// <summary>
        /// https://tools.ietf.org/html/rfc6979#section-3.2
        /// </summary>
        /// <param name="order">order of the DSA generator used in the signature</param>
        /// <param name="secexp">secure exponent (private key) in numeric form</param>
        /// <param name="hashFunc">reference to the same hash function used for generating hash</param>
        /// <param name="data">hash in binary form of the signing data</param>
        public static BigInteger GenerateK(BigInteger order, BigInteger secexp, HashAlgorithm hashFunc, byte[] data)
        {
            var qlen = Hex.BitLength(order);
            var holen = hashFunc.HashSize / 8;
            var rolen = (qlen + 7) / 8.0;
            var hsecexp = Hex.ToByteArrayUnsigned(secexp, true);
            var bx = Hex.Join(hsecexp, data);

            //Step B
            var v = new byte[holen];
            for (var i = 0; i < v.Length; i++)
                v[i]++;
            //Step C
            var k = new byte[holen];

            //Step D
            using (var hmacsha256 = new HMACSHA256(k))
            {
                var msg = Hex.Join(v, new byte[1], bx);
                k = hmacsha256.ComputeHash(msg);
            }

            //Step E
            using (var hmacsha256 = new HMACSHA256(k))
            {
                v = hmacsha256.ComputeHash(v);
            }

            //Step F
            using (var hmacsha256 = new HMACSHA256(k))
            {
                var msg = Hex.Join(v, new byte[] { 1 }, bx);
                k = hmacsha256.ComputeHash(msg);
            }

            //Step G
            using (var hmacsha256 = new HMACSHA256(k))
            {
                v = hmacsha256.ComputeHash(v);
            }

            //Step H
            while (true)
            {
                //Step H1
                var t = new byte[0];

                //Step H2
                while (t.Length < rolen)
                {
                    using (var hmacsha256 = new HMACSHA256(k))
                    {
                        v = hmacsha256.ComputeHash(v);
                    }
                    t = Hex.Join(t, v);
                }

                //Step H3
                var secret = Bits2Int(t, qlen);
                if (secret >= 1 && secret < order)
                    return secret;

                using (var hmacsha256 = new HMACSHA256(k))
                {
                    k = hmacsha256.ComputeHash(Hex.Join(v, new byte[0]));
                }
                using (var hmacsha256 = new HMACSHA256(k))
                {
                    v = hmacsha256.ComputeHash(v);
                }
            }
        }

        private static BigInteger Bits2Int(byte[] array, int qlen)
        {
            var secret = Hex.HexToBigInteger(array);
            var l = array.Length * 8;
            if (l > qlen)
                return secret >> (l - qlen);
            return secret;
        }

        private static byte Bits2Octets(byte[] array, BigInteger order)
        {
            var oLen = Hex.BitLength(order);
            var z1 = Bits2Int(array, oLen);
            var z2 = z1 - order;
            if (z2 < 0)
                z2 = z1;

            var bufarr = z2.ToByteArray();
            return bufarr[oLen / 8];
        }
    }
}