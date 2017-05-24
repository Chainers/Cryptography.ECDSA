using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Cryptography.ECDSA
{
    internal class Utils
    {
        public static byte[] HexStringToByteArray(string plainTex)
        {
            var rez = new byte[plainTex.Length / 2];
            for (var i = 0; i < rez.Length; i++)
                rez[i] = byte.Parse($"{plainTex[i * 2]}{ plainTex[i * 2 + 1]}", NumberStyles.AllowHexSpecifier);
            return rez;
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        /// <summary>
        /// Return a random integer k such that 1 &lt;= k &lt; order, uniformly distributed across that range. 
        /// For simplicity, this only behaves well if 'order' is fairly close (but below) a power of 256. 
        /// The try-try-again algorithm we use takes longer and longer time(on average) to complete as 'order' falls, 
        /// rising to a maximum of avg = 512 loops for the worst-case (256**k)+1.
        /// All of the standard curves behave well.
        /// There is a cutoff at 10k loops(which raises RuntimeError) to prevent an infinite loop when something is really broken like the entropy function not working.
        /// Note that this function is not declared to be forwards-compatible: we may change the behavior in future releases.
        /// The entropy= argument (which should get a callable that behaves like os.urandom) can be used to achieve stability within a given release (for repeatable unit tests), 
        /// but should not be used as a long-term-compatible key generation algorithm.
        /// <remarks>
        /// we could handle arbitrary orders (even 256**k+1) better if we created candidates bit-wise instead of byte-wise, 
        /// which would reduce the worst-case behavior to avg=2 loops, but that would be more complex. 
        /// The change would be to round the order up to a power of 256, subtract one (to get 0xffff..), 
        /// use that to get a byte-long mask for the top byte, generate the len-1 entropy bytes, generate one extra byte and mask off the top bits, 
        /// then combine it with the rest. Requires jumping back and forth between strings and integers a lot.
        /// </remarks>
        /// </summary>
        /// <returns></returns>
        public static BigInteger RandRange(BigInteger order, RandomNumberGenerator entropy)//def randrange(order, entropy=None):
        {
            if (entropy == null)
                entropy = RandomNumberGenerator.Create();
            //Assert.IsTrue(order > BigInteger.Zero);
            var byteslen = Hex.BitLength(order);
            var bytes = new byte[byteslen];
            var dontTryForever = 10000; // gives about 2**-60 failures for worst case
            while (dontTryForever > 0)
            {
                dontTryForever--;
                entropy.GetBytes(bytes);
                var candidate = Hex.HexToBigInteger(bytes) + 1;
                if (1 <= candidate && candidate < order)
                    return candidate;
            }
            throw new ArithmeticException($"randrange() tried hard but gave up, either something is very wrong or you got realllly unlucky. Order was {order}");
        }

        public static byte[] SigEncode(BigInteger r, BigInteger s)
        {
            var eR = Der.EncodeInteger(r);
            var eS = Der.EncodeInteger(s);
            return Der.EncodeSequence(eR, eS);
        }

        public static Tuple<BigInteger, BigInteger> SigDecode(byte[] sig)
        {
            var str = Der.RemoveSequence(sig);
            if (str.Item2.Length > 0)
                throw new ArithmeticException($"trailing junk after DER sig: {Hex.ToString(str.Item2)}");
            var remrez1 = Der.RemoveInteger(str.Item1);
            var remrez2 = Der.RemoveInteger(remrez1.Item2);
            if (remrez2.Item2.Length != 0)
                throw new ArithmeticException($"trailing junk after DER numbers: {Hex.ToString(remrez2.Item2)}");

            return new Tuple<BigInteger, BigInteger>(remrez1.Item1, remrez2.Item1);
        }

        public static byte[] SigEncodeString(BigInteger r, BigInteger s)
        {
            var ra = Hex.ToByteArrayUnsigned(r, true);
            var sa = Hex.ToByteArrayUnsigned(s, true);
            return Hex.Join(ra, sa);
        }

        public static Tuple<BigInteger, BigInteger> SigDecodeString(byte[] signature, BigInteger order)
        {
            var l = Hex.ByteLength(order);
            //Assert.IsTrue(signature.Length == 2 * l);
            var ra = Hex.SkipTake(signature, 0, l);
            var sa = Hex.Skip(signature, l);

            var r = Hex.HexToBigInteger(ra);
            var s = Hex.HexToBigInteger(sa);
            return new Tuple<BigInteger, BigInteger>(r, s);
        }
    }
}