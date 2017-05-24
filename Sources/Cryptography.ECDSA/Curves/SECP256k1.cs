//https://github.com/warner/python-ecdsa
//
// Implementation of elliptic curves, for cryptographic applications.
//
// This module doesn't provide any way to choose a random elliptic
// curve, nor to verify that an elliptic curve was chosen randomly,
// because one can simply use NIST's standard curves.
//
// Notes from X9.62-1998 (draft):
//   Nomenclature:
//     - Q is a public key.
//     The "Elliptic Curve Domain Parameters" include:
//     - q is the "field size", which in our case equals p.
//     - p is a big prime.
//     - G is a point of prime order (5.1.1.1).
//     - n is the order of G (5.1.1.1).
//   Public-key validation (5.2.2):
//     - Verify that Q is not the point at infinity.
//     - Verify that X_Q and Y_Q are in [0,p-1].
//     - Verify that Q is on the curve.
//     - Verify that nQ is the point at infinity.
//   Signature generation (5.3):
//     - Pick random k from [1,n-1].
//   Signature checking (5.4.2):
//     - Verify that r and s are in [1,n-1].
//
// Version of 2008.11.25.
//
// Revision history:
//    2005.12.31 - Initial version.
//    2008.11.25 - Change CurveFp.is_on to contains_point.
//
// Written in 2005 by Peter Pearson and placed in the public domain.

using System.Security.Cryptography;
using Cryptography.ECDSA.Keys;

namespace Cryptography.ECDSA.Curves
{
    public class Secp256K1 : CurveBase
    {
        protected static RandomNumberGenerator Entropy = new RNGCryptoServiceProvider();

        public Secp256K1()
        {
            var a = Hex.HexToBigInteger("0000000000000000000000000000000000000000000000000000000000000000");
            var b = Hex.HexToBigInteger("0000000000000000000000000000000000000000000000000000000000000007");
            var p = Hex.HexToBigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
            var gx = Hex.HexToBigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
            var gy = Hex.HexToBigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
            var r = Hex.HexToBigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
            var tsss = Hex.HexToBigInteger("7fffffffffffffff7fffffffffffffff7fffffffffffffff7fffffffffffffff");

            Curve = new CurveFp(p, a, b);

            Generator = new Point(Curve, gx, gy, r);
            Order = r;
            BaseLen = Hex.ByteLength(r);
            VerifyingKeyLength = 2 * BaseLen;
            SignatureLength = VerifyingKeyLength;
            OId = new byte[] { 1, 3, 132, 0, 10 };
            //EncodedOId = Der.EncodeOId(OId);
        }


        //public void CompressedPubKey(string wif)
        //{
        //    var curv = new Secp256K1();
        //    var secret = Utils.HexStringToByteArray(wif);
        //    var order = R;
        //    var p = curv * Utils.StringToNumber(secret);


        //    //2    p = ecdsa.SigningKey.from_string(secret, curve = ecdsa.SECP256k1).VerifyingKey.pubkey.point
        //    //2    x_str = ecdsa.util.number_to_string(p.x(), order)
        //    //2    y_str = ecdsa.util.number_to_string(p.y(), order)
        //    //2    compressed = hexlify(bytes(chr(2 + (p.y() & 1)), 'ascii') + x_str).decode('ascii')
        //    //2    uncompressed = hexlify(bytes(chr(4), 'ascii') + x_str + y_str).decode('ascii')
        //    //2    return ([compressed, uncompressed])
        //}


        //public object GetPoint(BigInteger other)
        //{


        //    //        def __mul__(self, other):
        //    //    """Multiply a point by an integer."""

        //    //    def leftmost_bit(x):
        //    //      assert x > 0
        //    //      result = 1
        //    //      while result <= x:
        //    //        result = 2 * result
        //    //      return result // 2

        //    var e = other;
        //    //    if self.__order:
        //    //      e = e % self.__order
        //    e = e % R;

        //    if (e == 0)
        //    {
        //        return BigInteger.m
        //    }
        //    //    if e == 0:
        //    //      return INFINITY
        //    //    if self == INFINITY:
        //    //      return INFINITY
        //    //    assert e > 0

        //    //    # From X9.62 D.3.2:

        //    //    e3 = 3 * e
        //    //    negative_self = Point(self.__curve, self.__x, -self.__y, self.__order)
        //    //    i = leftmost_bit(e3) // 2
        //    //    result = self
        //    //    # print_("Multiplying %s by %d (e3 = %d):" % (self, other, e3))
        //    //    while i > 1:
        //    //      result = result.double()
        //    //      if (e3 & i) != 0 and(e & i) == 0:
        //    //        result = result + self
        //    //      if (e3 & i) == 0 and(e & i) != 0:
        //    //        result = result + negative_self
        //    //# print_(". . . i = %d, result = %s" % ( i, result ))
        //    //      i = i // 2

        //    //    return result

        //}


        public override byte[] Sign(byte[] msg, Base58 key)
        {
            var digest = SHA256.Instance.ComputeHash(msg);
            var p = Hex.HexToBigInteger(key.Hex);
            var sk = SigningKey.FromString(p, this);
            byte[] signature;
            byte i;

            var cnt = 0;
            while (true)
            {
                cnt++;
                
                //Deterministic k
                var timehex = Hex.IntToBytes(cnt); // BitConverter.GetBytes(DateTime.Now.Ticks);
                var timeKey = Hex.Join(digest, timehex);
                var data = SHA256.Instance.ComputeHash(timeKey);
                var k = RFC6979.GenerateK(sk.Curve.Generator.Order.Value, sk.Privkey.SecretMultiplier, SHA256.Instance, data);

                //Sign message
                var sigder = sk.SignDigest(digest, Entropy, k);
                //Reformating of signature
                var sdec = Utils.SigDecode(sigder);
                //r, s

                signature = Utils.SigEncodeString(sdec.Item1, sdec.Item2);
                var t = Hex.ToString(signature);


                //Make sure signature is canonical!
                var lenR = sigder[3];
                var lenS = sigder[5 + lenR];
                if (lenR == 32 && lenS == 32) // Derive the recovery parameter
                {
                    i = RecoverPubkeyParameter(digest, signature, sk.VerifyingKey);
                    i += 4;   //compressed
                    i += 27;  //compact
                    break;
                }
            }

            return Hex.Join(new[] { i }, signature);
        }

        /// <summary>
        /// Use to derive a number that allows to easily recover the public key from the signature
        /// </summary>
        /// <param name="digest"></param>
        /// <param name="signature"></param>
        /// <param name="pubkey"></param>
        private byte RecoverPubkeyParameter(byte[] digest, byte[] signature, VerifyingKey pubkey)
        {
            for (byte i = 0; i < 4; i++)
            {
                var p = RecoverPublicKey(digest, signature, i);
                if (p.Equals(pubkey))//|| CompressedPubkey(p) == pubkey.)
                    return i;
            }
            return 0;
        }

        private byte[] CompressedPubkey(VerifyingKey pk)
        {
            var p = pk.PubKey.Point;
            var xStr = Hex.ToByteArrayUnsigned(p.X, true);
            var k = (byte)(p.Y & 1 + 2);
            return Hex.Join(new[] { k }, xStr);
        }

        /// <summary>
        /// Recover the public key from the the signature
        /// See http: //www.secg.org/download/aid-780/sec1-v2.pdf section 4.1.6 primarily
        /// </summary>
        private VerifyingKey RecoverPublicKey(byte[] digest, byte[] signature, int i)
        {
            var yp = NumberTheory.Mod(i, 2);
            var rs = Utils.SigDecodeString(signature, Order);
            //1.1
            var x = rs.Item1 + (i >> 1) * Order;
            //1.3. This actually calculates for either effectively 02||X or 03||X depending on 'k' instead of always for 02||X as specified.
            //This substitutes for the lack of reversing R later on. -R actually is defined to be just flipping the y-coordinate in the elliptic curve.
            var alpha = NumberTheory.Mod((x * x * x) + (Curve.A * x) + Curve.B, Curve.P);
            var beta = NumberTheory.SquareRootModPrime(alpha, Curve.P);
            var y = (beta - yp).IsEven ? beta : Curve.P - beta;
            //1.4 Constructor of Point is supposed to check if nR is at infinity.
            var r = new Point(Curve, x, y, Order);
            //# 1.5 Compute e
            var e = Hex.HexToBigInteger(digest);
            //# 1.6 Compute Q = r^-1(sR - eG)
            var q = (r * rs.Item2 + Generator * NumberTheory.Mod(-e, Order)) * NumberTheory.ModInverse(rs.Item1, Order);
            //Not strictly necessary, but let's verify the message for paranoia's sake.
            var vk = VerifyingKey.FromPublicPoint(q, this);
            if (!vk.VerifyDigest(signature, digest))
                return null;
            return vk;
        }
    }
}