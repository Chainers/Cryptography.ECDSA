using System.Numerics;

namespace Cryptography.ECDSA.Curves
{
    public abstract class CurveBase
    {
        internal CurveFp Curve { get; set; }

        internal Point Generator { get; set; }

        internal BigInteger Order { get; set; }

        internal int BaseLen { get; set; }

        internal BigInteger VerifyingKeyLength { get; set; }

        internal BigInteger SignatureLength { get; set; }

        internal byte[] OId { get; set; }

        //public byte[] EncodedOId { get; set; }


        internal int OrderLen(BigInteger order)
        {
            return Hex.ByteLength(order);
        }

        public abstract byte[] Sign(byte[] digest, Base58 key);
    }
}