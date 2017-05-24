using System.Numerics;

namespace Cryptography.ECDSA.Keys
{
    internal struct Signature
    {
        public BigInteger R;
        public BigInteger S;

        public Signature(BigInteger r, BigInteger s)
        {
            R = r;
            S = s;
        }
    }
}