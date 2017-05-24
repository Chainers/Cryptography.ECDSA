using System.Numerics;

namespace Cryptography.ECDSA.Curves
{
    /// <summary>
    /// The curve of points satisfying y^2 = x^3 + a*x + b (mod p)
    /// </summary>
    internal struct CurveFp
    {
        public BigInteger P { get; set; }
        public BigInteger A { get; set; }
        public BigInteger B { get; set; }

        public CurveFp(BigInteger p, BigInteger a, BigInteger b)
        {
            P = p;
            A = a;
            B = b;
        }

        public bool IsContainsPoint(BigInteger x, BigInteger y)
        {
            return NumberTheory.Mod(y * y - (x * x * x + A * x + B), P) == 0;
        }

        //def __str__(self):
        //  return "CurveFp(p=%d, a=%d, b=%d)" % (self.__p, self.__a, self.__b)
    }
}