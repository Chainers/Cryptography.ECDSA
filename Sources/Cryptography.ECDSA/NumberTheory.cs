using System;
using System.Numerics;

namespace Cryptography.ECDSA
{
    internal static class NumberTheory
    {
        public static int Mod(int value, int divVal)
        {
            var rez = value % divVal;
            if (value < 0 && divVal > 0 && rez < 0)
                return divVal + rez;
            return rez;
        }

        public static BigInteger Mod(BigInteger value, BigInteger divVal)
        {
            var rez = value % divVal;
            if (value.Sign < 0 && divVal.Sign > 0 && rez.Sign < 0)
                return divVal + rez;
            return rez;
        }

        //TODO: try simplefy
        public static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            if (a < 0 || m <= a)
                a = Mod(a, m);

            var c = a;
            var d = m;
            BigInteger uc = 1;
            BigInteger vc = 0;
            BigInteger ud = 0;
            BigInteger vd = 1;

            while (c != 0)
            {
                var q = BigInteger.Divide(d, c);
                var dd = c;
                c = Mod(d, c);
                d = dd;
                var ucb = uc;
                uc = ud - q * uc;
                ud = ucb;
                var vcb = vc;
                vc = vd - q * vc;
                vd = vcb;
            }

            //Assert.IsTrue(d.IsOne);
            if (ud.IsOne)
                return ud;
            return ud + m;
        }

        /// <summary>
        /// Modular square root of a, mod p, p prime.
        /// </summary>B
        /// <param name="a"></param>
        /// <param name="p"></param>
        public static BigInteger SquareRootModPrime(BigInteger a, BigInteger p)
        {
            //Based on the Handbook of Applied Cryptography, algorithms 3.34 to 3.39.
            //This module has been tested for all values in [0,p-1] for every prime p from 3 to 1229.

            //Assert.IsTrue(0 <= a && a < p && 1 < p);

            if (a == BigInteger.Zero)
                return BigInteger.Zero;

            if (p == 2)
                return a;

            var jac = Jacobi(a, p);
            if (jac == BigInteger.MinusOne)
                throw new ArithmeticException($"{a} has no square root modulo {p}");

            if (Mod(p, 4) == 3)
                return ModularExp(a, (p + 1) >> 2, p);

            if (Mod(p, 8) == 5)
            {
                var d = ModularExp(a, (p - 1) >> 2, p);
                if (d == BigInteger.One)
                    return ModularExp(a, (p + 3) >> 3, p);
                if (d == p - 1)
                    return Mod(2 * a * ModularExp(4 * a, (p - 5) >> 3, p), p);

                throw new ArithmeticException("Shouldn't get here.");
            }

            for (var b = 2; b < p; b++)
            {
                if (Jacobi(b * b - 4 * a, p) == -1)
                {
                    var f = new[] { a, -b, BigInteger.One };
                    var ff = PolynomialExpMod(new[] { BigInteger.Zero, BigInteger.One }, (p + 1) >> 2, f, p);
                    //Assert.IsTrue(ff[1] == BigInteger.Zero);
                    return ff[0];
                }
            }

            throw new ArithmeticException("No b found.");
        }

        public static BigInteger ModularExp(BigInteger basevalue, BigInteger exponent, BigInteger modulus)
        {
            if (exponent < 0)
                throw new ArithmeticException($"Negative exponents {exponent} not allowed");
            return BigInteger.ModPow(basevalue, exponent, modulus);
        }

        /// <summary>
        /// Polynomial exponentiation modulo a polynomial over ints mod p
        /// Polynomials are represented as lists of coefficients of increasing powers of x.
        /// Based on the Handbook of Applied Cryptography, algorithm 2.227.
        /// This module has been tested only by extensive use in calculating modular square roots.
        /// </summary>
        /// <param name="g"></param>
        /// <param name="exponent"></param>
        /// <param name="polymod"></param>
        /// <param name="p"></param>
        /// <returns></returns>
        public static BigInteger[] PolynomialExpMod(BigInteger[] g, BigInteger exponent, BigInteger[] polymod, BigInteger p)
        {
            //Assert.IsTrue(exponent < p);

            if (exponent == BigInteger.Zero)
                return new[] { BigInteger.One };


            var s = !exponent.IsEven ? g : new[] { BigInteger.One };

            while (exponent > BigInteger.One)
            {
                exponent >>= 1;
                g = PolynomialMultiplyMod(g, g, polymod, p);
                if (!exponent.IsEven)
                    s = PolynomialMultiplyMod(g, s, polymod, p);
            }
            return s;
        }

        /// <summary>
        /// Polynomial multiplication modulo a polynomial over ints mod p.
        /// Polynomials are represented as lists of coefficients of increasing powers of x.
        /// 
        /// This is just a seat-of-the-pants implementation.
        /// This module has been tested only by extensive use in calculating modular square roots.
        /// </summary>
        /// <param name="m1"></param>
        /// <param name="m2"></param>
        /// <param name="polymod"></param>
        /// <param name="p"></param>
        /// <returns></returns>
        public static BigInteger[] PolynomialMultiplyMod(BigInteger[] m1, BigInteger[] m2, BigInteger[] polymod, BigInteger p)
        {
            // Initialize the product to zero:
            var prod = new BigInteger[m1.Length + m2.Length - 1];

            //Add together all the cross-terms:

            for (var i = 0; i < m1.Length; i++)
                for (var j = 0; j < m2.Length; j++)
                    prod[i + j] = Mod(prod[i + j] + m1[i] * m2[j], p);

            return PolynomialReduceMod(prod, polymod, p);
        }

        /// <summary>
        /// Reduce poly by polymod, integer arithmetic modulo p.
        /// Polynomials are represented as lists of coefficients of increasing powers of x.
        /// 
        /// This module has been tested only by extensive use in calculating modular square roots.
        /// Just to make this easy, require a monic polynomial:
        /// </summary>
        /// <param name="poly"></param>
        /// <param name="polymod"></param>
        /// <param name="p"></param>
        public static BigInteger[] PolynomialReduceMod(BigInteger[] poly, BigInteger[] polymod, BigInteger p)
        {
            //Assert.IsTrue(polymod[polymod.Length - 1] == BigInteger.One);

            while (poly.Length >= polymod.Length)
            {
                if (poly[poly.Length - 1] != BigInteger.Zero)
                {
                    for (var i = 2; i < polymod.Length + 1; i++)
                        poly[poly.Length - i] = Mod(poly[poly.Length - i] - poly[poly.Length - 1] * polymod[polymod.Length - i], p);
                }
                poly = Hex.SkipTake(poly, 0, poly.Length - 1);
            }
            return poly;
        }

        /// <summary>
        /// Jacobi symbol
        /// Based on the Handbook of Applied Cryptography (HAC), algorithm 2.149.
        /// This function has been tested by comparison with a small table printed in HAC, and by extensive use in calculating modular square roots.
        /// </summary>
        /// <param name="a"></param>
        /// <param name="n"></param>
        public static BigInteger Jacobi(BigInteger a, BigInteger n)
        {
            //Assert.IsTrue(n >= 3 && !n.IsEven);
            a = Mod(a, n);

            if (a == BigInteger.Zero)
                return BigInteger.Zero;
            if (a == BigInteger.One)
                return BigInteger.One;
            var a1 = a;
            var e = BigInteger.Zero;

            while (a1.IsEven)
            {
                a1 >>= 1;
                e++;
            }
            //TODO:KOA change Mod(n, 8)=.., Mod(n, 4)= .. to mask 
            var s = (e.IsEven || Mod(n, 8) == 1 || Mod(n, 8) == 7) ? 1 : -1;

            if (a1 == BigInteger.One)
                return s;

            if (Mod(n, 4) == 3 && Mod(a1, 4) == 3)
            {
                s = -s;
            }
            return s * Jacobi(Mod(n, a1), a1);
        }
    }
}