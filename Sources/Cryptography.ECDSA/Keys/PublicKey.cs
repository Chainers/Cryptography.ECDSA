using System;
using System.Numerics;
using Cryptography.ECDSA.Curves;

namespace Cryptography.ECDSA.Keys
{
    internal class PublicKey
    {
        public CurveFp Curve { get; }
        public BigInteger Order { get; set; }
        public Point Generator { get; set; }
        public Point Point { get; set; }

        /// <summary>
        /// generator is the Point that generates the group, point is the Point that defines the public key.
        /// </summary>
        /// <param name="generator"></param>
        /// <param name="point"></param>
        internal PublicKey(Point generator, Point point)
        {
            Curve = generator.Curve;
            Generator = generator;
            Point = point;
            var n = generator.Order;

            if (!n.HasValue)
                throw new ArgumentNullException(nameof(generator.Order), "Generator point must have order.");

            if (!(point * n.Value).IsInfinity())
                throw new ArithmeticException("Generator point order is bad.");

            if (point.X < 0 || n <= point.X || point.Y < 0 || n <= point.Y)
                throw new ArithmeticException("Generator point has x or y out of range.");
        }

        /// <summary>
        /// Verify that signature is a valid signature of hash.
        /// Return True if the signature is valid.
        /// From X9.62 J.3.1.
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public bool Verifies(BigInteger hash, Signature signature)
        {
            if (signature.R < BigInteger.One || signature.R > Generator.Order - 1)
                return false;

            if (signature.S < BigInteger.One || signature.S > Generator.Order - 1)
                return false;

            var c = NumberTheory.ModInverse(signature.S, Generator.Order.Value);
            var u1 = NumberTheory.Mod(hash * c, Generator.Order.Value);
            var u2 = NumberTheory.Mod(signature.R * c, Generator.Order.Value);
            var xy = Generator * u1 + Point * u2;
            var v = NumberTheory.Mod(xy.X, Generator.Order.Value);
            return v == signature.R;
        }
    }
}