using System;
using System.Numerics;

namespace Cryptography.ECDSA.Curves
{
    internal struct Point
    {
        public static readonly Point InfinityPoint = new Point(true);
        private bool Infinity { get; set; }

        public CurveFp Curve { get; }
        public BigInteger X { get; }
        public BigInteger Y { get; }
        public BigInteger? Order { get; }

        private Point(bool infinity)
        {
            Infinity = infinity;
            Curve = new CurveFp(BigInteger.Zero, BigInteger.Zero, BigInteger.Zero);
            X = BigInteger.Zero;
            Y = BigInteger.Zero;
            Order = BigInteger.Zero;
        }

        public Point(CurveFp curve, BigInteger x, BigInteger y) : this(curve, x, y, null) { }

        public Point(CurveFp curve, BigInteger x, BigInteger y, BigInteger? order)
        {
            Curve = curve;
            X = x;
            Y = y;
            Order = order;
            Infinity = false;

            //Assert.IsTrue(curve.IsContainsPoint(x, y));
            //if (order.HasValue)
            //    Assert.IsTrue((this * order.Value).IsInfinity());
        }


        public bool IsInfinity()
        {
            return Infinity || (X == BigInteger.Zero && Y == BigInteger.Zero);
        }

        public bool Equals(Point other)
        {
            return X.Equals(other.X) && Y.Equals(other.Y) && Equals(Curve, other.Curve);
        }

        public override bool Equals(object obj)
        {
            if (obj is Point)
                return Equals((Point)obj);

            return false;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Curve.GetHashCode();
                hashCode = (hashCode * 397) ^ X.GetHashCode();
                hashCode = (hashCode * 397) ^ Y.GetHashCode();
                hashCode = (hashCode * 397) ^ Order.GetHashCode();
                return hashCode;
            }
        }

        public int CompareTo(Point other)
        {
            throw new NotImplementedException();
        }

        public static Point operator +(Point self, Point other)
        {
            //X9.62 B.3:
            if (other.IsInfinity())
                return self;

            if (self.IsInfinity())
                return other;

            //Assert.IsTrue(Equals(self.Curve, other.Curve));

            if (self.X == other.X)
                if (NumberTheory.Mod(self.Y + other.Y, self.Curve.P) == 0)
                    return InfinityPoint;
                else
                    return Twice(self);

            var p = self.Curve.P;

            var l = NumberTheory.Mod((other.Y - self.Y) * NumberTheory.ModInverse(other.X - self.X, p), p);

            var x3 = NumberTheory.Mod(l * l - self.X - other.X, p);
            var y3 = NumberTheory.Mod(l * (self.X - x3) - self.Y, p);
            return new Point(self.Curve, x3, y3);
        }

        public static Point operator *(Point self, BigInteger value)
        {
            if (self.IsInfinity())
                return InfinityPoint;

            if (self.Order.HasValue)
                value = NumberTheory.Mod(value, self.Order.Value);

            if (value == 0)
                return InfinityPoint;

            //Assert.IsTrue(value > 0);

            //From X9.62 D.3.2:

            var e3 = 3 * value;
            var negativeSelf = new Point(self.Curve, self.X, -self.Y, self.Order);
            var bitLen = Hex.BitLength(e3);
            var result = self;


            for (var i = bitLen - 2; i > 0; i--)
            {
                result = Twice(result);

                if (Hex.TestBit(e3, i) && !Hex.TestBit(value, i))
                    result = result + self;

                if (!Hex.TestBit(e3, i) && Hex.TestBit(value, i))
                    result = result + negativeSelf;
            }

            return result;
        }

        public override string ToString()
        {
            if (IsInfinity())
                return "Infinity";
            return $"({X},{Y})";
        }

        private static Point Twice(Point self)
        {
            if (self.IsInfinity())
                return InfinityPoint;

            //X9.62 B.3:
            var p = self.Curve.P;
            var a = self.Curve.A;
            var m = NumberTheory.Mod((3 * self.X * self.X + a) * NumberTheory.ModInverse(2 * self.Y, p), p);
            var x3 = NumberTheory.Mod(m * m - 2 * self.X, p);
            var y3 = NumberTheory.Mod(m * (self.X - x3) - self.Y, p);

            return new Point(self.Curve, x3, y3);
        }

        //  def __rmul__(self, other):
        //    """Multiply a point by an integer."""

        //    return self* other
    }
}
