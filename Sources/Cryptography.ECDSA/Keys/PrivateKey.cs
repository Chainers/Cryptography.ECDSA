using System;
using System.Numerics;

namespace Cryptography.ECDSA.Keys
{
    internal class PrivateKey
    {
        public PublicKey PublicKey { get; set; }
        public BigInteger SecretMultiplier { get; set; }
        public BigInteger Order { get; set; }

        public PrivateKey(PublicKey publicKey, BigInteger secretMultiplier)
        {
            PublicKey = publicKey;
            SecretMultiplier = secretMultiplier;
        }

        /// <summary>
        /// Return a signature for the provided hash, using the provided random nonce.
        /// It is absolutely vital that randomK be an unpredictable number in the range [1, self.PublicKey.point.order()-1].  
        /// If an attacker can guess randomK, he can compute our private key from a single signature.
        /// Also, if an attacker knows a few high-order bits(or a few low-order bits) of randomK, he can compute our private key from many signatures.
        /// The generation of nonces with adequate cryptographic strength is very difficult and far beyond the scope of this comment.
        /// May raise RuntimeError, in which case retrying with a new random value k is in order.
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="randomK"></param>
        /// <returns></returns>
        public Signature Sign(BigInteger hash, BigInteger randomK)
        {
            var g = PublicKey.Generator;
            var n = g.Order.Value;
            var k = NumberTheory.Mod(randomK, n);
            var p1 = g * k;
            var r = p1.X;
            if (r == 0)
                throw new ArithmeticException("amazingly unlucky random number r");
            var s = NumberTheory.Mod(NumberTheory.ModInverse(k, n) * (hash + NumberTheory.Mod(SecretMultiplier * r, n)), n);
            if (s == 0)
                throw new ArithmeticException("amazingly unlucky random number s");
            return new Signature(r, s);
        }
    }
}