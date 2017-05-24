using System;
using System.Numerics;
using System.Security.Cryptography;
using Cryptography.ECDSA.Curves;

namespace Cryptography.ECDSA.Keys
{
    internal class SigningKey
    {
        public CurveBase Curve { get; set; }
        public HashAlgorithm DefaultHashFunc { get; set; }
        public BigInteger BaseLen { get; set; }
        public VerifyingKey VerifyingKey { get; set; }
        public PrivateKey Privkey { get; set; }


        private SigningKey() { }

        public void Generate()//    def generate(klass, curve=NIST192p, entropy=None, hashfunc=sha1):
        {
            //var secexp = Util.RandRange(curve.order, entropy)
            //return klass.from_secret_exponent(secexp, curve, hashfunc)
        }


        /// <summary>
        /// to create a signing key from a short (arbitrary-length) seed, convert
        /// that seed into an integer with something like
        /// secexp=util.randrange_from_seed__X(seed, curve.order), and then pass
        /// that integer into SigningKey.from_secret_exponent(secexp, curve)
        /// </summary>
        public static SigningKey FromSecretExponent(BigInteger secexp, CurveBase curve, HashAlgorithm hashfunc) //def from_secret_exponent(klass, secexp, curve= NIST192p, hashfunc = sha1):
        {
            var instance = new SigningKey();
            instance.Curve = curve;
            instance.DefaultHashFunc = hashfunc;
            instance.BaseLen = curve.BaseLen;
            var n = curve.Order;
            //Assert.IsTrue(1 <= secexp && secexp < n);
            var pubkeyPoint = curve.Generator * secexp;
            var pubkey = new PublicKey(curve.Generator, pubkeyPoint);
            pubkey.Order = n;
            instance.VerifyingKey = VerifyingKey.FromPublicPoint(pubkeyPoint, curve, hashfunc);
            instance.Privkey = new PrivateKey(pubkey, secexp);
            instance.Privkey.Order = n;
            return instance;
        }

        public static SigningKey FromString(BigInteger secexp, CurveBase curve)
        {
            return FromString(secexp, curve, SHA1.Create());
        }

        public static SigningKey FromString(BigInteger secexp, CurveBase curve, HashAlgorithm hashfunc)
        {
            //Assert.IsTrue(Hex.ByteLength(secexp) == curve.BaseLen);
            return FromSecretExponent(secexp, curve, hashfunc);
        }

        internal byte[] SignDigest(byte[] digest, RandomNumberGenerator entropy, BigInteger k)
        {
            if (digest.Length > Curve.BaseLen)
                throw new ArithmeticException("this curve is too short for your digest");

            var number = Hex.HexToBigInteger(digest);
            var sig = SignNumber(number, entropy, k);
            return Utils.SigEncode(sig.R, sig.S);
        }

        internal Signature SignNumber(BigInteger number, RandomNumberGenerator entropy, BigInteger? k)
        {
            //returns a pair of numbers
            var order = Privkey.Order;
            //Privkey.sign() may raise RuntimeError in the amazingly unlikely
            //(2**-192) event that r=0 or s=0, because that would leak the key.
            //We could re-try with a different 'k', but we couldn't test that
            //code, so I choose to allow the signature to fail instead.

            //If k is set, it is used directly. In other cases
            //it is generated using entropy function
            var _k = k ?? Utils.RandRange(order, entropy);

            //Assert.IsTrue(1 <= _k && k < order);

            var sig = Privkey.Sign(number, _k);
            return sig;
        }





        //    @classmethod
        //    def from_pem(klass, string, hashfunc=sha1):
        //        # the Privkey pem file has two sections: "EC PARAMETERS" and "EC
        //        # PRIVATE KEY". The first is redundant.
        //        if PY3 and isinstance(string, str):
        //            string = string.encode()
        //        privkey_pem = string[string.index(b("-----BEGIN EC PRIVATE KEY-----")):]
        //        return klass.from_der(der.unpem(privkey_pem), hashfunc)

        //    @classmethod
        //    def from_der(klass, string, hashfunc=sha1):
        //        # SEQ([int(1), octetstring(Privkey),cont[0], oid(secp224r1),
        //        #      cont[1],bitstring])
        //        s, empty = der.remove_sequence(string)
        //        if empty != b(""):
        //            raise der.UnexpectedDER("trailing junk after DER Privkey: %s" %
        //                                    binascii.hexlify(empty))
        //        one, s = der.remove_integer(s)
        //        if one != 1:
        //            raise der.UnexpectedDER("expected '1' at start of DER Privkey,"
        //                                    " got %d" % one)
        //        privkey_str, s = der.remove_octet_string(s)
        //        tag, curve_oid_str, s = der.remove_constructed(s)
        //        if tag != 0:
        //            raise der.UnexpectedDER("expected tag 0 in DER Privkey,"
        //                                    " got %d" % tag)
        //        curve_oid, empty = der.remove_object(curve_oid_str)
        //        if empty != b(""):
        //            raise der.UnexpectedDER("trailing junk after DER Privkey "
        //                                    "curve_oid: %s" % binascii.hexlify(empty))
        //        curve = find_curve(curve_oid)

        //        # we don't actually care about the following fields
        //#
        //# tag, pubkey_bitstring, s = der.remove_constructed(s)
        //#if tag != 1:
        //# raise der.UnexpectedDER("expected tag 1 in DER Privkey, got %d"
        //#                             % tag)
        //# pubkey_str = der.remove_bitstring(pubkey_bitstring)
        //#if empty != "":
        //# raise der.UnexpectedDER("trailing junk after DER Privkey "
        //#                             "pubkeystr: %s" % binascii.hexlify(empty))

        //# our from_string method likes fixed-length Privkey strings
        //        if len(privkey_str) < curve.baselen:
        //            privkey_str = b("\x00") * (curve.baselen - len(privkey_str)) + privkey_str
        //        return klass.from_string(privkey_str, curve, hashfunc)

        //    def to_string(self):
        //        secexp = self.Privkey.SecretMultiplier
        //        s = number_to_string(secexp, self.Privkey.order)
        //        return s

        //    def to_pem(self):
        //# TODO: "BEGIN ECPARAMETERS"
        //        return der.topem(self.to_der(), "EC PRIVATE KEY")

        //    def to_der(self):
        //# SEQ([int(1), octetstring(Privkey),cont[0], oid(secp224r1),
        //# cont[1],bitstring])
        //        encoded_vk = b("\x00\x04") + self.get_verifying_key().to_string()
        //        return der.encode_sequence(der.encode_integer(1),
        //                                   der.encode_octet_string(self.to_string()),
        //                                   der.encode_constructed(0, self.curve.encoded_oid),
        //                                   der.encode_constructed(1, der.encode_bitstring(encoded_vk)),
        //                                   )

        //    def sign_deterministic(self, data, hashfunc=None, sigencode=sigencode_string):
        //        hashfunc = hashfunc or self.DefaultHashFunc
        //        digest = hashfunc(data).digest()

        //        return self.sign_digest_deterministic(digest, hashfunc=hashfunc, sigencode=sigencode)

        //    def sign_digest_deterministic(self, digest, hashfunc=None, sigencode=sigencode_string):
        //        """
        //        Calculates 'k' from data itself, removing the need for strong
        //        random generator and producing deterministic (reproducible) signatures.
        //        See RFC 6979 for more details.
        //        """
        //        secexp = self.Privkey.SecretMultiplier
        //        k = rfc6979.GenerateK(
        //            self.curve.generator.order(), secexp, hashfunc, digest)

        //        return self.sign_digest(digest, sigencode=sigencode, k=k)

        //    def sign(self, data, entropy=None, hashfunc=None, sigencode=sigencode_string, k=None):
        //        """
        //        hashfunc= should behave like hashlib.sha1 . The output length of the
        //        hash (in bytes) must not be longer than the length of the curve order
        //        (rounded up to the nearest byte), so using SHA256 with nist256p is
        //        ok, but SHA256 with nist192p is not. (In the 2**-96ish unlikely event
        //        of a hash output larger than the curve order, the hash will
        //        effectively be wrapped mod n).

        //        Use hashfunc=hashlib.sha1 to match openssl's -ecdsa-with-SHA1 mode,
        //        or hashfunc=hashlib.sha256 for openssl-1.0.0's -ecdsa-with-SHA256.
        //        """

        //        hashfunc = hashfunc or self.DefaultHashFunc
        //        h = hashfunc(data).digest()
        //        return self.sign_digest(h, entropy, sigencode, k)
    }
}