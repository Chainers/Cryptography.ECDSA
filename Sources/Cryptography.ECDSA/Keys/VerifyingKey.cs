using System;
using System.Security.Cryptography;
using Cryptography.ECDSA.Curves;

namespace Cryptography.ECDSA.Keys
{
    internal class VerifyingKey
    {
        public CurveBase Curve { get; set; }
        public HashAlgorithm DefaultHashFunc { get; set; }
        public PublicKey PubKey { get; set; }

        private VerifyingKey()
        {
        }


        public static VerifyingKey FromPublicPoint(Point point, CurveBase curve, HashAlgorithm hashfunc)
        {
            var instance = new VerifyingKey
            {
                Curve = curve,
                DefaultHashFunc = hashfunc,
                PubKey = new PublicKey(curve.Generator, point) { Order = curve.Order }
            };
            return instance;
        }

        public static VerifyingKey FromPublicPoint(Point point, CurveBase curve)
        {
            var instance = new VerifyingKey
            {
                Curve = curve,
                DefaultHashFunc = new SHA1Managed(),
                PubKey = new PublicKey(curve.Generator, point) { Order = curve.Order }
            };
            return instance;
        }


        public bool Equals(VerifyingKey other)
        {
            return PubKey.Point.X.Equals(other.PubKey.Point.X) && PubKey.Point.Y.Equals(other.PubKey.Point.Y);
        }

        public override bool Equals(object obj)
        {
            if (obj is VerifyingKey)
                return Equals((VerifyingKey)obj);

            return false;
        }

        //    @classmethod
        //    def from_string(klass, string, curve=NIST192p, hashfunc=sha1,
        //                    validate_point=True):
        //        order = curve.order
        //        assert (len(string) == curve.verifying_key_length), \
        //               (len(string), curve.verifying_key_length)
        //        xs = string[:curve.baselen]
        //ys = string[curve.baselen:]
        //assert len(xs) == curve.baselen, (len(xs), curve.baselen)
        //        assert len(ys) == curve.baselen, (len(ys), curve.baselen)
        //        x = string_to_number(xs)
        //        y = string_to_number(ys)
        //        if validate_point:
        //            assert ecdsa.point_is_valid(curve.generator, x, y)
        //        from.import ellipticcurve
        //        point = ellipticcurve.Point(curve.curve, x, y, order)
        //        return klass.from_public_point(point, curve, hashfunc)

        //    @classmethod
        //    def from_pem(klass, string):
        //        return klass.from_der(der.unpem(string))

        //    @classmethod
        //    def from_der(klass, string):
        //        # [[oid_ecPublicKey,oid_curve], point_str_bitstring]
        //        s1, empty = der.remove_sequence(string)
        //        if empty != b(""):
        //            raise der.UnexpectedDER("trailing junk after DER pubkey: %s" %
        //                                    binascii.hexlify(empty))
        //        s2, point_str_bitstring = der.remove_sequence(s1)
        //        # s2 = oid_ecPublicKey,oid_curve
        //        oid_pk, rest = der.remove_object(s2)
        //        oid_curve, empty = der.remove_object(rest)
        //        if empty != b(""):
        //            raise der.UnexpectedDER("trailing junk after DER pubkey objects: %s" %
        //                                    binascii.hexlify(empty))
        //        assert oid_pk == oid_ecPublicKey, (oid_pk, oid_ecPublicKey)
        //        curve = find_curve(oid_curve)
        //        point_str, empty = der.remove_bitstring(point_str_bitstring)
        //        if empty != b(""):
        //            raise der.UnexpectedDER("trailing junk after pubkey pointstring: %s" %
        //                                    binascii.hexlify(empty))
        //        assert point_str.startswith(b("\x00\x04"))
        //        return klass.from_string(point_str[2:], curve)

        //    def to_string(self):
        //        # VerifyingKey.from_string(vk.to_string()) == vk as long as the
        //        # curves are the same: the curve itself is not included in the
        //        # serialized form
        //        order = self.pubkey.order
        //        x_str = number_to_string(self.pubkey.point.x(), order)
        //        y_str = number_to_string(self.pubkey.point.y(), order)
        //        return x_str + y_str

        //    def to_pem(self):
        //        return der.topem(self.to_der(), "PUBLIC KEY")

        //    def to_der(self):
        //        order = self.pubkey.order
        //        x_str = number_to_string(self.pubkey.point.x(), order)
        //        y_str = number_to_string(self.pubkey.point.y(), order)
        //        point_str = b("\x00\x04") + x_str + y_str
        //        return der.encode_sequence(der.encode_sequence(encoded_oid_ecPublicKey,
        //                                                       self.curve.encoded_oid),
        //                                   der.encode_bitstring(point_str))

        //    def verify(self, signature, data, hashfunc= None, sigdecode= sigdecode_string):
        //        hashfunc = hashfunc or self.default_hashfunc
        //        digest = hashfunc(data).digest()
        //        return self.VerifyDigest(signature, digest, sigdecode)

        public bool VerifyDigest(byte[] signature, byte[] digest)
        {
            if (digest.Length > Curve.BaseLen)
                throw new ArgumentException($"this curve is too short for your digest {digest.Length}");

            var number = Hex.HexToBigInteger(digest);
            var r_s = Utils.SigDecodeString(signature, PubKey.Order);
            var sig = new Signature(r_s.Item1, r_s.Item2);
            if (PubKey.Verifies(number, sig))
                return true;

            throw new ArithmeticException("BadSignatureError");
        }
    }
}