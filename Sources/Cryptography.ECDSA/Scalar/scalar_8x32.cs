#define USE_SCALAR_8X32

#if USE_SCALAR_8X32
using System;

namespace Cryptography.ECDSA
{
    #region From C macros to С# regexp

    // Inspired by the macros in OpenSSL's crypto/bn/asm/x86_64-gcc.c. 

    // Add a*b to the number defined by (c0,c1,c2). c2 must never overflow.
    // #define muladd(a,b) { \
    //     uint32_t tl, th; \
    //     { \
    //         uint64_t t = (uint64_t)a * b; \
    //         th = t >> 32;         // at most 0xFFFFFFFE  \
    //         tl = t; \
    //     } \
    //     c0 += tl;                 // overflow is handled on the next line  \
    //     th += (c0<tl) ? 1 : 0;  // at most 0xFFFFFFFF  \
    //     c1 += th;                 // overflow is handled on the next line  \
    //     c2 += (c1<th) ? 1 : 0;  // never overflows by contract (verified in the next line)  \
    //     VERIFY_CHECK((c1 >= th) || (c2 != 0)); \
    // }
    //>>>>>>>>>
    // pattern:
    //     muladd\((?<a>[0-9a-zA-Z\.\[\]_]*),\s?(?<b>[0-9a-zA-Z\.\[\]_]*)\);
    // replacement:
    //     { UInt64 t = (UInt64)(${a}) * (${b}); UInt32 th = (UInt32)(t >> 32);  UInt32 tl = (UInt32)t; c0 += tl; th += (c0<tl) ? 1 : 0; c1 += th; Util.VERIFY_CHECK(c1 >= th); }
    //     //___________________________________________________________________________________________________________________________________


    // Add a*b to the number defined by (c0,c1). c1 must never overflow. 
    // #define muladd_fast(a,b) { \
    //     uint32_t tl, th; \
    //     { \
    //         uint64_t t = (uint64_t)a * b; \
    //         th = t >> 32;         // at most 0xFFFFFFFE  \
    //         tl = t; \
    //     } \
    //     c0 += tl;                 // overflow is handled on the next line  \
    //     th += (c0<tl) ? 1 : 0;  // at most 0xFFFFFFFF  \
    //     c1 += th;                 // never overflows by contract (verified in the next line)  \
    //     VERIFY_CHECK(c1 >= th); \
    // }
    //>>>>>>>>>
    // pattern:
    //     muladd_fast\((?<a>[0-9a-zA-Z\.\[\]_]*),\s?(?<b>[0-9a-zA-Z\.\[\]_]*)\);
    // replacement:
    //     { UInt64 t = (UInt64)(${a}) * (${b}); UInt32 th = (UInt32)(t >> 32);  UInt32 tl = (UInt32)t; c0 += tl; th += (c0<tl) ? 1 : 0; c1 += th; Util.VERIFY_CHECK(c1 >= th); }
    //     //___________________________________________________________________________________________________________________________________


    // Add 2*a*b to the number defined by (c0,c1,c2). c2 must never overflow. 
    // #define muladd2(a,b) { \
    //     uint32_t tl, th, th2, tl2; \
    //     { \
    //         uint64_t t = (uint64_t)a * b; \
    //         th = t >> 32;               // at most 0xFFFFFFFE  \
    //         tl = t; \
    //     } \
    //     th2 = th + th;                  // at most 0xFFFFFFFE (in case th was 0x7FFFFFFF)  \
    //     c2 += (th2<th) ? 1 : 0;       // never overflows by contract (verified the next line)  \
    //     VERIFY_CHECK((th2 >= th) || (c2 != 0)); \
    //     tl2 = tl + tl;                  // at most 0xFFFFFFFE (in case the lowest 63 bits of tl were 0x7FFFFFFF)  \
    //     th2 += (tl2<tl) ? 1 : 0;      // at most 0xFFFFFFFF  \
    //     c0 += tl2;                      // overflow is handled on the next line  \
    //     th2 += (c0<tl2) ? 1 : 0;      // second overflow is handled on the next line  \
    //     c2 += (c0<tl2) & (th2 == 0);  // never overflows by contract (verified the next line)  \
    //     VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); \
    //     c1 += th2;                      // overflow is handled on the next line  \
    //     c2 += (c1<th2) ? 1 : 0;       // never overflows by contract (verified the next line)  \
    //     VERIFY_CHECK((c1 >= th2) || (c2 != 0)); \
    // }
    //>>>>>>>>>
    // pattern:
    //     muladd2\((?<a>[0-9a-zA-Z\.\[\]_]*),\s?(?<b>[0-9a-zA-Z\.\[\]_]*)\);
    // replacement:
    //     { UInt64 t = (UInt64)(${a}) * (${b}); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2<th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2<tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0<tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1<th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
    //     //___________________________________________________________________________________________________________________________________

    // Add a to the number defined by (c0,c1,c2). c2 must never overflow. 
    // #define sumadd(a) { \
    //     unsigned int over; \
    //     c0 += (a);                  // overflow is handled on the next line  \
    //     over = (c0<(a)) ? 1 : 0; \
    //     c1 += over;                 // overflow is handled on the next line  \
    //     c2 += (c1<over) ? 1 : 0;  // never overflows by contract  \
    // } 
    //>>>>>>>>>
    // pattern:
    //     sumadd\((?<a>[0-9a-zA-Z\.\[\]_]*)\);
    // replacement:
    //     { c0 += (${a}); UInt32 over = (UInt32)((c0<(${a})) ? 1 : 0);  c1 += over; c2 += (UInt32)((c1<over) ? 1 : 0);}
    //     //___________________________________________________________________________________________________________________________________


    // Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. 
    // #define sumadd_fast(a) { \
    //     c0 += (a);                 // overflow is handled on the next line  \
    //     c1 += (c0<(a)) ? 1 : 0;  // never overflows by contract (verified the next line)  \
    //     VERIFY_CHECK((c1 != 0) | (c0 >= (a))); \
    //     VERIFY_CHECK(c2 == 0); \
    // }
    //>>>>>>>>>
    // pattern:
    //     sumadd_fast\((?<a>[0-9a-zA-Z\.\[\]_]*)\);
    // replacement:
    //     { c0 += (${a}); c1 += (UInt32)((c0<(${a})) ? 1 : 0);  Util.VERIFY_CHECK((c1 != 0) | (c0 >= (${a}))); Util.VERIFY_CHECK(c2 == 0);}
    //     //___________________________________________________________________________________________________________________________________


    // Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. 
    // #define extract(n) { \
    //     (n) = c0; \
    //     c0 = c1; \
    //     c1 = c2; \
    //     c2 = 0; \
    // }
    //>>>>>>>>>
    // pattern:
    //     extract\((?<n>[0-9a-zA-Z\.\[\]_]*)\);
    // replacement:
    //     { (${n}) = c0; c0 = c1; c1 = c2; c2 = 0; }
    //     //___________________________________________________________________________________________________________________________________


    // Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. c2 is required to be zero. 
    // #define extract_fast(n) { \
    //     (n) = c0; \
    //     c0 = c1; \
    //     c1 = 0; \
    //     VERIFY_CHECK(c2 == 0); \
    // }
    //>>>>>>>>>
    // pattern:
    //     extract_fast\((?<n>[0-9a-zA-Z\.\[\]_]*)\);
    // replacement:
    //     { (${n}) = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
    //     //___________________________________________________________________________________________________________________________________

    #endregion From C macros to С# regexp



    /** A scalar modulo the group order of the secp256k1 curve. */
    internal class secp256k1_scalar
    {
        public const int Size = 32;
        public UInt32[] d;

        public secp256k1_scalar()
        {
            d = new UInt32[Size / 4];
        }

        public secp256k1_scalar(UInt32[] arr)
        {
            d = arr;
        }

        public secp256k1_scalar(secp256k1_scalar other)
        {
            d = new UInt32[other.d.Length];
            Array.Copy(other.d, d, other.d.Length);
        }

        public secp256k1_scalar Clone()
        {
            return new secp256k1_scalar(this);
        }
    }

    //#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7)}}


    internal partial class Scalar
    {
        ///* Limbs of the secp256k1 order. */
        private const UInt32 SECP256K1_N_0 = 0xD0364141;
        private const UInt32 SECP256K1_N_1 = 0xBFD25E8C;
        private const UInt32 SECP256K1_N_2 = 0xAF48A03B;
        private const UInt32 SECP256K1_N_3 = 0xBAAEDCE6;
        private const UInt32 SECP256K1_N_4 = 0xFFFFFFFE;
        private const UInt32 SECP256K1_N_5 = Const.FFFFFFFF;
        private const UInt32 SECP256K1_N_6 = Const.FFFFFFFF;
        private const UInt32 SECP256K1_N_7 = Const.FFFFFFFF;

        ///* Limbs of 2^256 minus the secp256k1 order. */
        private const UInt32 SECP256K1_N_C_0 = ~SECP256K1_N_0 + 1;
        private const UInt32 SECP256K1_N_C_1 = ~SECP256K1_N_1;
        private const UInt32 SECP256K1_N_C_2 = ~SECP256K1_N_2;
        private const UInt32 SECP256K1_N_C_3 = ~SECP256K1_N_3;
        private const UInt32 SECP256K1_N_C_4 = 1;

        ///* Limbs of half the secp256k1 order. */
        private const UInt32 SECP256K1_N_H_0 = 0x681B20A0;
        private const UInt32 SECP256K1_N_H_1 = 0xDFE92F46;
        private const UInt32 SECP256K1_N_H_2 = 0x57A4501D;
        private const UInt32 SECP256K1_N_H_3 = 0x5D576E73;
        private const UInt32 SECP256K1_N_H_4 = Const.FFFFFFFF;
        private const UInt32 SECP256K1_N_H_5 = Const.FFFFFFFF;
        private const UInt32 SECP256K1_N_H_6 = Const.FFFFFFFF;
        private const UInt32 SECP256K1_N_H_7 = 0x7FFFFFFF;


        /// <summary>
        /// Set a scalar from a big endian byte array.
        /// </summary>
        /// <param name="r"></param>
        /// <param name="b32"></param>
        /// <param name="overflow"></param>
        public static void secp256k1_scalar_set_b32(secp256k1_scalar r, byte[] b32, ref bool overflow)
        {
            var isOverflow = secp256k1_scalar_set_b32(r, b32, 0);
            if (overflow)
                overflow = isOverflow;
        }

        public static bool secp256k1_scalar_set_b32(secp256k1_scalar r, byte[] b32, int skip = 0)
        {
            r.d[0] = (UInt32)b32[skip + 31] | (UInt32)b32[skip + 30] << 8 | (UInt32)b32[skip + 29] << 16 | (UInt32)b32[skip + 28] << 24;
            r.d[1] = (UInt32)b32[skip + 27] | (UInt32)b32[skip + 26] << 8 | (UInt32)b32[skip + 25] << 16 | (UInt32)b32[skip + 24] << 24;
            r.d[2] = (UInt32)b32[skip + 23] | (UInt32)b32[skip + 22] << 8 | (UInt32)b32[skip + 21] << 16 | (UInt32)b32[skip + 20] << 24;
            r.d[3] = (UInt32)b32[skip + 19] | (UInt32)b32[skip + 18] << 8 | (UInt32)b32[skip + 17] << 16 | (UInt32)b32[skip + 16] << 24;
            r.d[4] = (UInt32)b32[skip + 15] | (UInt32)b32[skip + 14] << 8 | (UInt32)b32[skip + 13] << 16 | (UInt32)b32[skip + 12] << 24;
            r.d[5] = (UInt32)b32[skip + 11] | (UInt32)b32[skip + 10] << 8 | (UInt32)b32[skip + 9] << 16 | (UInt32)b32[skip + 8] << 24;
            r.d[6] = (UInt32)b32[skip + 7] | (UInt32)b32[skip + 6] << 8 | (UInt32)b32[skip + 5] << 16 | (UInt32)b32[skip + 4] << 24;
            r.d[7] = (UInt32)b32[skip + 3] | (UInt32)b32[skip + 2] << 8 | (UInt32)b32[skip + 1] << 16 | (UInt32)b32[skip + 0] << 24;
            var isOverflow = secp256k1_scalar_check_overflow(r);
            secp256k1_scalar_reduce(r, isOverflow);
            return isOverflow;
        }

        private static bool secp256k1_scalar_check_overflow(secp256k1_scalar a)
        {
            bool no = (a.d[7] < SECP256K1_N_7) || (a.d[6] < SECP256K1_N_6) || (a.d[5] < SECP256K1_N_5) || (a.d[4] < SECP256K1_N_4);
            bool yes = (a.d[4] > SECP256K1_N_4) & !no;
            no |= (a.d[3] < SECP256K1_N_3) & !yes;
            yes |= (a.d[3] > SECP256K1_N_3) & !no;
            no |= (a.d[2] < SECP256K1_N_2) & !yes;
            yes |= (a.d[2] > SECP256K1_N_2) & !no;
            no |= (a.d[1] < SECP256K1_N_1) & !yes;
            yes |= (a.d[1] > SECP256K1_N_1) & !no;
            yes |= (a.d[0] >= SECP256K1_N_0) & !no;
            return yes;
        }

        private static void secp256k1_scalar_reduce(secp256k1_scalar r, bool isOverflow)
        {
            UInt64 overflow = (UInt64)(isOverflow ? 1 : 0);
            UInt64 t = (UInt64)r.d[0] + overflow * SECP256K1_N_C_0;
            r.d[0] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)r.d[1] + overflow * SECP256K1_N_C_1;
            r.d[1] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)r.d[2] + overflow * SECP256K1_N_C_2;
            r.d[2] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)r.d[3] + overflow * SECP256K1_N_C_3;
            r.d[3] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)r.d[4] + overflow * SECP256K1_N_C_4;
            r.d[4] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)r.d[5];
            r.d[5] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)r.d[6];
            r.d[6] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)r.d[7];
            r.d[7] = (UInt32)(t & Const.FFFFFFFF);
        }

        /// <summary>
        /// Check whether a scalar equals zero.
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        public static bool secp256k1_scalar_is_zero(secp256k1_scalar a)
        {
            return (a.d[0] | a.d[1] | a.d[2] | a.d[3] | a.d[4] | a.d[5] | a.d[6] | a.d[7]) == 0;
        }

        /// <summary>
        /// Add two scalars together(modulo the group order). Returns whether it overflowed.
        /// </summary>
        /// <param name="r"></param>
        /// <param name=""></param>
        /// <returns></returns>
        public static bool secp256k1_scalar_add(secp256k1_scalar r, secp256k1_scalar a, secp256k1_scalar b)
        {
            UInt64 t = (UInt64)a.d[0] + b.d[0];
            r.d[0] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)a.d[1] + b.d[1];
            r.d[1] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)a.d[2] + b.d[2];
            r.d[2] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)a.d[3] + b.d[3];
            r.d[3] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)a.d[4] + b.d[4];
            r.d[4] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)a.d[5] + b.d[5];
            r.d[5] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)a.d[6] + b.d[6];
            r.d[6] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            t += (UInt64)a.d[7] + b.d[7];
            r.d[7] = (UInt32)(t & Const.FFFFFFFF);
            t >>= 32;
            var overflow = t > 0 || secp256k1_scalar_check_overflow(r);
            secp256k1_scalar_reduce(r, overflow);
            return overflow;
        }

        /// <summary>
        /// Access bits from a scalar. All requested bits must belong to the same 32-bit limb.
        /// </summary>
        /// <param name="a"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static uint secp256k1_scalar_get_bits(secp256k1_scalar a, int offset, int count)
        {
            if ((offset + count - 1) >> 5 != offset >> 5)
                throw new ArithmeticException();
            return (a.d[offset >> 5] >> (offset & 0x1F)) & (((uint)1 << count) - 1);
        }

        public static void secp256k1_scalar_clear(secp256k1_scalar r)
        {
            r.d[0] = 0;
            r.d[1] = 0;
            r.d[2] = 0;
            r.d[3] = 0;
            r.d[4] = 0;
            r.d[5] = 0;
            r.d[6] = 0;
            r.d[7] = 0;
        }

        public static void secp256k1_scalar_set_int(secp256k1_scalar r, uint v)
        {
            r.d[0] = v;
            r.d[1] = 0;
            r.d[2] = 0;
            r.d[3] = 0;
            r.d[4] = 0;
            r.d[5] = 0;
            r.d[6] = 0;
            r.d[7] = 0;
        }

        public static uint secp256k1_scalar_get_bits_var(secp256k1_scalar a, int offset, int count)
        {
            Util.VERIFY_CHECK(count < 32);
            Util.VERIFY_CHECK(offset + count <= 256);
            if ((offset + count - 1) >> 5 == offset >> 5)
            {
                return secp256k1_scalar_get_bits(a, offset, count);
            }
            else
            {
                Util.VERIFY_CHECK((offset >> 5) + 1 < 8);
                return ((a.d[offset >> 5] >> (offset & 0x1F)) | (a.d[(offset >> 5) + 1] << (32 - (offset & 0x1F)))) & ((((UInt32)1) << count) - 1);
            }
        }

        public static void secp256k1_scalar_cadd_bit(secp256k1_scalar r, uint ubit, int flag)
        {
            UInt64 t;
            Util.VERIFY_CHECK(ubit < 256);
            var bit = (byte)ubit;
            bit += (byte)((flag - 1) & 0x100);  /* forcing (bit >> 5) > 7 makes this a noop */
            t = (UInt64)r.d[0] + (((UInt32)(((bit >> 5) == 0) ? 1 : 0)) << (bit & 0x1F));
            r.d[0] = (UInt32)(t & 0xFFFFFFFF); t >>= 32;
            t += (UInt64)r.d[1] + (((UInt32)(((bit >> 5) == 1) ? 1 : 0)) << (bit & 0x1F));
            r.d[1] = (UInt32)(t & 0xFFFFFFFF); t >>= 32;
            t += (UInt64)r.d[2] + (((UInt32)(((bit >> 5) == 2) ? 1 : 0)) << (bit & 0x1F));
            r.d[2] = (UInt32)(t & 0xFFFFFFFF); t >>= 32;
            t += (UInt64)r.d[3] + (((UInt32)(((bit >> 5) == 3) ? 1 : 0)) << (bit & 0x1F));
            r.d[3] = (UInt32)(t & 0xFFFFFFFF); t >>= 32;
            t += (UInt64)r.d[4] + (((UInt32)(((bit >> 5) == 4) ? 1 : 0)) << (bit & 0x1F));
            r.d[4] = (UInt32)(t & 0xFFFFFFFF); t >>= 32;
            t += (UInt64)r.d[5] + (((UInt32)(((bit >> 5) == 5) ? 1 : 0)) << (bit & 0x1F));
            r.d[5] = (UInt32)(t & 0xFFFFFFFF); t >>= 32;
            t += (UInt64)r.d[6] + (((UInt32)(((bit >> 5) == 6) ? 1 : 0)) << (bit & 0x1F));
            r.d[6] = (UInt32)(t & 0xFFFFFFFF); t >>= 32;
            t += (UInt64)r.d[7] + (((UInt32)(((bit >> 5) == 7) ? 1 : 0)) << (bit & 0x1F));
            r.d[7] = (UInt32)(t & 0xFFFFFFFF);
#if VERIFY
            Util.VERIFY_CHECK((t >> 32) == 0);
            Util.VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
#endif
        }

        public static void secp256k1_scalar_get_b32(byte[] bin, secp256k1_scalar a)
        {
            secp256k1_scalar_get_b32(bin, 0, a);
        }

        public static void secp256k1_scalar_get_b32(byte[] bin, int skip, secp256k1_scalar a)
        {
            bin[skip + 0] = (byte)(a.d[7] >> 24); bin[skip + 1] = (byte)(a.d[7] >> 16); bin[skip + 2] = (byte)(a.d[7] >> 8); bin[skip + 3] = (byte)(a.d[7]);
            bin[skip + 4] = (byte)(a.d[6] >> 24); bin[skip + 5] = (byte)(a.d[6] >> 16); bin[skip + 6] = (byte)(a.d[6] >> 8); bin[skip + 7] = (byte)(a.d[6]);
            bin[skip + 8] = (byte)(a.d[5] >> 24); bin[skip + 9] = (byte)(a.d[5] >> 16); bin[skip + 10] = (byte)(a.d[5] >> 8); bin[skip + 11] = (byte)(a.d[5]);
            bin[skip + 12] = (byte)(a.d[4] >> 24); bin[skip + 13] = (byte)(a.d[4] >> 16); bin[skip + 14] = (byte)(a.d[4] >> 8); bin[skip + 15] = (byte)(a.d[4]);
            bin[skip + 16] = (byte)(a.d[3] >> 24); bin[skip + 17] = (byte)(a.d[3] >> 16); bin[skip + 18] = (byte)(a.d[3] >> 8); bin[skip + 19] = (byte)(a.d[3]);
            bin[skip + 20] = (byte)(a.d[2] >> 24); bin[skip + 21] = (byte)(a.d[2] >> 16); bin[skip + 22] = (byte)(a.d[2] >> 8); bin[skip + 23] = (byte)(a.d[2]);
            bin[skip + 24] = (byte)(a.d[1] >> 24); bin[skip + 25] = (byte)(a.d[1] >> 16); bin[skip + 26] = (byte)(a.d[1] >> 8); bin[skip + 27] = (byte)(a.d[1]);
            bin[skip + 28] = (byte)(a.d[0] >> 24); bin[skip + 29] = (byte)(a.d[0] >> 16); bin[skip + 30] = (byte)(a.d[0] >> 8); bin[skip + 31] = (byte)(a.d[0]);
        }

        public static void secp256k1_scalar_negate(secp256k1_scalar r, secp256k1_scalar a)
        {
            UInt32 nonzero = secp256k1_scalar_is_zero(a) ? 0 : 0xFFFFFFFF;
            UInt64 t = (UInt64)(~a.d[0]) + SECP256K1_N_0 + 1;
            r.d[0] = (UInt32)(t & nonzero); t >>= 32;
            t += (UInt64)(~a.d[1]) + SECP256K1_N_1;
            r.d[1] = (UInt32)(t & nonzero); t >>= 32;
            t += (UInt64)(~a.d[2]) + SECP256K1_N_2;
            r.d[2] = (UInt32)(t & nonzero); t >>= 32;
            t += (UInt64)(~a.d[3]) + SECP256K1_N_3;
            r.d[3] = (UInt32)(t & nonzero); t >>= 32;
            t += (UInt64)(~a.d[4]) + SECP256K1_N_4;
            r.d[4] = (UInt32)(t & nonzero); t >>= 32;
            t += (UInt64)(~a.d[5]) + SECP256K1_N_5;
            r.d[5] = (UInt32)(t & nonzero); t >>= 32;
            t += (UInt64)(~a.d[6]) + SECP256K1_N_6;
            r.d[6] = (UInt32)(t & nonzero); t >>= 32;
            t += (UInt64)(~a.d[7]) + SECP256K1_N_7;
            r.d[7] = (UInt32)(t & nonzero);
        }

        public static bool secp256k1_scalar_is_one(secp256k1_scalar a)
        {
            return ((a.d[0] ^ 1) | a.d[1] | a.d[2] | a.d[3] | a.d[4] | a.d[5] | a.d[6] | a.d[7]) == 0;
        }

        public static bool secp256k1_scalar_is_high(secp256k1_scalar a)
        {
            bool yes = false;
            bool no = false;
            no |= (a.d[7] < SECP256K1_N_H_7);
            yes |= (a.d[7] > SECP256K1_N_H_7) & !no;
            no |= (a.d[6] < SECP256K1_N_H_6) & !yes; /* No need for a > check. */
            no |= (a.d[5] < SECP256K1_N_H_5) & !yes; /* No need for a > check. */
            no |= (a.d[4] < SECP256K1_N_H_4) & !yes; /* No need for a > check. */
            no |= (a.d[3] < SECP256K1_N_H_3) & !yes;
            yes |= (a.d[3] > SECP256K1_N_H_3) & !no;
            no |= (a.d[2] < SECP256K1_N_H_2) & !yes;
            yes |= (a.d[2] > SECP256K1_N_H_2) & !no;
            no |= (a.d[1] < SECP256K1_N_H_1) & !yes;
            yes |= (a.d[1] > SECP256K1_N_H_1) & !no;
            yes |= (a.d[0] > SECP256K1_N_H_0) & !no;
            return yes;
        }

        //public static int secp256k1_scalar_cond_negate(secp256k1_scalar r, int flag)
        //{
        //    /* If we are flag = 0, mask = 00...00 and this is a no-op;
        //     * if we are flag = 1, mask = 11...11 and this is identical to secp256k1_scalar_negate */
        //    UInt32 mask = !flag - 1;
        //    UInt32 nonzero = secp256k1_scalar_is_zero(r) ? 0 : 0xFFFFFFFF;
        //    UInt64 t = (UInt64)(r.d[0] ^ mask) + ((SECP256K1_N_0 + 1) & mask);
        //    r.d[0] = (UInt32)(t & nonzero); t >>= 32;
        //    t += (UInt64)(r.d[1] ^ mask) + (SECP256K1_N_1 & mask);
        //    r.d[1] = (UInt32)(t & nonzero); t >>= 32;
        //    t += (UInt64)(r.d[2] ^ mask) + (SECP256K1_N_2 & mask);
        //    r.d[2] = (UInt32)(t & nonzero); t >>= 32;
        //    t += (UInt64)(r.d[3] ^ mask) + (SECP256K1_N_3 & mask);
        //    r.d[3] = (UInt32)(t & nonzero); t >>= 32;
        //    t += (UInt64)(r.d[4] ^ mask) + (SECP256K1_N_4 & mask);
        //    r.d[4] = (UInt32)(t & nonzero); t >>= 32;
        //    t += (UInt64)(r.d[5] ^ mask) + (SECP256K1_N_5 & mask);
        //    r.d[5] = (UInt32)(t & nonzero); t >>= 32;
        //    t += (UInt64)(r.d[6] ^ mask) + (SECP256K1_N_6 & mask);
        //    r.d[6] = (UInt32)(t & nonzero); t >>= 32;
        //    t += (UInt64)(r.d[7] ^ mask) + (SECP256K1_N_7 & mask);
        //    r.d[7] = (UInt32)(t & nonzero);
        //    return 2 * (mask == 0) - 1;
        //}

        static void secp256k1_scalar_reduce_512(secp256k1_scalar r, UInt32[] l)
        {
            UInt64 c;
            UInt32 n0 = l[8], n1 = l[9], n2 = l[10], n3 = l[11], n4 = l[12], n5 = l[13], n6 = l[14], n7 = l[15];
            UInt32 m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12;
            UInt32 p0, p1, p2, p3, p4, p5, p6, p7, p8;

            /* 96 bit accumulator. */
            UInt32 c0, c1, c2;

            /* Reduce 512 bits into 385. */
            /* m[0..12] = l[0..7] + n[0..7] * SECP256K1_N_C. */
            c0 = l[0]; c1 = 0; c2 = 0;
            { UInt64 t = (UInt64)(n0) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += (UInt32)tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; Util.VERIFY_CHECK(c1 >= th); }
            //___________________________________________________________________________________________________________________________________

            { (m0) = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (l[1]); c1 += (UInt32)((c0 < (l[1])) ? 1 : 0); Util.VERIFY_CHECK((c1 != 0) | (c0 >= (l[1]))); Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n1) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n0) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (m1) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (l[2]); UInt32 over = (UInt32)((c0 < (l[2])) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n2) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n1) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n0) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (m2) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (l[3]); UInt32 over = (UInt32)((c0 < (l[3])) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n3) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n2) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n1) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n0) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (m3) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (l[4]); UInt32 over = (UInt32)((c0 < (l[4])) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n4) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n3) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n2) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n1) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (n0); UInt32 over = (UInt32)((c0 < (n0)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (m4) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (l[5]); UInt32 over = (UInt32)((c0 < (l[5])) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n5) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n4) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n3) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n2) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (n1); UInt32 over = (UInt32)((c0 < (n1)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (m5) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (l[6]); UInt32 over = (UInt32)((c0 < (l[6])) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n6) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n5) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n4) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n3) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (n2); UInt32 over = (UInt32)((c0 < (n2)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (m6) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (l[7]); UInt32 over = (UInt32)((c0 < (l[7])) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n7) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n6) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n5) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n4) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (n3); UInt32 over = (UInt32)((c0 < (n3)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (m7) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n7) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n6) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n5) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (n4); UInt32 over = (UInt32)((c0 < (n4)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (m8) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n7) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n6) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (n5); UInt32 over = (UInt32)((c0 < (n5)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (m9) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(n7) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (n6); UInt32 over = (UInt32)((c0 < (n6)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (m10) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (n7); c1 += (UInt32)((c0 < (n7)) ? 1 : 0); Util.VERIFY_CHECK((c1 != 0) | (c0 >= (n7))); Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { (m11) = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            Util.VERIFY_CHECK(c0 <= 1);
            m12 = c0;

            /* Reduce 385 bits into 258. */
            /* p[0..8] = m[0..7] + m[8..12] * SECP256K1_N_C. */
            c0 = m0; c1 = 0; c2 = 0;
            { UInt64 t = (UInt64)(m8) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += (UInt32)tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; Util.VERIFY_CHECK(c1 >= th); }
            //___________________________________________________________________________________________________________________________________

            { (p0) = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m1); c1 += (UInt32)((c0 < (m1)) ? 1 : 0); Util.VERIFY_CHECK((c1 != 0) | (c0 >= (m1))); Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m9) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m8) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (p1) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m2); UInt32 over = (UInt32)((c0 < (m2)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m10) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m9) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m8) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (p2) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m3); UInt32 over = (UInt32)((c0 < (m3)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m11) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m10) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m9) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m8) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (p3) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m4); UInt32 over = (UInt32)((c0 < (m4)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m12) * (SECP256K1_N_C_0); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m11) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m10) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m9) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m8); UInt32 over = (UInt32)((c0 < (m8)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (p4) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m5); UInt32 over = (UInt32)((c0 < (m5)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m12) * (SECP256K1_N_C_1); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m11) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m10) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m9); UInt32 over = (UInt32)((c0 < (m9)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (p5) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m6); UInt32 over = (UInt32)((c0 < (m6)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m12) * (SECP256K1_N_C_2); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m11) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m10); UInt32 over = (UInt32)((c0 < (m10)) ? 1 : 0); c1 += over; c2 += (UInt32)((c1 < over) ? 1 : 0); }
            //___________________________________________________________________________________________________________________________________

            { (p6) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m7); c1 += (UInt32)((c0 < (m7)) ? 1 : 0); Util.VERIFY_CHECK((c1 != 0) | (c0 >= (m7))); Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(m12) * (SECP256K1_N_C_3); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += (UInt32)tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; Util.VERIFY_CHECK(c1 >= th); }
            //___________________________________________________________________________________________________________________________________

            { c0 += (m11); c1 += (UInt32)((c0 < (m11)) ? 1 : 0); Util.VERIFY_CHECK((c1 != 0) | (c0 >= (m11))); Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { (p7) = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            p8 = c0 + m12;
            Util.VERIFY_CHECK(p8 <= 2);

            /* Reduce 258 bits into 256. */
            /* r[0..7] = p[0..7] + p[8] * SECP256K1_N_C. */
            c = p0 + (UInt64)SECP256K1_N_C_0 * p8;
            r.d[0] = (UInt32)(c & 0xFFFFFFFF); c >>= 32;
            c += p1 + (UInt64)SECP256K1_N_C_1 * p8;
            r.d[1] = (UInt32)(c & 0xFFFFFFFF); c >>= 32;
            c += p2 + (UInt64)SECP256K1_N_C_2 * p8;
            r.d[2] = (UInt32)(c & 0xFFFFFFFF); c >>= 32;
            c += p3 + (UInt64)SECP256K1_N_C_3 * p8;
            r.d[3] = (UInt32)(c & 0xFFFFFFFF); c >>= 32;
            c += p4 + (UInt64)p8;
            r.d[4] = (UInt32)(c & 0xFFFFFFFF); c >>= 32;
            c += p5;
            r.d[5] = (UInt32)(c & 0xFFFFFFFF); c >>= 32;
            c += p6;
            r.d[6] = (UInt32)(c & 0xFFFFFFFF); c >>= 32;
            c += p7;
            r.d[7] = (UInt32)(c & 0xFFFFFFFF); c >>= 32;

            /* Final reduction of r. */
            secp256k1_scalar_reduce(r, c > 0 || secp256k1_scalar_check_overflow(r));
        }

        private static void secp256k1_scalar_mul_512(UInt32[] l, secp256k1_scalar a, secp256k1_scalar b)
        {
            /* 96 bit accumulator. */
            UInt32 c0 = 0, c1 = 0, c2 = 0;

            /* l[0..15] = a[0..7] * b[0..7]. */
            { UInt64 t = (UInt64)(a.d[0]) * (b.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += (UInt32)tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; Util.VERIFY_CHECK(c1 >= th); }
            //___________________________________________________________________________________________________________________________________

            { l[0] = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (b.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (b.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[1]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (b.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (b.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (b.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[2]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (b.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (b.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (b.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (b.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[3]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (b.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (b.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (b.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (b.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (b.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[4]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (b.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (b.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (b.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (b.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (b.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (b.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[5]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (b.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (b.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (b.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (b.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (b.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (b.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (b.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[6]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (b.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (b.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (b.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (b.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (b.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (b.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (b.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (b.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[7]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (b.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (b.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (b.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (b.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (b.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (b.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (b.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[8]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (b.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (b.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (b.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (b.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (b.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (b.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[9]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (b.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (b.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (b.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (b.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (b.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[10]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (b.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (b.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (b.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (b.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[11]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (b.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (b.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (b.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[12]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (b.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (b.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[13]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (b.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += (UInt32)tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; Util.VERIFY_CHECK(c1 >= th); }
            //___________________________________________________________________________________________________________________________________

            { l[14] = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            Util.VERIFY_CHECK(c1 == 0);
            l[15] = c0;
        }

        public static void secp256k1_scalar_sqr_512(UInt32[] l, secp256k1_scalar a)
        {
            /* 96 bit accumulator. */
            UInt32 c0 = 0, c1 = 0, c2 = 0;

            /* l[0..15] = a[0..7]^2. */
            { UInt64 t = (UInt64)(a.d[0]) * (a.d[0]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += (UInt32)tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; Util.VERIFY_CHECK(c1 >= th); }
            //___________________________________________________________________________________________________________________________________

            { l[0] = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (a.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________


            { (l[1]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (a.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (a.d[1]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[2]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (a.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (a.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[3]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (a.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (a.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (a.d[2]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[4]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (a.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (a.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (a.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[5]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (a.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (a.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (a.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (a.d[3]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[6]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[0]) * (a.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (a.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (a.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (a.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[7]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[1]) * (a.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (a.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (a.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (a.d[4]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[8]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[2]) * (a.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (a.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (a.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[9]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[3]) * (a.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (a.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (a.d[5]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[10]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[4]) * (a.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (a.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[11]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[5]) * (a.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (a.d[6]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; c2 += (UInt32)((c1 < th) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[12]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[6]) * (a.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)(t); UInt32 th2 = th + th; c2 += (UInt32)((th2 < th) ? 1 : 0); Util.VERIFY_CHECK((th2 >= th) || (c2 != 0)); UInt32 tl2 = tl + tl; th2 += (UInt32)((tl2 < tl) ? 1 : 0); c0 += tl2; th2 += (UInt32)((c0 < tl2) ? 1 : 0); c2 += (UInt32)((c0 < tl2) & (th2 == 0) ? 1 : 0); Util.VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); c1 += th2; c2 += (UInt32)((c1 < th2) ? 1 : 0); Util.VERIFY_CHECK((c1 >= th2) || (c2 != 0)); }
            //___________________________________________________________________________________________________________________________________

            { (l[13]) = c0; c0 = c1; c1 = c2; c2 = 0; }
            //___________________________________________________________________________________________________________________________________

            { UInt64 t = (UInt64)(a.d[7]) * (a.d[7]); UInt32 th = (UInt32)(t >> 32); UInt32 tl = (UInt32)t; c0 += (UInt32)tl; th += (UInt32)((c0 < tl) ? 1 : 0); c1 += th; Util.VERIFY_CHECK(c1 >= th); }
            //___________________________________________________________________________________________________________________________________

            { l[14] = c0; c0 = c1; c1 = 0; Util.VERIFY_CHECK(c2 == 0); }
            //___________________________________________________________________________________________________________________________________

            Util.VERIFY_CHECK(c1 == 0);
            l[15] = c0;
        }

        public static void secp256k1_scalar_mul(secp256k1_scalar r, secp256k1_scalar a, secp256k1_scalar b)
        {
            var l = new UInt32[16];
            secp256k1_scalar_mul_512(l, a, b);
            secp256k1_scalar_reduce_512(r, l);
        }

        //static int secp256k1_scalar_shr_int(secp256k1_scalar* r, int n)
        //{
        //int ret;
        // Util.VERIFY_CHECK(n > 0);
        // Util.VERIFY_CHECK(n < 16);
        //ret = r.d[0] & ((1 << n) - 1);
        //r.d[0] = (r.d[0] >> n) + (r.d[1] << (32 - n));
        //r.d[1] = (r.d[1] >> n) + (r.d[2] << (32 - n));
        //r.d[2] = (r.d[2] >> n) + (r.d[3] << (32 - n));
        //r.d[3] = (r.d[3] >> n) + (r.d[4] << (32 - n));
        //r.d[4] = (r.d[4] >> n) + (r.d[5] << (32 - n));
        //r.d[5] = (r.d[5] >> n) + (r.d[6] << (32 - n));
        //r.d[6] = (r.d[6] >> n) + (r.d[7] << (32 - n));
        //r.d[7] = (r.d[7] >> n);
        //return ret;
        //}

        static void secp256k1_scalar_sqr(secp256k1_scalar r, secp256k1_scalar a)
        {
            var l = new UInt32[16];
            secp256k1_scalar_sqr_512(l, a);
            secp256k1_scalar_reduce_512(r, l);
        }

        //#ifdef USE_ENDOMORPHISM
        //static void secp256k1_scalar_split_128(secp256k1_scalar* r1, secp256k1_scalar* r2, const secp256k1_scalar* a)
        //{
        //r1.d[0] = a.d[0];
        //r1.d[1] = a.d[1];
        //r1.d[2] = a.d[2];
        //r1.d[3] = a.d[3];
        //r1.d[4] = 0;
        //r1.d[5] = 0;
        //r1.d[6] = 0;
        //r1.d[7] = 0;
        //r2.d[0] = a.d[4];
        //r2.d[1] = a.d[5];
        //r2.d[2] = a.d[6];
        //r2.d[3] = a.d[7];
        //r2.d[4] = 0;
        //r2.d[5] = 0;
        //r2.d[6] = 0;
        //r2.d[7] = 0;
        //}
        //#endif

        //SECP256K1_INLINE static int secp256k1_scalar_eq(const secp256k1_scalar* a, const secp256k1_scalar* b)
        //{
        //return ((a.d[0] ^ b.d[0]) | (a.d[1] ^ b.d[1]) | (a.d[2] ^ b.d[2]) | (a.d[3] ^ b.d[3]) | (a.d[4] ^ b.d[4]) | (a.d[5] ^ b.d[5]) | (a.d[6] ^ b.d[6]) | (a.d[7] ^ b.d[7])) == 0;
        //}

        //SECP256K1_INLINE static void secp256k1_scalar_mul_shift_var(secp256k1_scalar* r, const secp256k1_scalar* a, const secp256k1_scalar* b, unsigned int shift)
        //{
        //UInt32 l[16];
        //unsigned int shiftlimbs;
        //unsigned int shiftlow;
        //unsigned int shifthigh;
        // Util.VERIFY_CHECK(shift >= 256);
        //secp256k1_scalar_mul_512(l, a, b);
        //shiftlimbs = shift >> 5;
        //shiftlow = shift & 0x1F;
        //shifthigh = 32 - shiftlow;
        //r.d[0] = shift < 512 ? (l[0 + shiftlimbs] >> shiftlow | (shift < 480 && shiftlow ? (l[1 + shiftlimbs] << shifthigh) : 0)) : 0;
        //r.d[1] = shift < 480 ? (l[1 + shiftlimbs] >> shiftlow | (shift < 448 && shiftlow ? (l[2 + shiftlimbs] << shifthigh) : 0)) : 0;
        //r.d[2] = shift < 448 ? (l[2 + shiftlimbs] >> shiftlow | (shift < 416 && shiftlow ? (l[3 + shiftlimbs] << shifthigh) : 0)) : 0;
        //r.d[3] = shift < 416 ? (l[3 + shiftlimbs] >> shiftlow | (shift < 384 && shiftlow ? (l[4 + shiftlimbs] << shifthigh) : 0)) : 0;
        //r.d[4] = shift < 384 ? (l[4 + shiftlimbs] >> shiftlow | (shift < 352 && shiftlow ? (l[5 + shiftlimbs] << shifthigh) : 0)) : 0;
        //r.d[5] = shift < 352 ? (l[5 + shiftlimbs] >> shiftlow | (shift < 320 && shiftlow ? (l[6 + shiftlimbs] << shifthigh) : 0)) : 0;
        //r.d[6] = shift < 320 ? (l[6 + shiftlimbs] >> shiftlow | (shift < 288 && shiftlow ? (l[7 + shiftlimbs] << shifthigh) : 0)) : 0;
        //r.d[7] = shift < 288 ? (l[7 + shiftlimbs] >> shiftlow) : 0;
        //secp256k1_scalar_cadd_bit(r, 0, (l[(shift - 1) >> 5] >> ((shift - 1) & 0x1f)) & 1);
        //}

    }
}
#endif