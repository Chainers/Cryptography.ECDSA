#define USE_FIELD_10X26
//#define VERIFY

using System;

namespace Cryptography.ECDSA
{
    #region From C macros to С# regexp

    // #define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
    //# ifdef VERIFY
    //#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)), 1, 1}
    //#else
    //#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0))}
    //#endif
    //>>>>>>>>>
    // pattern:
    //     SECP256K1_GE_CONST\((?<a>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<b>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<c>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<d>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<e>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<f>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<g>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<h>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<i>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<j>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<k>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<l>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<m>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<n>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<o>[0-9a-zA-Z\.\[\]_\=\! ]*),\s(?<p>[0-9a-zA-Z\.\[\]_\=\! ]*)\);
    // replacement:
    // new secp256k1_ge(
    // new UInt32[10]
    // { 
    //  (UInt32) ((${h}) & 0x3FFFFFFUL),
    //  (UInt32) ((((UInt32)${h}) >> 26) | (((UInt32)(${g}) & 0xFFFFFUL) << 6)),
    //  (UInt32) ((((UInt32)${g}) >> 20) | (((UInt32)(${f}) & 0x3FFFUL) << 12)),
    //  (UInt32) ((((UInt32)${f}) >> 14) | (((UInt32)(${e}) & 0xFFUL) << 18)),
    //  (UInt32) ((((UInt32)${e}) >> 8) | (((UInt32)(${d}) & 0x3UL) << 24)),
    //  (UInt32) ((((UInt32)${d}) >> 2) & 0x3FFFFFFUL),
    //  (UInt32) ((((UInt32)${d}) >> 28) | (((UInt32)(${c}) & 0x3FFFFFUL) << 4)),
    //  (UInt32) ((((UInt32)${c}) >> 22) | (((UInt32)(${b}) & 0xFFFFUL) << 10)),
    //  (UInt32) ((((UInt32)${b}) >> 16) | (((UInt32)(${a}) & 0x3FFUL) << 16)),
    //  (UInt32) ((((UInt32)${a}) >> 10))
    // },
    // new UInt32[10]
    // { 
    //  (UInt32) ((${p}) & 0x3FFFFFFUL),
    //  (UInt32) ((((UInt32)${p}) >> 26) | (((UInt32)(${o}) & 0xFFFFFUL) << 6)),
    //  (UInt32) ((((UInt32)${o}) >> 20) | (((UInt32)(${n}) & 0x3FFFUL) << 12)),
    //  (UInt32) ((((UInt32)${n}) >> 14) | (((UInt32)(${m}) & 0xFFUL) << 18)),
    //  (UInt32) ((((UInt32)${m}) >> 8) | (((UInt32)(${l}) & 0x3UL) << 24)),
    //  (UInt32) ((((UInt32)${l}) >> 2) & 0x3FFFFFFUL),
    //  (UInt32) ((((UInt32)${l}) >> 28) | (((UInt32)(${k}) & 0x3FFFFFUL) << 4)),
    //  (UInt32) ((((UInt32)${k}) >> 22) | (((UInt32)(${j}) & 0xFFFFUL) << 10)),
    //  (UInt32) ((((UInt32)${j}) >> 16) | (((UInt32)(${i}) & 0x3FFUL) << 16)),
    //  (UInt32) ((((UInt32)${i}) >> 10))
    // });
    // //___________________________________________________________________________________________________________________________________

    //#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
    //#define SECP256K1_GE_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

    //#define SECP256K1_GEJ_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), 0}
    //#define SECP256K1_GEJ_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}
    //#define SECP256K1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

    //#define SECP256K1_GE_STORAGE_CONST_GET(t) SECP256K1_FE_STORAGE_CONST_GET(t.x), SECP256K1_FE_STORAGE_CONST_GET(t.y)


    #endregion From C macros to С# regexp



    internal class secp256k1_ge_storage
    {
        public secp256k1_fe_storage x;
        public secp256k1_fe_storage y;

        public secp256k1_ge_storage()
        {
            x = new secp256k1_fe_storage();
            y = new secp256k1_fe_storage();
        }
    }

    /// <summary>
    /// A group element of the secp256k1 curve, in jacobian coordinates.
    /// </summary>
    internal class secp256k1_gej
    {
        public secp256k1_fe x; // actual X: x/z^2 
        public secp256k1_fe y; // actual Y: y/z^3
        public secp256k1_fe z;
        public bool infinity; // whether this represents the point at infinity

        public secp256k1_gej()
        {
            x = new secp256k1_fe();
            y = new secp256k1_fe();
            z = new secp256k1_fe();
        }

        public secp256k1_gej(secp256k1_fe xVal, secp256k1_fe yVal, secp256k1_fe zVal)
        {
            x = xVal ?? new secp256k1_fe();
            y = yVal ?? new secp256k1_fe();
            z = zVal ?? new secp256k1_fe();
        }

        public secp256k1_gej Clone()
        {
            return new secp256k1_gej(x?.Clone(), y?.Clone(), z?.Clone());
        }
    }

    /// <summary>
    /// A group element of the secp256k1 curve, in affine coordinates.
    /// </summary>
    internal class secp256k1_ge
    {
        public secp256k1_fe x;
        public secp256k1_fe y;
        public bool infinity; // whether this represents the point at infinity

        public secp256k1_ge()
        {
            x = new secp256k1_fe();
            y = new secp256k1_fe();
        }

        public secp256k1_ge(UInt32[] xarr, UInt32[] yarr)
        {
            x = new secp256k1_fe(xarr);
            y = new secp256k1_fe(yarr);
        }
    }


    internal class Group
    {

        ///** Set a group element equal to the point with given X and Y coordinates */
        //        static void secp256k1_ge_set_xy(secp256k1_ge* r, const secp256k1_fe* x, const secp256k1_fe* y);

        ///** Check whether a group element is the point at infinity. */
        //        static int secp256k1_ge_is_infinity(const secp256k1_ge* a);

        ///** Check whether a group element is valid (i.e., on the curve). */
        //        static int secp256k1_ge_is_valid_var(const secp256k1_ge* a);

        //        static void secp256k1_ge_neg(secp256k1_ge* r, const secp256k1_ge* a);

        ///** Bring a batch inputs given in jacobian coordinates (with known z-ratios) to
        // *  the same global z "denominator". zr must contain the known z-ratios such
        // *  that mul(a[i].z, zr[i+1]) == a[i+1].z. zr[0] is ignored. The x and y
        // *  coordinates of the result are stored in r, the common z coordinate is
        // *  stored in globalz. */
        //        static void secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge* r, secp256k1_fe* globalz, const secp256k1_gej* a, const secp256k1_fe* zr);

        ///** Set a group element (jacobian) equal to the point at infinity. */
        //        static void secp256k1_gej_set_infinity(secp256k1_gej* r);


        ///** Compare the X coordinate of a group element (jacobian). */
        //        static int secp256k1_gej_eq_x_var(const secp256k1_fe* x, const secp256k1_gej* a);

        ///** Check whether a group element is the point at infinity. */
        //        static int secp256k1_gej_is_infinity(const secp256k1_gej* a);

        ///** Check whether a group element's y coordinate is a quadratic residue. */
        //        static int secp256k1_gej_has_quad_y_var(const secp256k1_gej* a);

        ///** Set r equal to the double of a. If rzr is not-null, r.z = a.z * *rzr (where infinity means an implicit z = 0).
        // * a may not be zero. Constant time. */
        //        static void secp256k1_gej_double_nonzero(secp256k1_gej* r, const secp256k1_gej* a, secp256k1_fe* rzr);


        /// <summary>
        /// Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity).
        /// </summary>
        /// <param name="r"></param>
        /// <param name="a"></param>
        /// <param name="b"></param>
        public static void secp256k1_gej_add_ge(secp256k1_gej r, secp256k1_gej a, secp256k1_ge b)
        {
            /* Operations: 7 mul, 5 sqr, 4 normalize, 21 mul_int/add/negate/cmov */
#if USE_FIELD_10X26
#if VERIFY
            static const secp256k1_fe fe_1 = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);
            //#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)), 1, 1}
#else
            //static const secp256k1_fe fe_1 = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);
            secp256k1_fe fe_1 = new secp256k1_fe(new uint[10]
            {
                (1) & 0x3FFFFFF,
                (((UInt32) 1) >> 26) | (((UInt32) (0) & 0xFFFFF) << 6),
                (((UInt32) 0) >> 20) | (((UInt32) (0) & 0x3FFF) << 12),
                (((UInt32) 0) >> 14) | (((UInt32) (0) & 0xFF) << 18),
                (((UInt32) 0) >> 8) | (((UInt32) (0) & 0x3) << 24),
                (((UInt32) 0) >> 2) & 0x3FFFFFF,
                (((UInt32) 0) >> 28) | (((UInt32) (0) & 0x3FFFFF) << 4),
                (((UInt32) 0) >> 22) | (((UInt32) (0) & 0xFFFF) << 10),
                (((UInt32) 0) >> 16) | (((UInt32) (0) & 0x3FF) << 16),
                (((UInt32) 0) >> 10)
            });
#endif
#endif
            secp256k1_fe zz, u1, u2, s1, s2, t, tt, m, n, q, rr;
            secp256k1_fe m_alt, rr_alt;
            bool infinity, degenerate;
            if (b.infinity)
                throw new ArithmeticException();

            /** In:
             *    Eric Brier and Marc Joye, Weierstrass Elliptic Curves and Side-Channel Attacks.
             *    In D. Naccache and P. Paillier, Eds., Public Key Cryptography, vol. 2274 of Lecture Notes in Computer Science, pages 335-345. Springer-Verlag, 2002.
             *  we find as solution for a unified addition/doubling formula:
             *    lambda = ((x1 + x2)^2 - x1 * x2 + a) / (y1 + y2), with a = 0 for secp256k1's curve equation.
             *    x3 = lambda^2 - (x1 + x2)
             *    2*y3 = lambda * (x1 + x2 - 2 * x3) - (y1 + y2).
             *
             *  Substituting x_i = Xi / Zi^2 and yi = Yi / Zi^3, for i=1,2,3, gives:
             *    U1 = X1*Z2^2, U2 = X2*Z1^2
             *    S1 = Y1*Z2^3, S2 = Y2*Z1^3
             *    Z = Z1*Z2
             *    T = U1+U2
             *    M = S1+S2
             *    Q = T*M^2
             *    R = T^2-U1*U2
             *    X3 = 4*(R^2-Q)
             *    Y3 = 4*(R*(3*Q-2*R^2)-M^4)
             *    Z3 = 2*M*Z
             *  (Note that the paper uses xi = Xi / Zi and yi = Yi / Zi instead.)
             *
             *  This formula has the benefit of being the same for both addition
             *  of distinct points and doubling. However, it breaks down in the
             *  case that either point is infinity, or that y1 = -y2. We handle
             *  these cases in the following ways:
             *
             *    - If b is infinity we simply bail by means of a VERIFY_CHECK.
             *
             *    - If a is infinity, we detect this, and at the end of the
             *      computation replace the result (which will be meaningless,
             *      but we compute to be constant-time) with b.x : b.y : 1.
             *
             *    - If a = -b, we have y1 = -y2, which is a degenerate case.
             *      But here the answer is infinity, so we simply set the
             *      infinity flag of the result, overriding the computed values
             *      without even needing to cmov.
             *
             *    - If y1 = -y2 but x1 != x2, which does occur thanks to certain
             *      properties of our curve (specifically, 1 has nontrivial cube
             *      roots in our field, and the curve equation has no x coefficient)
             *      then the answer is not infinity but also not given by the above
             *      equation. In this case, we cmov in place an alternate expression
             *      for lambda. Specifically (y1 - y2)/(x1 - x2). Where both these
             *      expressions for lambda are defined, they are equal, and can be
             *      obtained from each other by multiplication by (y1 + y2)/(y1 + y2)
             *      then substitution of x^3 + 7 for y^2 (using the curve equation).
             *      For all pairs of nonzero points (a, b) at least one is defined,
             *      so this covers everything.
             */

            zz = new secp256k1_fe();
            Field.secp256k1_fe_sqr(zz, a.z);                       /* z = Z1^2 */
            u1 = a.x.Clone(); Field.secp256k1_fe_normalize_weak(u1);        /* u1 = U1 = X1*Z2^2 (1) */
            u2 = new secp256k1_fe();
            Field.secp256k1_fe_mul(u2, b.x, zz);                  /* u2 = U2 = X2*Z1^2 (1) */
            s1 = a.y.Clone(); Field.secp256k1_fe_normalize_weak(s1);        /* s1 = S1 = Y1*Z2^3 (1) */
            s2 = new secp256k1_fe();
            Field.secp256k1_fe_mul(s2, b.y, zz);                  /* s2 = Y2*Z1^2 (1) */
            Field.secp256k1_fe_mul(s2, s2, a.z);                  /* s2 = S2 = Y2*Z1^3 (1) */
            t = u1.Clone(); Field.secp256k1_fe_add(t, u2);                  /* t = T = U1+U2 (2) */
            m = s1.Clone(); Field.secp256k1_fe_add(m, s2);                  /* m = M = S1+S2 (2) */
            rr = new secp256k1_fe();
            Field.secp256k1_fe_sqr(rr, t);                          /* rr = T^2 (1) */
            m_alt = new secp256k1_fe();
            Field.secp256k1_fe_negate(m_alt, u2, 1);                /* Malt = -X2*Z1^2 */
            tt = new secp256k1_fe();
            Field.secp256k1_fe_mul(tt, u1, m_alt);                 /* tt = -U1*U2 (2) */
            Field.secp256k1_fe_add(rr, tt);                         /* rr = R = T^2-U1*U2 (3) */
                                                                    /** If lambda = R/M = 0/0 we have a problem (except in the "trivial"
                                                                     *  case that Z = z1z2 = 0, and this is special-cased later on). */
            degenerate = Field.secp256k1_fe_normalizes_to_zero(m) &&
                Field.secp256k1_fe_normalizes_to_zero(rr);
            /* This only occurs when y1 == -y2 and x1^3 == x2^3, but x1 != x2.
             * This means either x1 == beta*x2 or beta*x1 == x2, where beta is
             * a nontrivial cube root of one. In either case, an alternate
             * non-indeterminate expression for lambda is (y1 - y2)/(x1 - x2),
             * so we set R/M equal to this. */
            rr_alt = s1.Clone();
            Field.secp256k1_fe_mul_int(rr_alt, 2);       /* rr = Y1*Z2^3 - Y2*Z1^3 (2) */
            Field.secp256k1_fe_add(m_alt, u1);          /* Malt = X1*Z2^2 - X2*Z1^2 */

            Field.secp256k1_fe_cmov(rr_alt, rr, !degenerate);
            Field.secp256k1_fe_cmov(m_alt, m, !degenerate);
            /* Now Ralt / Malt = lambda and is guaranteed not to be 0/0.
             * From here on out Ralt and Malt represent the numerator
             * and denominator of lambda; R and M represent the explicit
             * expressions x1^2 + x2^2 + x1x2 and y1 + y2. */
            n = new secp256k1_fe();
            Field.secp256k1_fe_sqr(n, m_alt);                       /* n = Malt^2 (1) */
            q = new secp256k1_fe();
            Field.secp256k1_fe_mul(q, n, t);                       /* q = Q = T*Malt^2 (1) */
                                                                   /* These two lines use the observation that either M == Malt or M == 0,
                                                                    * so M^3 * Malt is either Malt^4 (which is computed by squaring), or
                                                                    * zero (which is "computed" by cmov). So the cost is one squaring
                                                                    * versus two multiplications. */
            Field.secp256k1_fe_sqr(n, n);
            Field.secp256k1_fe_cmov(n, m, degenerate);              /* n = M^3 * Malt (2) */
            Field.secp256k1_fe_sqr(t, rr_alt);                      /* t = Ralt^2 (1) */
            Field.secp256k1_fe_mul(r.z, a.z, m_alt);             /* r.z = Malt*Z (1) */
            infinity = !a.infinity && Field.secp256k1_fe_normalizes_to_zero(r.z);
            Field.secp256k1_fe_mul_int(r.z, 2);                     /* r.z = Z3 = 2*Malt*Z (2) */
            Field.secp256k1_fe_negate(q, q, 1);                     /* q = -Q (2) */
            Field.secp256k1_fe_add(t, q);                           /* t = Ralt^2-Q (3) */
            Field.secp256k1_fe_normalize_weak(t);
            r.x = t.Clone();                                           /* r.x = Ralt^2-Q (1) */
            Field.secp256k1_fe_mul_int(t, 2);                        /* t = 2*x3 (2) */
            Field.secp256k1_fe_add(t, q);                           /* t = 2*x3 - Q: (4) */
            Field.secp256k1_fe_mul(t, t, rr_alt);                  /* t = Ralt*(2*x3 - Q) (1) */
            Field.secp256k1_fe_add(t, n);                           /* t = Ralt*(2*x3 - Q) + M^3*Malt (3) */
            Field.secp256k1_fe_negate(r.y, t, 3);                  /* r.y = Ralt*(Q - 2x3) - M^3*Malt (4) */
            Field.secp256k1_fe_normalize_weak(r.y);
            Field.secp256k1_fe_mul_int(r.x, 4);                     /* r.x = X3 = 4*(Ralt^2-Q) */
            Field.secp256k1_fe_mul_int(r.y, 4);                     /* r.y = Y3 = 4*Ralt*(Q - 2x3) - 4*M^3*Malt (4) */

            /** In case a.infinity == 1, replace r with (b.x, b.y, 1). */
            Field.secp256k1_fe_cmov(r.x, b.x, a.infinity);
            Field.secp256k1_fe_cmov(r.y, b.y, a.infinity);
            Field.secp256k1_fe_cmov(r.z, fe_1, a.infinity);
            r.infinity = infinity;
        }


        ///** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
        //    than secp256k1_gej_add_var. It is identical to secp256k1_gej_add_ge but without constant-time
        //    guarantee, and b is allowed to be infinity. If rzr is non-null, r.z = a.z * *rzr (a cannot be infinity in that case). */
        //        static void secp256k1_gej_add_ge_var(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b, secp256k1_fe* rzr);

        ///** Set r equal to the sum of a and b (with the inverse of b's Z coordinate passed as bzinv). */
        //        static void secp256k1_gej_add_zinv_var(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b, const secp256k1_fe* bzinv);

        //#ifdef USE_ENDOMORPHISM
        ///** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
        //        static void secp256k1_ge_mul_lambda(secp256k1_ge* r, const secp256k1_ge* a);
        //#endif

        ///** Clear a secp256k1_gej to prevent leaking sensitive information. */
        //        static void secp256k1_gej_clear(secp256k1_gej* r);


        ///** Convert a group element to the storage type. */
        //        static void secp256k1_ge_to_storage(secp256k1_ge_storage* r, const secp256k1_ge* a);

        /// <summary>
        /// Convert a group element back from the storage type.
        /// </summary>
        /// <param name="r"></param>
        /// <param name=""></param>
        public static void secp256k1_ge_from_storage(secp256k1_ge r, secp256k1_ge_storage a)
        {
            Field.secp256k1_fe_from_storage(r.x, a.x);
            Field.secp256k1_fe_from_storage(r.y, a.y);
            r.infinity = false;
        }


        /// <summary>
        /// If flag is true, set *r equal to *a; otherwise leave it. Constant-time.
        /// </summary>
        public static void secp256k1_ge_storage_cmov(secp256k1_ge_storage r, secp256k1_ge_storage a, bool flag)
        {
            Field.secp256k1_fe_storage_cmov(r.x, a.x, flag);
            Field.secp256k1_fe_storage_cmov(r.y, a.y, flag);
        }


        ///* These points can be generated in sage as follows:
        // *
        // * 0. Setup a worksheet with the following parameters.
        // *   b = 4  # whatever CURVE_B will be set to
        // *   F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
        // *   C = EllipticCurve ([F (0), F (b)])
        // *
        // * 1. Determine all the small orders available to you. (If there are
        // *    no satisfactory ones, go back and change b.)
        // *   print C.order().factor(limit=1000)
        // *
        // * 2. Choose an order as one of the prime factors listed in the above step.
        // *    (You can also multiply some to get a composite order, though the
        // *    tests will crash trying to invert scalars during signing.) We take a
        // *    random point and scale it to drop its order to the desired value.
        // *    There is some probability this won't work; just try again.
        // *   order = 199
        // *   P = C.random_point()
        // *   P = (int(P.order()) / int(order)) * P
        // *   assert(P.order() == order)
        // *
        // * 3. Print the values. You'll need to use a vim macro or something to
        // *    split the hex output into 4-byte chunks.
        // *   print "%x %x" % P.xy()
        // */

#if EXHAUSTIVE_TEST_ORDER
//#if EXHAUSTIVE_TEST_ORDER == 199
//        public static secp256k1_ge secp256k1_ge_const_g = new secp256k1_ge(
//            new UInt32[10]
//            {
//                (UInt32) ((0x9EA66C18) & 0x3FFFFFFUL),
//                (UInt32) ((((UInt32) 0x9EA66C18) >> 26) | (((UInt32) (0xFB12940C) & 0xFFFFFUL) << 6)),
//                (UInt32) ((((UInt32) 0xFB12940C) >> 20) | (((UInt32) (0xA808C2F1) & 0x3FFFUL) << 12)),
//                (UInt32) ((((UInt32) 0xA808C2F1) >> 14) | (((UInt32) (0x3B017A7D) & 0xFFUL) << 18)),
//                (UInt32) ((((UInt32) 0x3B017A7D) >> 8) | (((UInt32) (0x2B4FB069) & 0x3UL) << 24)),
//                (UInt32) ((((UInt32) 0x2B4FB069) >> 2) & 0x3FFFFFFUL),
//                (UInt32) ((((UInt32) 0x2B4FB069) >> 28) | (((UInt32) (0xA749DD39) & 0x3FFFFFUL) << 4)),
//                (UInt32) ((((UInt32) 0xA749DD39) >> 22) | (((UInt32) (0x0737F2DB) & 0xFFFFUL) << 10)),
//                (UInt32) ((((UInt32) 0x0737F2DB) >> 16) | (((UInt32) (0xFA7CC9A7) & 0x3FFUL) << 16)),
//                (UInt32) ((((UInt32) 0xFA7CC9A7) >> 10))
//            },
//            new UInt32[10]
//            {
//                (UInt32) ((0x7F0501ED) & 0x3FFFFFFUL),
//                (UInt32) ((((UInt32) 0x7F0501ED) >> 26) | (((UInt32) (0xCFE52572) & 0xFFFFFUL) << 6)),
//                (UInt32) ((((UInt32) 0xCFE52572) >> 20) | (((UInt32) (0x808DAE72) & 0x3FFFUL) << 12)),
//                (UInt32) ((((UInt32) 0x808DAE72) >> 14) | (((UInt32) (0x48DF246C) & 0xFFUL) << 18)),
//                (UInt32) ((((UInt32) 0x48DF246C) >> 8) | (((UInt32) (0x1F3A2868) & 0x3UL) << 24)),
//                (UInt32) ((((UInt32) 0x1F3A2868) >> 2) & 0x3FFFFFFUL),
//                (UInt32) ((((UInt32) 0x1F3A2868) >> 28) | (((UInt32) (0x8732BC91) & 0x3FFFFFUL) << 4)),
//                (UInt32) ((((UInt32) 0x8732BC91) >> 22) | (((UInt32) (0x5ED8AEF3) & 0xFFFFUL) << 10)),
//                (UInt32) ((((UInt32) 0x5ED8AEF3) >> 16) | (((UInt32) (0x78AC123A) & 0x3FFUL) << 16)),
//                (UInt32) ((((UInt32) 0x78AC123A) >> 10))
//            });

//        const int CURVE_B = 4;
//#elif EXHAUSTIVE_TEST_ORDER == 13
//        public static secp256k1_ge secp256k1_ge_const_g = new secp256k1_ge(
//            new UInt32[10]
//            {
//                (UInt32) ((0x7277ef15) & 0x3FFFFFFUL),
//                (UInt32) ((((UInt32) 0x7277ef15) >> 26) | (((UInt32) (0x6cf4345c) & 0xFFFFFUL) << 6)),
//                (UInt32) ((((UInt32) 0x6cf4345c) >> 20) | (((UInt32) (0xa1316554) & 0x3FFFUL) << 12)),
//                (UInt32) ((((UInt32) 0xa1316554) >> 14) | (((UInt32) (0x9de54c3b) & 0xFFUL) << 18)),
//                (UInt32) ((((UInt32) 0x9de54c3b) >> 8) | (((UInt32) (0x4c9416c0) & 0x3UL) << 24)),
//                (UInt32) ((((UInt32) 0x4c9416c0) >> 2) & 0x3FFFFFFUL),
//                (UInt32) ((((UInt32) 0x4c9416c0) >> 28) | (((UInt32) (0x2ea91f4d) & 0x3FFFFFUL) << 4)),
//                (UInt32) ((((UInt32) 0x2ea91f4d) >> 22) | (((UInt32) (0xa51a786b) & 0xFFFFUL) << 10)),
//                (UInt32) ((((UInt32) 0xa51a786b) >> 16) | (((UInt32) (0xedc60018) & 0x3FFUL) << 16)),
//                (UInt32) ((((UInt32) 0xedc60018) >> 10))
//            },
//            new UInt32[10]
//            {
//                (UInt32) ((0x37adf8ac) & 0x3FFFFFFUL),
//                (UInt32) ((((UInt32) 0x37adf8ac) >> 26) | (((UInt32) (0x939f806d) & 0xFFFFFUL) << 6)),
//                (UInt32) ((((UInt32) 0x939f806d) >> 20) | (((UInt32) (0xf6effe55) & 0x3FFFUL) << 12)),
//                (UInt32) ((((UInt32) 0xf6effe55) >> 14) | (((UInt32) (0x0eaf9a43) & 0xFFUL) << 18)),
//                (UInt32) ((((UInt32) 0x0eaf9a43) >> 8) | (((UInt32) (0x43f4603e) & 0x3UL) << 24)),
//                (UInt32) ((((UInt32) 0x43f4603e) >> 2) & 0x3FFFFFFUL),
//                (UInt32) ((((UInt32) 0x43f4603e) >> 28) | (((UInt32) (0x087844ea) & 0x3FFFFFUL) << 4)),
//                (UInt32) ((((UInt32) 0x087844ea) >> 22) | (((UInt32) (0xdc8c1273) & 0xFFFFUL) << 10)),
//                (UInt32) ((((UInt32) 0xdc8c1273) >> 16) | (((UInt32) (0x54cb1b6b) & 0x3FFUL) << 16)),
//                (UInt32) ((((UInt32) 0x54cb1b6b) >> 10))
//            });
//        const int CURVE_B = 2;
//#else
//#error No known generator for the specified exhaustive test group order.
//#endif
#else
        /** Generator for secp256k1, value 'g' defined in
         *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
         */
        public static secp256k1_ge secp256k1_ge_const_g = new secp256k1_ge(
            new UInt32[10]
            {
                (UInt32) ((0x16F81798) & 0x3FFFFFF),
                (UInt32) ((((UInt32) 0x16F81798) >> 26) | (((UInt32) (0x59F2815B) & 0xFFFFF) << 6)),
                (UInt32) ((((UInt32) 0x59F2815B) >> 20) | (((UInt32) (0x2DCE28D9) & 0x3FFF) << 12)),
                (UInt32) ((((UInt32) 0x2DCE28D9) >> 14) | (((UInt32) (0x029BFCDB) & 0xFF) << 18)),
                (UInt32) ((((UInt32) 0x029BFCDB) >> 8) | (((UInt32) (0xCE870B07) & 0x3) << 24)),
                (UInt32) ((((UInt32) 0xCE870B07) >> 2) & 0x3FFFFFF),
                (UInt32) ((((UInt32) 0xCE870B07) >> 28) | (((UInt32) (0x55A06295) & 0x3FFFFF) << 4)),
                (UInt32) ((((UInt32) 0x55A06295) >> 22) | (((UInt32) (0xF9DCBBAC) & 0xFFFF) << 10)),
                (UInt32) ((((UInt32) 0xF9DCBBAC) >> 16) | (((UInt32) (0x79BE667E) & 0x3FF) << 16)),
                (UInt32) ((((UInt32) 0x79BE667E) >> 10))
            },
            new UInt32[10]
            {
                (UInt32) ((0xFB10D4B8) & 0x3FFFFFF),
                (UInt32) ((((UInt32) 0xFB10D4B8) >> 26) | (((UInt32) (0x9C47D08F) & 0xFFFFF) << 6)),
                (UInt32) ((((UInt32) 0x9C47D08F) >> 20) | (((UInt32) (0xA6855419) & 0x3FFF) << 12)),
                (UInt32) ((((UInt32) 0xA6855419) >> 14) | (((UInt32) (0xFD17B448) & 0xFF) << 18)),
                (UInt32) ((((UInt32) 0xFD17B448) >> 8) | (((UInt32) (0x0E1108A8) & 0x3) << 24)),
                (UInt32) ((((UInt32) 0x0E1108A8) >> 2) & 0x3FFFFFF),
                (UInt32) ((((UInt32) 0x0E1108A8) >> 28) | (((UInt32) (0x5DA4FBFC) & 0x3FFFFF) << 4)),
                (UInt32) ((((UInt32) 0x5DA4FBFC) >> 22) | (((UInt32) (0x26A3C465) & 0xFFFF) << 10)),
                (UInt32) ((((UInt32) 0x26A3C465) >> 16) | (((UInt32) (0x483ADA77) & 0x3FF) << 16)),
                (UInt32) ((((UInt32) 0x483ADA77) >> 10))
            });

        const int CURVE_B = 7;
#endif

        public static void secp256k1_ge_set_gej_zinv(secp256k1_ge r, secp256k1_gej a, secp256k1_fe zi)
        {
            secp256k1_fe zi2 = new secp256k1_fe();
            secp256k1_fe zi3 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(zi2, zi);
            Field.secp256k1_fe_mul(zi3, zi2, zi);
            Field.secp256k1_fe_mul(r.x, a.x, zi2);
            Field.secp256k1_fe_mul(r.y, a.y, zi3);
            r.infinity = a.infinity;
        }

        //static void secp256k1_ge_set_xy(secp256k1_ge* r, const secp256k1_fe* x, const secp256k1_fe* y)
        //{
        //r.infinity = 0;
        //r.x = *x;
        //r.y = *y;
        //}

        //static int secp256k1_ge_is_infinity(const secp256k1_ge* a)
        //{
        //return a.infinity;
        //}

        //static void secp256k1_ge_neg(secp256k1_ge* r, const secp256k1_ge* a)
        //{
        //*r = *a;
        //Field.secp256k1_fe_normalize_weak(r.y);
        //Field.secp256k1_fe_negate(r.y, r.y, 1);
        //}

        /// <summary>
        /// Set a group element equal to another which is given in jacobian coordinates
        /// </summary>
        /// <param name="r"></param>
        /// <param name="a"></param>
        public static void secp256k1_ge_set_gej(secp256k1_ge r, secp256k1_gej a)
        {
            secp256k1_fe z2 = new secp256k1_fe();
            secp256k1_fe z3 = new secp256k1_fe();
            r.infinity = a.infinity;
            Field.secp256k1_fe_inv(a.z, a.z);
            Field.secp256k1_fe_sqr(z2, a.z);
            Field.secp256k1_fe_mul(z3, a.z, z2);
            Field.secp256k1_fe_mul(a.x, a.x, z2);
            Field.secp256k1_fe_mul(a.y, a.y, z3);
            Field.secp256k1_fe_set_int(a.z, 1);
            r.x = a.x.Clone();
            r.y = a.y.Clone();
        }

        //static void secp256k1_ge_set_gej_var(secp256k1_ge* r, secp256k1_gej* a)
        //{
        //secp256k1_fe z2, z3;
        //r.infinity = a.infinity;
        //if (a.infinity)
        //{
        //return;
        //}
        //secp256k1_fe_inv_var(a.z, a.z);
        //Field.secp256k1_fe_sqr(z2, a.z);
        //Field.secp256k1_fe_mul(z3, a.z, z2);
        //Field.secp256k1_fe_mul(a.x, a.x, z2);
        //Field.secp256k1_fe_mul(a.y, a.y, z3);
        //secp256k1_fe_set_int(a.z, 1);
        //r.x = a.x.Clone();
        //r.y = a.y.Clone();
        //}

        /// <summary>
        /// Set a batch of group elements equal to the inputs given in jacobian coordinates
        /// </summary>
        /// <param name="r"></param>
        /// <param name=""></param>
        public static void secp256k1_ge_set_all_gej_var(secp256k1_ge[] r, secp256k1_gej[] a, int len, EventHandler<secp256k1_callback> cb)
        {
            secp256k1_fe[] az = new secp256k1_fe[len];
            int count = 0;
            for (int i = 0; i < len; i++)
            {
                if (!a[i].infinity)
                {
                    az[count++] = a[i].z.Clone(); ;
                }
            }

            secp256k1_fe[] azi = new secp256k1_fe[count];
            Field.secp256k1_fe_inv_all_var(azi, az, count);
            //free(az);

            count = 0;
            for (var i = 0; i < len; i++)
            {
                r[i].infinity = a[i].infinity;
                if (!a[i].infinity)
                {
                    secp256k1_ge_set_gej_zinv(r[i], a[i], azi[count++]);
                }
            }
            //free(azi);
        }


        /// <summary>
        ///  Set a batch of group elements equal to the inputs given in jacobian
        /// coordinates (with known z-ratios). zr must contain the known z-ratios such
        /// that mul(a[i].z, zr[i+1]) == a[i+1].z. zr[0] is ignored. 
        /// </summary>
        /// <param name="r"></param>
        /// <param name="a"></param>
        /// <param name="zr"></param>
        /// <param name="len"></param>
        public static void secp256k1_ge_set_table_gej_var(secp256k1_ge[] r, secp256k1_gej[] a, secp256k1_fe[] zr, int len)
        {
            int i = len - 1;
            secp256k1_fe zi = new secp256k1_fe();

            if (len > 0)
            {
                /* Compute the inverse of the last z coordinate, and use it to compute the last affine output. */
                Field.secp256k1_fe_inv(zi, a[i].z);
                secp256k1_ge_set_gej_zinv(r[i], a[i], zi);

                /* Work out way backwards, using the z-ratios to scale the x/y values. */
                while (i > 0)
                {
                    Field.secp256k1_fe_mul(zi, zi, zr[i]);
                    i--;
                    secp256k1_ge_set_gej_zinv(r[i], a[i], zi);
                }
            }
        }

        //static void secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge* r, secp256k1_fe* globalz, const secp256k1_gej* a, const secp256k1_fe* zr)
        //{
        //size_t i = len - 1;
        //secp256k1_fe zs;

        //if (len > 0)
        //{
        ///* The z of the final point gives us the "global Z" for the table. */
        //r[i].x = a[i].x;
        //r[i].y = a[i].y;
        //*globalz = a[i].z;
        //r[i].infinity = 0;
        //zs = zr[i];

        ///* Work our way backwards, using the z-ratios to scale the x/y values. */
        //while (i > 0)
        //{
        //if (i != len - 1)
        //{
        //Field.secp256k1_fe_mul(zs, zs, zr[i]);
        //}
        //i--;
        //secp256k1_ge_set_gej_zinv(r[i], a[i], zs);
        //}
        //}
        //}

        //static void secp256k1_gej_set_infinity(secp256k1_gej* r)
        //{
        //r.infinity = 1;
        //Field.secp256k1_fe_clear(r.x);
        //Field.secp256k1_fe_clear(r.y);
        //Field.secp256k1_fe_clear(r.z);
        //}

        public static void secp256k1_gej_clear(secp256k1_gej r)
        {
            r.infinity = false;
            Field.secp256k1_fe_clear(r.x);
            Field.secp256k1_fe_clear(r.y);
            Field.secp256k1_fe_clear(r.z);
        }

        /// <summary>
        /// Clear a secp256k1_ge to prevent leaking sensitive information.
        /// </summary>
        /// <param name="r"></param>
        public static void secp256k1_ge_clear(secp256k1_ge r)
        {
            r.infinity = false;
            Field.secp256k1_fe_clear(r.x);
            Field.secp256k1_fe_clear(r.y);
        }

        /// <summary>
        /// Set a group element (affine) equal to the point with the given X coordinate and a Y coordinate that is a quadratic residue modulo p. 
        /// The return value is true iff a coordinate with the given X coordinate exists.
        /// </summary>
        /// <param name="r"></param>
        /// <param name=""></param>
        /// <returns></returns>
        public static bool secp256k1_ge_set_xquad(secp256k1_ge r, secp256k1_fe x)
        {
            secp256k1_fe x2, x3, c;
            r.x = x.Clone();
            x2 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(x2, x);
            x3 = new secp256k1_fe();
            Field.secp256k1_fe_mul(x3, x, x2);
            r.infinity = false;
            c = new secp256k1_fe();
            Field.secp256k1_fe_set_int(c, CURVE_B);
            Field.secp256k1_fe_add(c, x3);
            return Field.secp256k1_fe_sqrt(r.y, c);
        }

        /// <summary>
        /// Set a group element (affine) equal to the point with the given X coordinate, and given oddness for Y. Return value indicates whether the result is valid.
        /// </summary>
        /// <param name="r"></param>
        /// <param name="x"></param>
        /// <param name="odd"></param>
        /// <returns></returns>
        public static bool secp256k1_ge_set_xo_var(secp256k1_ge r, secp256k1_fe x, bool odd)
        {
            if (!secp256k1_ge_set_xquad(r, x))
                return false;

            Field.secp256k1_fe_normalize_var(r.y);
            if (Field.secp256k1_fe_is_odd(r.y) != odd)
            {
                Field.secp256k1_fe_negate(r.y, r.y, 1);
            }
            return true;
        }

        /// <summary>
        ///  Set a group element (jacobian) equal to another which is given in affine coordinates.
        /// </summary>
        /// <param name="r"></param>
        /// <param name="a"></param>
        public static void secp256k1_gej_set_ge(secp256k1_gej r, secp256k1_ge a)
        {
            r.infinity = a.infinity;
            r.x = a.x.Clone();
            r.y = a.y.Clone();
            Field.secp256k1_fe_set_int(r.z, 1);
        }

        //static int secp256k1_gej_eq_x_var(const secp256k1_fe* x, const secp256k1_gej* a)
        //{
        //secp256k1_fe r, r2;
        //Util.VERIFY_CHECK(!a.infinity);
        //Field.secp256k1_fe_sqr(r, a.z); Field.secp256k1_fe_mul(r, r, x);
        //r2 = a.x; Field.secp256k1_fe_normalize_weak(r2);
        //return secp256k1_fe_equal_var(r, r2);
        //}

        /// <summary>
        /// Set r equal to the inverse of a (i.e., mirrored around the X axis)
        /// </summary>
        /// <param name="r"></param>
        /// <param name=""></param>
        public static void secp256k1_gej_neg(secp256k1_gej r, secp256k1_gej a)
        {
            r.infinity = a.infinity;
            r.x = a.x.Clone();
            r.y = a.y.Clone();
            r.z = a.z.Clone();
            Field.secp256k1_fe_normalize_weak(r.y);
            Field.secp256k1_fe_negate(r.y, r.y, 1);
        }

        //static int secp256k1_gej_is_infinity(const secp256k1_gej* a)
        //{
        //return a.infinity;
        //}

        //static int secp256k1_gej_is_valid_var(const secp256k1_gej* a)
        //{
        //secp256k1_fe y2, x3, z2, z6;
        //if (a.infinity)
        //{
        //return 0;
        //}
        ///** y^2 = x^3 + 7
        // *  (Y/Z^3)^2 = (X/Z^2)^3 + 7
        // *  Y^2 / Z^6 = X^3 / Z^6 + 7
        // *  Y^2 = X^3 + 7*Z^6
        // */
        //Field.secp256k1_fe_sqr(y2, a.y);
        //Field.secp256k1_fe_sqr(x3, a.x); Field.secp256k1_fe_mul(x3, x3, a.x);
        //Field.secp256k1_fe_sqr(z2, a.z);
        //Field.secp256k1_fe_sqr(z6, z2); Field.secp256k1_fe_mul(z6, z6, z2);
        //Field.secp256k1_fe_mul_int(z6, CURVE_B);
        //Field.secp256k1_fe_add(x3, z6);
        //Field.secp256k1_fe_normalize_weak(x3);
        //return secp256k1_fe_equal_var(y2, x3);
        //}

        //static int secp256k1_ge_is_valid_var(const secp256k1_ge* a)
        //{
        //secp256k1_fe y2, x3, c;
        //if (a.infinity)
        //{
        //return 0;
        //}
        ///* y^2 = x^3 + 7 */
        //Field.secp256k1_fe_sqr(y2, a.y);
        //Field.secp256k1_fe_sqr(x3, a.x); Field.secp256k1_fe_mul(x3, x3, a.x);
        //secp256k1_fe_set_int(c, CURVE_B);
        //Field.secp256k1_fe_add(x3, c);
        //Field.secp256k1_fe_normalize_weak(x3);
        //return secp256k1_fe_equal_var(y2, x3);
        //}

        /// <summary>
        /// Set r equal to the double of a. If rzr is not-null, r.z = a.z * *rzr (where infinity means an implicit z = 0).
        /// </summary>
        /// <param name="r"></param>
        /// <param name=""></param>
        public static void secp256k1_gej_double_var(secp256k1_gej r, secp256k1_gej a, secp256k1_fe rzr)
        {
            /* Operations: 3 mul, 4 sqr, 0 normalize, 12 mul_int/add/negate.
             *
             * Note that there is an implementation described at
             *     https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
             * which trades a multiply for a square, but in practice this is actually slower,
             * mainly because it requires more normalizations.
             */
            secp256k1_fe t1, t2, t3, t4;
            /** For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
             *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
             *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
             *
             *  Having said this, if this function receives a point on a sextic twist, e.g. by
             *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
             *  since -6 does have a cube root mod p. For this point, this function will not set
             *  the infinity flag even though the point doubles to infinity, and the result
             *  point will be gibberish (z = 0 but infinity = 0).
             */
            r.infinity = a.infinity;
            if (r.infinity)
            {
                if (rzr != null)
                {
                    Field.secp256k1_fe_set_int(rzr, 1);
                }
                return;
            }

            if (rzr != null)
            {
                rzr = a.y.Clone();
                Field.secp256k1_fe_normalize_weak(rzr);
                Field.secp256k1_fe_mul_int(rzr, 2);
            }

            Field.secp256k1_fe_mul(r.z, a.z, a.y);
            Field.secp256k1_fe_mul_int(r.z, 2);       /* Z' = 2*Y*Z (2) */
            t1 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(t1, a.x);
            Field.secp256k1_fe_mul_int(t1, 3);         /* T1 = 3*X^2 (3) */
            t2 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(t2, t1);           /* T2 = 9*X^4 (1) */
            t3 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(t3, a.y);
            Field.secp256k1_fe_mul_int(t3, 2);         /* T3 = 2*Y^2 (2) */
            t4 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(t4, t3);
            Field.secp256k1_fe_mul_int(t4, 2);         /* T4 = 8*Y^4 (2) */
            Field.secp256k1_fe_mul(t3, t3, a.x);    /* T3 = 2*X*Y^2 (1) */
            r.x = t3.Clone();
            Field.secp256k1_fe_mul_int(r.x, 4);       /* X' = 8*X*Y^2 (4) */
            Field.secp256k1_fe_negate(r.x, r.x, 4); /* X' = -8*X*Y^2 (5) */
            Field.secp256k1_fe_add(r.x, t2);         /* X' = 9*X^4 - 8*X*Y^2 (6) */
            Field.secp256k1_fe_negate(t2, t2, 1);     /* T2 = -9*X^4 (2) */
            Field.secp256k1_fe_mul_int(t3, 6);         /* T3 = 12*X*Y^2 (6) */
            Field.secp256k1_fe_add(t3, t2);           /* T3 = 12*X*Y^2 - 9*X^4 (8) */
            Field.secp256k1_fe_mul(r.y, t1, t3);    /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
            Field.secp256k1_fe_negate(t2, t4, 2);     /* T2 = -8*Y^4 (3) */
            Field.secp256k1_fe_add(r.y, t2);         /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */
        }

        //static SECP256K1_INLINE void secp256k1_gej_double_nonzero(secp256k1_gej* r, const secp256k1_gej* a, secp256k1_fe* rzr)
        //{
        //Util.VERIFY_CHECK(!secp256k1_gej_is_infinity(a));
        //secp256k1_gej_double_var(r, a, rzr);
        //}

        /// <summary>
        /// Set r equal to the sum of a and b. If rzr is non-null, r.z = a.z * *rzr (a cannot be infinity in that case).
        /// </summary>
        /// <param name="r"></param>
        /// <param name=""></param>
        public static void secp256k1_gej_add_var(secp256k1_gej r, secp256k1_gej a, secp256k1_gej b, secp256k1_fe rzr)
        {
            /* Operations: 12 mul, 4 sqr, 2 normalize, 12 mul_int/add/negate */
            secp256k1_fe z22, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

            if (a.infinity)
            {
                Util.VERIFY_CHECK(rzr == null);
                r = b.Clone();
                return;
            }

            if (b.infinity)
            {
                if (rzr != null)
                {
                    Field.secp256k1_fe_set_int(rzr, 1);
                }
                r = a.Clone();
                return;
            }

            r.infinity = false;
            z22 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(z22, b.z);
            z12 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(z12, a.z);
            u1 = new secp256k1_fe();
            Field.secp256k1_fe_mul(u1, a.x, z22);
            u2 = new secp256k1_fe();
            Field.secp256k1_fe_mul(u2, b.x, z12);
            s1 = new secp256k1_fe();
            Field.secp256k1_fe_mul(s1, a.y, z22); Field.secp256k1_fe_mul(s1, s1, b.z);
            s2 = new secp256k1_fe();
            Field.secp256k1_fe_mul(s2, b.y, z12); Field.secp256k1_fe_mul(s2, s2, a.z);
            h = new secp256k1_fe();
            Field.secp256k1_fe_negate(h, u1, 1); Field.secp256k1_fe_add(h, u2);
            i = new secp256k1_fe();
            Field.secp256k1_fe_negate(i, s1, 1); Field.secp256k1_fe_add(i, s2);
            if (Field.secp256k1_fe_normalizes_to_zero_var(h))
            {
                if (Field.secp256k1_fe_normalizes_to_zero_var(i))
                {
                    secp256k1_gej_double_var(r, a, rzr);
                }
                else
                {
                    if (rzr != null)
                    {
                        Field.secp256k1_fe_set_int(rzr, 0);
                    }
                    r.infinity = true;
                }
                return;
            }
            i2 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(i2, i);
            h2 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(h2, h);
            h3 = new secp256k1_fe();
            Field.secp256k1_fe_mul(h3, h, h2);
            Field.secp256k1_fe_mul(h, h, b.z);
            if (rzr != null)
            {
                rzr = h.Clone();
            }
            Field.secp256k1_fe_mul(r.z, a.z, h);
            t = new secp256k1_fe();
            Field.secp256k1_fe_mul(t, u1, h2);
            r.x = t.Clone(); Field.secp256k1_fe_mul_int(r.x, 2); Field.secp256k1_fe_add(r.x, h3); Field.secp256k1_fe_negate(r.x, r.x, 3); Field.secp256k1_fe_add(r.x, i2);
            Field.secp256k1_fe_negate(r.y, r.x, 5); Field.secp256k1_fe_add(r.y, t); Field.secp256k1_fe_mul(r.y, r.y, i);
            Field.secp256k1_fe_mul(h3, h3, s1); Field.secp256k1_fe_negate(h3, h3, 1);
            Field.secp256k1_fe_add(r.y, h3);
        }

        public static void secp256k1_gej_add_ge_var(secp256k1_gej r, secp256k1_gej a, secp256k1_ge b, secp256k1_fe rzr)
        {
            /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
            if (a.infinity)
            {
                Util.VERIFY_CHECK(rzr == null);
                secp256k1_gej_set_ge(r, b);
                return;
            }
            if (b.infinity)
            {
                if (rzr != null)
                {
                    Field.secp256k1_fe_set_int(rzr, 1);
                }
                r = a.Clone();
                return;
            }
            r.infinity = false;

            var z12 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(z12, a.z);
            var u1 = a.x.Clone(); Field.secp256k1_fe_normalize_weak(u1);
            var u2 = new secp256k1_fe();
            Field.secp256k1_fe_mul(u2, b.x, z12);
            var s1 = a.y.Clone(); Field.secp256k1_fe_normalize_weak(s1);
            var s2 = new secp256k1_fe();
            Field.secp256k1_fe_mul(s2, b.y, z12); Field.secp256k1_fe_mul(s2, s2, a.z);
            var h = new secp256k1_fe();
            Field.secp256k1_fe_negate(h, u1, 1); Field.secp256k1_fe_add(h, u2);
            var i = new secp256k1_fe();
            Field.secp256k1_fe_negate(i, s1, 1); Field.secp256k1_fe_add(i, s2);
            if (Field.secp256k1_fe_normalizes_to_zero_var(h))
            {
                if (Field.secp256k1_fe_normalizes_to_zero_var(i))
                {
                    secp256k1_gej_double_var(r, a, rzr);
                }
                else
                {
                    if (rzr != null)
                    {
                        Field.secp256k1_fe_set_int(rzr, 0);
                    }
                    r.infinity = true;
                }
                return;
            }
            var i2 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(i2, i);
            var h2 = new secp256k1_fe();
            Field.secp256k1_fe_sqr(h2, h);
            var h3 = new secp256k1_fe();
            Field.secp256k1_fe_mul(h3, h, h2);
            if (rzr != null)
            {
                rzr = h.Clone();
            }
            Field.secp256k1_fe_mul(r.z, a.z, h);
            var t = new secp256k1_fe();
            Field.secp256k1_fe_mul(t, u1, h2);
            r.x = t.Clone(); Field.secp256k1_fe_mul_int(r.x, 2); Field.secp256k1_fe_add(r.x, h3); Field.secp256k1_fe_negate(r.x, r.x, 3); Field.secp256k1_fe_add(r.x, i2);
            Field.secp256k1_fe_negate(r.y, r.x, 5); Field.secp256k1_fe_add(r.y, t); Field.secp256k1_fe_mul(r.y, r.y, i);
            Field.secp256k1_fe_mul(h3, h3, s1); Field.secp256k1_fe_negate(h3, h3, 1);
            Field.secp256k1_fe_add(r.y, h3);
        }

        //static void secp256k1_gej_add_zinv_var(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b, const secp256k1_fe* bzinv)
        //{
        ///* 9 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
        //secp256k1_fe az, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

        //if (b.infinity)
        //{
        //*r = *a;
        //return;
        //}
        //if (a.infinity)
        //{
        //secp256k1_fe bzinv2, bzinv3;
        //r.infinity = b.infinity;
        //Field.secp256k1_fe_sqr(bzinv2, bzinv);
        //Field.secp256k1_fe_mul(bzinv3, bzinv2, bzinv);
        //Field.secp256k1_fe_mul(r.x, b.x, bzinv2);
        //Field.secp256k1_fe_mul(r.y, b.y, bzinv3);
        //secp256k1_fe_set_int(r.z, 1);
        //return;
        //}
        //r.infinity = 0;

        ///** We need to calculate (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Due to
        // *  secp256k1's isomorphism we can multiply the Z coordinates on both sides
        // *  by bzinv, and get: (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1).
        // *  This means that (rx,ry,rz) can be calculated as
        // *  (ax,ay,az*bzinv) + (bx,by,1), when not applying the bzinv factor to rz.
        // *  The variable az below holds the modified Z coordinate for a, which is used
        // *  for the computation of rx and ry, but not for rz.
        // */
        //Field.secp256k1_fe_mul(az, a.z, bzinv);

        //Field.secp256k1_fe_sqr(z12, az);
        //u1 = a.x.Clone(); Field.secp256k1_fe_normalize_weak(u1);
        //Field.secp256k1_fe_mul(u2, b.x, z12);
        //s1 = a.y.Clone(); Field.secp256k1_fe_normalize_weak(s1);
        //Field.secp256k1_fe_mul(s2, b.y, z12); Field.secp256k1_fe_mul(s2, s2, az);
        //Field.secp256k1_fe_negate(h, u1, 1); Field.secp256k1_fe_add(h, u2);
        //Field.secp256k1_fe_negate(i, s1, 1); Field.secp256k1_fe_add(i, s2);
        //if (secp256k1_fe_normalizes_to_zero_var(h))
        //{
        //if (secp256k1_fe_normalizes_to_zero_var(i))
        //{
        //secp256k1_gej_double_var(r, a, null);
        //}
        //else
        //{
        //r.infinity = 1;
        //}
        //return;
        //}
        //Field.secp256k1_fe_sqr(i2, i);
        //Field.secp256k1_fe_sqr(h2, h);
        //Field.secp256k1_fe_mul(h3, h, h2);
        //r.z = a.z.Clone(); Field.secp256k1_fe_mul(r.z, r.z, h);
        //Field.secp256k1_fe_mul(t, u1, h2);
        //r.x = t.Clone(); Field.secp256k1_fe_mul_int(r.x, 2); Field.secp256k1_fe_add(r.x, h3); Field.secp256k1_fe_negate(r.x, r.x, 3); Field.secp256k1_fe_add(r.x, i2);
        //Field.secp256k1_fe_negate(r.y, r.x, 5); Field.secp256k1_fe_add(r.y, t); Field.secp256k1_fe_mul(r.y, r.y, i);
        //Field.secp256k1_fe_mul(h3, h3, s1); Field.secp256k1_fe_negate(h3, h3, 1);
        //Field.secp256k1_fe_add(r.y, h3);
        //}

        /// <summary>
        /// Rescale a jacobian point by b which must be non-zero. Constant-time.
        /// </summary>
        /// <param name="r"></param>
        /// <param name=""></param>
        public static void secp256k1_gej_rescale(secp256k1_gej r, secp256k1_fe s)
        {
            /* Operations: 4 mul, 1 sqr */
            secp256k1_fe zz = new secp256k1_fe();
            Util.VERIFY_CHECK(!Field.secp256k1_fe_is_zero(s));
            Field.secp256k1_fe_sqr(zz, s);
            Field.secp256k1_fe_mul(r.x, r.x, zz);                /* r.x *= s^2 */
            Field.secp256k1_fe_mul(r.y, r.y, zz);
            Field.secp256k1_fe_mul(r.y, r.y, s);                  /* r.y *= s^3 */
            Field.secp256k1_fe_mul(r.z, r.z, s);                  /* r.z *= s   */
        }

        public static void secp256k1_ge_to_storage(secp256k1_ge_storage r, secp256k1_ge a)
        {
            secp256k1_fe x, y;
            Util.VERIFY_CHECK(!a.infinity);
            x = a.x.Clone();
            Field.secp256k1_fe_normalize(x);
            y = a.y.Clone();
            Field.secp256k1_fe_normalize(y);
            Field.secp256k1_fe_to_storage(r.x, x);
            Field.secp256k1_fe_to_storage(r.y, y);
        }


        //static SECP256K1_INLINE void secp256k1_ge_storage_cmov(secp256k1_ge_storage* r, const secp256k1_ge_storage* a, int flag)
        //{
        //secp256k1_fe_storage_cmov(r.x, a.x, flag);
        //secp256k1_fe_storage_cmov(r.y, a.y, flag);
        //}

        //#ifdef USE_ENDOMORPHISM
        //static void secp256k1_ge_mul_lambda(secp256k1_ge* r, const secp256k1_ge* a)
        //{
        //static const secp256k1_fe beta = SECP256K1_FE_CONST(
        //0x7ae96a2bul, 0x657c0710ul, 0x6e64479eul, 0xac3434e9ul,
        //0x9cf04975ul, 0x12f58995ul, 0xc1396c28ul, 0x719501eeul
        //);
        //*r = *a;
        //Field.secp256k1_fe_mul(r.x, r.x, beta);
        //}
        //#endif

        //static int secp256k1_gej_has_quad_y_var(const secp256k1_gej* a)
        //{
        //secp256k1_fe yz;

        //if (a.infinity)
        //{
        //return 0;
        //}

        ///* We rely on the fact that the Jacobi symbol of 1 / a.z^3 is the same as
        // * that of a.z. Thus a.y / a.z^3 is a quadratic residue iff a.y * a.z
        //   is */
        //Field.secp256k1_fe_mul(yz, a.y, a.z);
        //return secp256k1_fe_is_quad_var(yz);
        //}

        //#endif
    }
}