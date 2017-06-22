using System;
using System.Text;

namespace Cryptography.ECDSA
{
    internal class ECMultGen
    {
        public static void secp256k1_ecmult_gen_context_init(secp256k1_ecmult_gen_context ctx)
        {
            ctx.prec = null;
        }

        public static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context ctx, EventHandler<secp256k1_callback> cb)
        {
#if !USE_ECMULT_STATIC_PRECOMPUTATION
            secp256k1_ge[] prec = new secp256k1_ge[1024];
            secp256k1_gej gj = new secp256k1_gej();
            secp256k1_gej nums_gej = new secp256k1_gej();
            int i, j;
#endif

            if (ctx.prec != null)
            {
                return;
            }
#if !USE_ECMULT_STATIC_PRECOMPUTATION
            ctx.PrecInit();

            /* get the generator */
            Group.secp256k1_gej_set_ge(gj, Group.secp256k1_ge_const_g);

            /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
            {
                var nums_b32 = Encoding.UTF8.GetBytes("The scalar for this x is unknown");
                secp256k1_fe nums_x = new secp256k1_fe();
                secp256k1_ge nums_ge = new secp256k1_ge();
                var r = Field.secp256k1_fe_set_b32(nums_x, nums_b32);
                //(void)r;
                Util.VERIFY_CHECK(r);
                r = Group.secp256k1_ge_set_xo_var(nums_ge, nums_x, false);
                //(void)r;
                Util.VERIFY_CHECK(r);
                Group.secp256k1_gej_set_ge(nums_gej, nums_ge);
                /* Add G to make the bits in x uniformly distributed. */
                Group.secp256k1_gej_add_ge_var(nums_gej, nums_gej, Group.secp256k1_ge_const_g, null);
            }

            /* compute prec. */
            {
                secp256k1_gej[] precj = new secp256k1_gej[1024]; /* Jacobian versions of prec. */
                for (int k = 0; k < precj.Length; k++)
                    precj[k] = new secp256k1_gej();
                secp256k1_gej gbase;
                secp256k1_gej numsbase;
                gbase = gj.Clone(); /* 16^j * G */
                numsbase = nums_gej.Clone(); /* 2^j * nums. */
                for (j = 0; j < 64; j++)
                {
                    /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
                    precj[j * 16] = numsbase.Clone();
                    for (i = 1; i < 16; i++)
                    {
                        Group.secp256k1_gej_add_var(precj[j * 16 + i], precj[j * 16 + i - 1], gbase, null);
                    }
                    /* Multiply gbase by 16. */
                    for (i = 0; i < 4; i++)
                    {
                        Group.secp256k1_gej_double_var(gbase, gbase, null);
                    }
                    /* Multiply numbase by 2. */
                    Group.secp256k1_gej_double_var(numsbase, numsbase, null);
                    if (j == 62)
                    {
                        /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                        Group.secp256k1_gej_neg(numsbase, numsbase);
                        Group.secp256k1_gej_add_var(numsbase, numsbase, nums_gej, null);
                    }
                }
                for (int k = 0; k < prec.Length; k++)
                    prec[k] = new secp256k1_ge();
                Group.secp256k1_ge_set_all_gej_var(prec, precj, 1024, cb);
            }
            for (j = 0; j < 64; j++)
            {
                for (i = 0; i < 16; i++)
                {
                    Group.secp256k1_ge_to_storage(ctx.prec[j][i], prec[j * 16 + i]);
                }
            }
#else
            (void)cb;
            ctx.prec = (secp256k1_ge_storage(*)[64][16])secp256k1_ecmult_static_context;
#endif
            secp256k1_ecmult_gen_blind(ctx, null);
        }

        public static bool secp256k1_ecmult_gen_context_is_built(secp256k1_ecmult_gen_context ctx)
        {
            return ctx.prec != null;
        }

        //static void secp256k1_ecmult_gen_context_clone(secp256k1_ecmult_gen_context* dst,
        //                                               const secp256k1_ecmult_gen_context* src, secp256k1_callback* cb)
        //{
        //    if (src.prec == null)
        //    {
        //        dst.prec = null;
        //    }
        //    else
        //    {
        //#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
        //        dst.prec = (secp256k1_ge_storage(*)[64][16])checked_malloc(cb, sizeof(*dst.prec));
        //        memcpy(dst.prec, src.prec, sizeof(*dst.prec));
        //#else
        //        (void)cb;
        //        dst.prec = src.prec;
        //#endif
        //        dst.initial = src.initial;
        //        dst.blind = src.blind;
        //    }
        //}

        //static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context* ctx)
        //{
        //#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
        //    free(ctx.prec);
        //#endif
        //    secp256k1_scalar_clear(ctx.blind);
        //    secp256k1_gej_clear(ctx.initial);
        //    ctx.prec = null;
        //}


        /// <summary>
        /// Multiply with the generator: R = a*G
        /// </summary>
        public static void secp256k1_ecmult_gen(secp256k1_ecmult_gen_context ctx, out secp256k1_gej r, secp256k1_scalar gn)
        {
            secp256k1_ge add = new secp256k1_ge();
            secp256k1_ge_storage adds = new secp256k1_ge_storage();
            secp256k1_scalar gnb = new secp256k1_scalar();
            uint bits;
            //Util.MemSet(adds,0,); //memset(adds, 0, sizeof(adds));
            r = ctx.initial.Clone();
            /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
            Scalar.secp256k1_scalar_add(gnb, gn, ctx.blind);
            add.infinity = false;
            for (var j = 0; j < 64; j++)
            {
                bits = Scalar.secp256k1_scalar_get_bits(gnb, j * 4, 4);
                for (var i = 0; i < 16; i++)
                {
                    /** This uses a conditional move to avoid any secret data in array indexes.
                     *   _Any_ use of secret indexes has been demonstrated to result in timing
                     *   sidechannels, even when the cache-line access patterns are uniform.
                     *  See also:
                     *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
                     *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
                     *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
                     *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
                     *    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
                     */
                    Group.secp256k1_ge_storage_cmov(adds, ctx.prec[j][i], i == bits);
                }
                Group.secp256k1_ge_from_storage(add, adds);
                Group.secp256k1_gej_add_ge(r, r, add);
            }
            bits = 0;
            Group.secp256k1_ge_clear(add);
            Scalar.secp256k1_scalar_clear(gnb);
        }

        /* Setup blinding values for secp256k1_ecmult_gen. */
        public static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context ctx, byte[] seed32)
        {
            secp256k1_scalar b = new secp256k1_scalar();
            secp256k1_gej gb;
            secp256k1_fe s = new secp256k1_fe();
            var nonce32 = new byte[32];
            secp256k1_rfc6979_hmac_sha256_t rng = new secp256k1_rfc6979_hmac_sha256_t();
            bool retry;
            var keydata = new byte[64];
            if (seed32 == null)
            {
                /* When seed is null, reset the initial point and blinding value. */
                Group.secp256k1_gej_set_ge(ctx.initial, Group.secp256k1_ge_const_g);
                Group.secp256k1_gej_neg(ctx.initial, ctx.initial);
                Scalar.secp256k1_scalar_set_int(ctx.blind, 1);
            }
            /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
            Scalar.secp256k1_scalar_get_b32(nonce32, ctx.blind);
            /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
             *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
             *   asking the caller for blinding values directly and expecting them to retry on failure.
             */
            Util.Memcpy(nonce32, 0, keydata, 0, 32); //memcpy(keydata, nonce32, 32);
            if (seed32 != null)
            {
                Util.Memcpy(seed32, 0, keydata, 32, 32); //memcpy(keydata + 32, seed32, 32);
            }
            Hash.secp256k1_rfc6979_hmac_sha256_initialize(rng, keydata, (UInt32)(seed32 != null ? 64 : 32));
            Util.MemSet(keydata, 0, keydata.Length); //memset(keydata, 0, sizeof(keydata));
            /* Retry for out of range results to achieve uniformity. */
            do
            {
                Hash.secp256k1_rfc6979_hmac_sha256_generate(rng, nonce32, 32);
                retry = !Field.secp256k1_fe_set_b32(s, nonce32);
                retry |= Field.secp256k1_fe_is_zero(s);
            } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
            /* Randomize the projection to defend against multiplier sidechannels. */
            Group.secp256k1_gej_rescale(ctx.initial, s);
            Field.secp256k1_fe_clear(s);
            do
            {
                Hash.secp256k1_rfc6979_hmac_sha256_generate(rng, nonce32, 32);
                Scalar.secp256k1_scalar_set_b32(b, nonce32, ref retry);
                /* A blinding value of 0 works, but would undermine the projection hardening. */
                retry |= Scalar.secp256k1_scalar_is_zero(b);
            } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > order. */
            Hash.secp256k1_rfc6979_hmac_sha256_finalize(rng);
            Util.MemSet(nonce32, 0, 32);//memset(nonce32, 0, 32);
            secp256k1_ecmult_gen(ctx, out gb, b);
            Scalar.secp256k1_scalar_negate(b, b);
            ctx.blind = b.Clone();
            ctx.initial = gb.Clone();
            Scalar.secp256k1_scalar_clear(b);
            Group.secp256k1_gej_clear(gb);
        }
    }
}