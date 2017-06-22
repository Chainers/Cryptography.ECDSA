using System;

namespace Cryptography.ECDSA
{

    #region From C macros to С# regexp

    //  #define ARG_CHECK(cond) do { \
    //      if (EXPECT(!(cond), 0)) { \
    //          secp256k1_callback_call(&ctx->illegal_callback, #cond); \
    //          return 0; \
    //      } \
    //  } while(0)
    //>>>>>>>>>
    // pattern:
    //     ARG_CHECK\((?<cond>[0-9a-zA-Z\.\[\]_]*)\);
    // replacement:
    //     if (!(${cond}))
    //     {
    //           secp256k1_callback_call(ctx.illegal_callback, (${cond}));
    //           return 0;
    //     }
    //     //___________________________________________________________________________________________________________________________________

    #endregion From C macros to С# regexp

    public class secp256k1_callback : EventArgs
    {
        public secp256k1_callback()
        {
        }

        public secp256k1_callback(string message)
        {
            Message = message;
        }

        public string Message;
    }


    public class Secp256k1Manager
    {
        [Flags]
        private enum Secp256K1Options : uint
        {
            // All flags' lower 8 bits indicate what they're for. Do not use directly.
            FlagsTypeMask = ((1 << 8) - 1),
            FlagsTypeContext = (1 << 0),
            FlagsTypeCompression = (1 << 1),
            // The higher bits contain the actual data. Do not use directly. 
            FlagsBitContextVerify = (1 << 8),
            FlagsBitContextSign = (1 << 9),
            FlagsBitCompression = (1 << 8),

            /** Flags to pass to secp256k1_context_create. */
            ContextVerify = (FlagsTypeContext | FlagsBitContextVerify),
            ContextSign = (FlagsTypeContext | FlagsBitContextSign),
            ContextNone = (FlagsTypeContext),

            /** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
            EcCompressed = (FlagsTypeCompression | FlagsBitCompression),
            EcUncompressed = (FlagsTypeCompression)
        }

        private static secp256k1_context Ctx;

        public static event EventHandler<secp256k1_callback> IllegalCallback;
        public static event EventHandler<secp256k1_callback> ErrorCallback;

        static Secp256k1Manager()
        {
            IllegalCallback += OnIllegalCallback;
            ErrorCallback += OnErrorCallback;
            Ctx = new secp256k1_context();
            Ctx = secp256k1_context_create(Secp256K1Options.ContextSign | Secp256K1Options.ContextVerify);
        }

        private static void OnErrorCallback(object sender, secp256k1_callback secp256K1Callback)
        {
        }

        private static void OnIllegalCallback(object sender, secp256k1_callback secp256K1Callback)
        {
        }


        private static secp256k1_context secp256k1_context_create(Secp256K1Options flags)
        {
            var ret = new secp256k1_context
            {
                illegal_callback = IllegalCallback,
                error_callback = ErrorCallback
            };

            if ((flags & Secp256K1Options.FlagsTypeMask) != Secp256K1Options.FlagsTypeContext)
            {
                ret.illegal_callback?.Invoke(null, new secp256k1_callback("Invalid flags"));
                return null;
            }

            ECMult.secp256k1_ecmult_context_init(ret.ecmult_ctx);
            ECMultGen.secp256k1_ecmult_gen_context_init(ret.ecmult_gen_ctx);

            if (flags.HasFlag(Secp256K1Options.FlagsBitContextSign))
            {
                ECMultGen.secp256k1_ecmult_gen_context_build(ret.ecmult_gen_ctx, ret.error_callback);
            }
            if (flags.HasFlag(Secp256K1Options.FlagsBitContextVerify))
            {
                ECMult.secp256k1_ecmult_context_build(ret.ecmult_ctx, ret.error_callback);
            }

            return ret;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] GetMessageHash(byte[] data)
        {
            secp256k1_sha256_t sha = new secp256k1_sha256_t();
            Hash.secp256k1_sha256_initialize(sha);
            Hash.secp256k1_sha256_write(sha, data, (UInt32)data.Length);
            byte[] output_ser = new byte[32];
            Hash.secp256k1_sha256_finalize(sha, output_ser);
            return output_ser;
        }

        private static int sign_compact(secp256k1_context ctx, byte[] msg32, byte[] seckey, byte[] output64, out byte recid)
        {
            secp256k1_ecdsa_recoverable_signature sig = new secp256k1_ecdsa_recoverable_signature();
            byte loop = 0;
            int index = 0;
            bool rec = false;
            var extra = new byte[32];
            do
            {
                extra[index] = loop;
                loop++;
                if (extra[index] == 0xff)
                    index = index + 1;

                rec = secp256k1_ecdsa_sign_recoverable(ctx, sig, msg32, seckey, null, extra);

            } while (!rec && !is_canonical(sig.data));

            secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output64, out recid, sig);
            return loop;
        }


        private static bool secp256k1_ecdsa_sign_recoverable(secp256k1_context ctx, secp256k1_ecdsa_recoverable_signature signature,
            byte[] msg32, byte[] seckey, secp256k1_nonce_function noncefp, byte[] noncedata)
        {
            if (ctx == null || msg32 == null || signature == null || seckey == null)
                throw new NullReferenceException();

            if (!ECMultGen.secp256k1_ecmult_gen_context_is_built(ctx.ecmult_gen_ctx))
                throw new ArithmeticException();

            if (noncefp == null)
            {
                noncefp = Secp256k1.secp256k1_nonce_function_default;
            }

            secp256k1_scalar r, s;
            secp256k1_scalar sec, non, msg;
            byte recid = 1;
            bool ret = false;
            var overflow = false;

            sec = new secp256k1_scalar();
            Scalar.secp256k1_scalar_set_b32(sec, seckey, ref overflow);
            r = new secp256k1_scalar();
            s = new secp256k1_scalar();
            /* Fail if the secret key is invalid. */
            if (!overflow && !Scalar.secp256k1_scalar_is_zero(sec))
            {
                var nonce32 = new byte[32];
                uint count = 0;
                msg = new secp256k1_scalar();
                Scalar.secp256k1_scalar_set_b32(msg, msg32);
                non = new secp256k1_scalar();

                while (true)
                {
                    ret = noncefp(nonce32, msg32, seckey, null, noncedata, count);
                    if (!ret)
                        break;

                    Scalar.secp256k1_scalar_set_b32(non, nonce32, ref overflow);
                    if (!Scalar.secp256k1_scalar_is_zero(non) && !overflow)
                    {
                        if (secp256k1_ecdsa_sig_sign(ctx.ecmult_gen_ctx, r, s, sec, msg, non, out recid))
                        {
                            break;
                        }
                    }
                    count++;
                }
                Util.MemSet(nonce32, 0, 32); //memset(nonce32, 0, 32);
                Scalar.secp256k1_scalar_clear(msg);
                Scalar.secp256k1_scalar_clear(non);
                Scalar.secp256k1_scalar_clear(sec);
            }
            if (ret)
            {
                secp256k1_ecdsa_recoverable_signature_save(signature, r, s, recid);
            }
            else
            {
                Util.MemSet(signature.data, 0, secp256k1_ecdsa_recoverable_signature.Size); //memset(signature, 0, sizeof(* signature));
            }
            return ret;
        }

        private static void secp256k1_ecdsa_recoverable_signature_save(secp256k1_ecdsa_recoverable_signature sig, secp256k1_scalar r, secp256k1_scalar s, byte recid)
        {
            if (secp256k1_scalar.Size == 32)
            {
                Util.Memcpy(r.d, 0, sig.data, 0, 32);// memcpy(&sig.data[0], r, 32);
                Util.Memcpy(s.d, 0, sig.data, 32, 32);// memcpy(&sig->data[32], s, 32);
            }
            else
            {
                Scalar.secp256k1_scalar_get_b32(sig.data, 0, r);
                Scalar.secp256k1_scalar_get_b32(sig.data, 32, s);
            }
            sig.data[64] = recid;
        }


        private static bool secp256k1_ecdsa_sig_sign(secp256k1_ecmult_gen_context ctx, secp256k1_scalar sigr, secp256k1_scalar sigs, secp256k1_scalar seckey,
            secp256k1_scalar message, secp256k1_scalar nonce, out byte recid)
        {
            var b = new byte[32];
            secp256k1_gej rp;
            secp256k1_ge r = new secp256k1_ge();
            secp256k1_scalar n = new secp256k1_scalar();
            bool overflow = false;

            ECMultGen.secp256k1_ecmult_gen(ctx, out rp, nonce);
            Group.secp256k1_ge_set_gej(r, rp);
            Field.secp256k1_fe_normalize(r.x);
            Field.secp256k1_fe_normalize(r.y);
            Field.secp256k1_fe_get_b32(b, r.x);
            Scalar.secp256k1_scalar_set_b32(sigr, b, ref overflow);
            /* These two conditions should be checked before calling */
            Util.VERIFY_CHECK(!Scalar.secp256k1_scalar_is_zero(sigr));
            Util.VERIFY_CHECK(!overflow);


            // The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
            // of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.
            recid = (byte)((overflow ? 2 : 0) | (Field.secp256k1_fe_is_odd(r.y) ? 1 : 0));

            Scalar.secp256k1_scalar_mul(n, sigr, seckey);
            Scalar.secp256k1_scalar_add(n, n, message);
            Scalar.secp256k1_scalar_inverse(sigs, nonce);
            Scalar.secp256k1_scalar_mul(sigs, sigs, n);
            Scalar.secp256k1_scalar_clear(n);
            Group.secp256k1_gej_clear(rp);
            Group.secp256k1_ge_clear(r);
            if (Scalar.secp256k1_scalar_is_zero(sigs))
            {
                return false;
            }
            if (Scalar.secp256k1_scalar_is_high(sigs))
            {
                Scalar.secp256k1_scalar_negate(sigs, sigs);
                recid ^= 1;
            }
            return true;
        }

        private static bool secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context ctx, byte[] output64, out byte recid, secp256k1_ecdsa_recoverable_signature sig)
        {
            return secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output64, 0, out recid, sig);
        }


        private static bool secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context ctx, byte[] outputxx, int skip, out byte recid, secp256k1_ecdsa_recoverable_signature sig)
        {
            secp256k1_scalar r = new secp256k1_scalar();
            secp256k1_scalar s = new secp256k1_scalar();
            recid = 0;

            if (outputxx == null)
            {
                ctx.illegal_callback?.Invoke(null, new secp256k1_callback("(outputxx != null)"));
                return false;
            }
            //___________________________________________________________________________________________________________________________________
            if (sig == null)
            {
                ctx.illegal_callback?.Invoke(null, new secp256k1_callback("(sig != null)"));
                return false;
            }
            //___________________________________________________________________________________________________________________________________

            secp256k1_ecdsa_recoverable_signature_load(ctx, r, s, out recid, sig);
            Scalar.secp256k1_scalar_get_b32(outputxx, skip + 0, r);
            Scalar.secp256k1_scalar_get_b32(outputxx, skip + 32, s);
            return true;
        }

        private static void secp256k1_ecdsa_recoverable_signature_load(secp256k1_context ctx, secp256k1_scalar r, secp256k1_scalar s, out byte recid, secp256k1_ecdsa_recoverable_signature sig)
        {
            //(void)ctx;
            if (secp256k1_scalar.Size == 32)
            {
                /* When the secp256k1_scalar type is exactly 32 byte, use its
                 * representation inside secp256k1_ecdsa_signature, as conversion is very fast.
                 * Note that secp256k1_ecdsa_signature_save must use the same representation. */
                Util.Memcpy(sig.data, 0, r.d, 0, 32); //memcpy(r, &sig->data[0], 32);
                Util.Memcpy(sig.data, 32, s.d, 0, 32); //memcpy(s, &sig->data[32], 32);
            }
            else
            {
                Scalar.secp256k1_scalar_set_b32(r, sig.data, 0);
                Scalar.secp256k1_scalar_set_b32(s, sig.data, 32);
            }
            recid = sig.data[64];
        }

        private static byte[] sign_compact(byte[] data, byte[] seckey, out byte recoveryId)
        {
            secp256k1_ecdsa_recoverable_signature sig = new secp256k1_ecdsa_recoverable_signature();
            byte loop = 0;
            int index = 0;
            bool rec;
            var extra = new byte[32];
            do
            {
                extra[index] = loop++;
                if (loop == 0xff) { index = index + 1; loop = 0; }
                rec = secp256k1_ecdsa_sign_recoverable(Ctx, sig, data, seckey, null, extra);

            } while (!rec);
            var output64 = new byte[64];
            secp256k1_ecdsa_recoverable_signature_serialize_compact(Ctx, output64, out recoveryId, sig);
            return output64;
        }

        /// <summary>Signs a data and returns the signature in compact form.  Returns null on failure.</summary>
        /// <param name="dataage">The data to sign.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
        /// <param name="seckeyeKey">The private key to use to sign the data.</param>
        /// <param name="recoveryId">This will contain the recovery ID needed to retrieve the key from the compact signature using the RecoverKeyFromCompact method.</param> 
        public static byte[] SignCompact(byte[] data, byte[] seckey, out int recoveryId)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(data));
            if (seckey == null)
                throw new ArgumentNullException(nameof(seckey));
            if (seckey.Length != 32)
                throw new ArgumentOutOfRangeException(nameof(seckey));

            recoveryId = 0;

            secp256k1_ecdsa_recoverable_signature sig = new secp256k1_ecdsa_recoverable_signature();
            {
                if (!secp256k1_ecdsa_sign_recoverable(Ctx, sig, data, seckey, null, null))
                    return null;
            }
            var sigbytes = new byte[64];
            byte recid;
            {
                if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(Ctx, sigbytes, out recid, sig))
                    return null;
            }
            recoveryId = recid;
            return sigbytes;
        }

        /// <summary>
        /// Get compressed and compact signature (possible in not canonical form)
        /// </summary>
        /// <param name="data">Hashed data</param>
        /// <param name="seckey">Private key (32 bytes)</param>
        /// <returns> 65 bytes compressed / compact</returns>
        public static byte[] SignCompressedCompact(byte[] data, byte[] seckey)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(data));
            if (seckey == null)
                throw new ArgumentNullException(nameof(seckey));
            if (seckey.Length != 32)
                throw new ArgumentOutOfRangeException(nameof(seckey));

            byte recoveryId = 0;

            secp256k1_ecdsa_recoverable_signature sig = new secp256k1_ecdsa_recoverable_signature();
            byte loop = 0;
            int index = 0;
            bool rec;
            byte[] extra = null;
            Random r = new Random();
            do
            {
                if (loop == 0xff) { index = index + 1; loop = 0; }
                if (loop > 0)
                {
                    extra = new byte[32];
                    r.NextBytes(extra);
                }
                loop++;
                rec = secp256k1_ecdsa_sign_recoverable(Ctx, sig, data, seckey, null, extra);

            } while (!rec && !is_canonical(sig.data));
            var output65 = new byte[65];
            secp256k1_ecdsa_recoverable_signature_serialize_compact(Ctx, output65, 1, out recoveryId, sig);


            //4 - compressed | 27 - compact
            output65[0] = (byte)(recoveryId + 4 + 27);
            return output65;
        }

        private static bool is_canonical(byte[] sig)
        {
            return !((sig[0] & 0x80) > 0)
                   && !(sig[0] == 0 && !((sig[1] & 0x80) > 0))
                   && !((sig[32] & 0x80) > 0)
                   && !(sig[32] == 0 && !((sig[33] & 0x80) > 0));
        }
    }
}