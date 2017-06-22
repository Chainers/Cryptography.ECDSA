
using System;

namespace Cryptography.ECDSA
{
    /* These rules specify the order of arguments in API calls:
     *
     * 1. Context pointers go first, followed by output arguments, combined
     *    output/input arguments, and finally input-only arguments.
     * 2. Array lengths always immediately the follow the argument whose length
     *    they describe, even if this violates rule 1.
     * 3. Within the OUT/OUTIN/IN groups, pointers to data that is typically generated
     *    later go first. This means: signatures, public nonces, private nonces,
     *    messages, public keys, secret keys, tweaks.
     * 4. Arguments that are not data pointers go last, from more complex to less
     *    complex: function pointers, algorithm names, messages, void pointers,
     *    counts, flags, booleans.
     * 5. Opaque data pointers follow the function pointer they are to be passed to.
     */

    /// <summary>
    /// Opaque data structure that holds context information (precomputed tables etc.).
    /// 
    /// The purpose of context structures is to cache large precomputed data tables 
    /// that are expensive to construct, and also to maintain the randomization data for blinding.
    /// 
    /// Do not create a new context object for each operation, as construction is
    /// far slower than all other API calls (~100 times slower than an ECDSA  verification).
    /// 
    /// A constructed context can safely be used from multiple threads
    /// simultaneously, but API call that take a non-const pointer to a context
    /// need exclusive access to it. In particular this is the case for
    /// secp256k1_context_destroy and secp256k1_context_randomize.
    /// 
    /// Regarding randomization, either do it once at creation time (in which case
    /// you do not need any locking for the other calls), or use a read-write lock.
    /// </summary>
    internal class secp256k1_context : secp256k1_context_struct
    {
    }

    /// <summary>
    /// Opaque data structured that holds a parsed ECDSA signature,
    /// supporting pubkey recovery.
    /// 
    /// The exact representation of data inside is implementation defined and not
    /// guaranteed to be portable between different platforms or versions. It is
    /// however guaranteed to be 65 bytes in size, and can be safely copied/moved.
    /// If you need to convert to a format suitable for storage or transmission, use
    /// the secp256k1_ecdsa_signature_serialize_* and
    /// secp256k1_ecdsa_signature_parse_* functions.
    /// 
    /// Furthermore, it is guaranteed that identical signatures (including their
    /// recoverability) will have identical representation, so they can be
    /// memcmp'ed.
    /// </summary>
    public class secp256k1_ecdsa_recoverable_signature
    {
        public const int Size = 65;
        public byte[] data = new byte[Size];
    }

    internal class secp256k1_context_struct
    {
        public secp256k1_ecmult_context ecmult_ctx;
        public secp256k1_ecmult_gen_context ecmult_gen_ctx;
        public EventHandler<secp256k1_callback> illegal_callback;
        public EventHandler<secp256k1_callback> error_callback;

        public secp256k1_context_struct()
        {
            ecmult_ctx = new secp256k1_ecmult_context();
            ecmult_gen_ctx = new secp256k1_ecmult_gen_context();
        }
    };

    /// <summary>
    /// A pointer to a function to deterministically generate a nonce.
    /// Except for test cases, this function should compute some cryptographic hash of the message, the algorithm, the key and the attempt.
    /// </summary>
    /// <param name="nonce32">(Out) pointer to a 32-byte array to be filled by the function.</param>
    /// <param name="msg32">(In) the 32-byte message hash being verified (will not be NULL)</param>
    /// <param name="key32">(In) pointer to a 32-byte secret key (will not be NULL)</param>
    /// <param name="algo16">(In) pointer to a 16-byte array describing the signature algorithm(will be NULL for ECDSA for compatibility).</param>
    /// <param name="data">(In) Arbitrary data pointer that is passed through.</param>
    /// <param name="attempt">(In) how many iterations we have tried to find a nonce. This will almost always be 0, but different attempt values are required to result in a different nonce.</param>
    /// <returns></returns>
    public delegate bool secp256k1_nonce_function(byte[] nonce32, byte[] msg32, byte[] key32, byte[] algo16, byte[] data, uint attempt);

    public class Secp256k1
    {
        /// <summary>
        /// An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function. 
        /// If a data pointer is passed, it is assumed to be a pointer to 32 bytes of extra entropy.
        /// </summary>
        public static secp256k1_nonce_function secp256k1_nonce_function_rfc6979;

        /// <summary>
        /// A default safe nonce generation function (currently equal to secp256k1_nonce_function_rfc6979).
        /// </summary>
        public static secp256k1_nonce_function secp256k1_nonce_function_default;


        static Secp256k1()
        {
            secp256k1_nonce_function_rfc6979 = nonce_function_rfc6979;
            secp256k1_nonce_function_default = nonce_function_rfc6979;
        }

        public static bool nonce_function_rfc6979(byte[] nonce32, byte[] msg32, byte[] key32, byte[] algo16, byte[] data, uint counter)
        {
            var sizeofkeydata = 112;
            var keydata = new byte[sizeofkeydata];

            secp256k1_rfc6979_hmac_sha256_t rng = new secp256k1_rfc6979_hmac_sha256_t();
            uint i;
            // We feed a byte array to the PRNG as input, consisting of:
            // - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
            // - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
            // - optionally 16 extra bytes with the algorithm name.
            // Because the arguments have distinct fixed lengths it is not possible for
            //  different argument mixtures to emulate each other and result in the same
            //  nonces.
            UInt32 keylen = 0;
            Util.Memcpy(key32, 0, keydata, keylen, 32); //memcpy(keydata, key32, 32);
            keylen += 32;
            Util.Memcpy(msg32, 0, keydata, keylen, 32); //memcpy(keydata + 32, msg32, 32);
            keylen += 32;
            if (data != null)
            {
                Util.Memcpy(data, 0, keydata, 64, 32); //memcpy(keydata + 64, data, 32);
                keylen = 96;
            }
            if (algo16 != null)
            {
                Util.Memcpy(algo16, 0, keydata, keylen, 16); //memcpy(keydata + keylen, algo16, 16);
                keylen += 16;
            }
            Hash.secp256k1_rfc6979_hmac_sha256_initialize(rng, keydata, keylen);
            Util.MemSet(keydata, 0, sizeofkeydata);//memset(keydata, 0, sizeof(keydata));
            for (i = 0; i <= counter; i++)
            {
                Hash.secp256k1_rfc6979_hmac_sha256_generate(rng, nonce32, 32);
            }
            Hash.secp256k1_rfc6979_hmac_sha256_finalize(rng);
            return true;
        }
    }
}
