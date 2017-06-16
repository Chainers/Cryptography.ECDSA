using System;
using System.Runtime.InteropServices;

namespace Cryptography.ECDSA
{
    public class UnmanagedApi : IDisposable
    {
        private const string LibName = "libSecp256k1.so";

        public static IntPtr Ctx;

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

        static UnmanagedApi()
        {
            Ctx = new IntPtr();
            Ctx = secp256k1_context_create((uint)(Secp256K1Options.ContextSign | Secp256K1Options.ContextVerify));
        }

        #region SECP256K1_API

        /// <summary>
        /// Create a secp256k1 context object.
        /// See also secp256k1_context_randomize.
        /// </summary>
        /// <param name="flags">which parts of the context to initialize.</param>
        /// <returns>a newly created context object.</returns>
        [DllImport(LibName)]
        private static extern IntPtr secp256k1_context_create(uint flags);

        /// <summary>
        /// Destroy a secp256k1 context object.
        /// The context pointer may not be used afterwards.
        /// </summary>
        /// <param name="ctx">an existing context to destroy (cannot be NULL)</param>
        [DllImport(LibName)]
        private static extern void secp256k1_context_destroy(IntPtr ctx);
        
        [DllImport(LibName)]
        private static extern void get_message_hash(byte[] data, int sz, byte[] hash);

        [DllImport(LibName)]
        private static extern int sign_compact(IntPtr ctx, byte[] data, byte[] seckey, byte[] output64, ref int recid);
        
        #endregion SECP256K1_API

        public static byte[] SignCompact(byte[] data, byte[] seckey)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(data));
            if (seckey == null)
                throw new ArgumentNullException(nameof(seckey));
            if (seckey.Length != 32)
                throw new ArgumentOutOfRangeException(nameof(seckey));

            int recoveryId = -1;
            var sigptr = new byte[64];
            var msg32 = GetMessageHash(data);
            var t = sign_compact(Ctx, msg32, seckey, sigptr, ref recoveryId);
            var sRez = Hex.Join(new[] { (byte)(recoveryId + 4 + 27) }, sigptr);
            return sRez;
        }
        

        /// <summary>Use sha256 to get hash from message</summary>
        /// <param name="data">message</param>
        public static byte[] GetMessageHash(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(data));

            byte[] hash = new byte[32];
            get_message_hash(data, data.Length, hash);
            return hash;
        }


        #region IDisposable Members
        private bool disposed = false;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposeManagedResources)
        {
            if (!this.disposed)
            {
                if (disposeManagedResources)
                {
                    // dispose managed resources
                }
                // dispose unmanaged resources
                secp256k1_context_destroy(Ctx);
                disposed = true;
            }

        }

        #endregion
    }
}
