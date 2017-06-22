using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace Cryptography.ECDSA
{
    public static class Proxy
    {
        private static Type _signaturesType;

        private static Type SignaturesType
        {
            get
            {
                if (_signaturesType == null)
                {
                    var asmName = $"Secp256k1.CLI.x{(Environment.Is64BitProcess ? "64" : "86")}.dll";
                    var path = GetPathToAssembly(asmName);

                    Assembly a = Assembly.LoadFrom(path);
                    //var ver = a.GetName().Version;
                    //if (ver.Major < 1)
                    //    return null;
                    //if (ver.Major == 1 && ver.Minor < 1)
                    //    return null;
                    _signaturesType = a.GetType("Secp256k1.Signatures");
                }
                return _signaturesType;
            }
        }

        private static string GetPathToAssembly(string asmName)
        {
            var partpath = AppDomain.CurrentDomain.RelativeSearchPath;
            if (!string.IsNullOrEmpty(partpath) && File.Exists(Path.Combine(partpath, asmName)))
                return Path.Combine(partpath, asmName);

            partpath = AppDomain.CurrentDomain.BaseDirectory;
            if (!string.IsNullOrEmpty(partpath) && File.Exists(Path.Combine(partpath, asmName)))
                return Path.Combine(partpath, asmName);

            var codeBase = Assembly.GetAssembly(typeof(Proxy)).CodeBase;
            var uri = new UriBuilder(codeBase);
            var path = Uri.UnescapeDataString(uri.Path);
            partpath = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(partpath) && File.Exists(Path.Combine(partpath, asmName)))
                return Path.Combine(partpath, asmName);

            throw new DirectoryNotFoundException($"Папка {asmName} не найдена!");
        }


        public delegate bool VerifyPrivateKeyDelegate(byte[] privateKey);
        public static VerifyPrivateKeyDelegate VerifyPrivateKey = (VerifyPrivateKeyDelegate)Delegate.CreateDelegate(typeof(VerifyPrivateKeyDelegate), SignaturesType.GetRuntimeMethod("VerifyPrivateKey", new[] { typeof(byte[]) }));

        public delegate bool VerifyDelegate(byte[] message, byte[] signature, byte[] publicKey, bool normalizeSignatureOnFailure);
        public static VerifyDelegate Verify = (VerifyDelegate)Delegate.CreateDelegate(typeof(VerifyDelegate), SignaturesType.GetRuntimeMethod("Verify", new[] { typeof(byte[]), typeof(byte[]), typeof(byte[]), typeof(bool) }));

        public delegate byte[] SignDelegate(byte[] message, byte[] privateKey);
        public static SignDelegate Sign = (SignDelegate)Delegate.CreateDelegate(typeof(SignDelegate), SignaturesType.GetRuntimeMethod("Sign", new[] { typeof(byte[]), typeof(byte[]) }));

        public delegate byte[] SignCompactDelegate(byte[] message, byte[] privateKey, out int recoveryId);
        public static SignCompactDelegate SignCompact = (SignCompactDelegate)Delegate.CreateDelegate(typeof(SignCompactDelegate), SignaturesType.GetRuntimeMethod("SignCompact", new[] { typeof(byte[]), typeof(byte[]), typeof(int).MakeByRefType() }));

        public delegate byte[] GetMessageHashDelegate(byte[] message);
        public static GetMessageHashDelegate GetMessageHash = (GetMessageHashDelegate)Delegate.CreateDelegate(typeof(GetMessageHashDelegate), SignaturesType.GetRuntimeMethod("GetMessageHash", new[] { typeof(byte[]) }));

        public delegate byte[] RecoverKeyFromCompactDelegate(byte[] message, byte[] signature, int recoveryId, bool compressed);
        public static RecoverKeyFromCompactDelegate RecoverKeyFromCompact = (RecoverKeyFromCompactDelegate)Delegate.CreateDelegate(typeof(RecoverKeyFromCompactDelegate), SignaturesType.GetRuntimeMethod("RecoverKeyFromCompact", new[] { typeof(byte[]), typeof(byte[]), typeof(int), typeof(bool) }));

        public delegate byte[] GetPublicKeyDelegate(byte[] privateKey, bool compressed);
        public static GetPublicKeyDelegate GetPublicKey = (GetPublicKeyDelegate)Delegate.CreateDelegate(typeof(GetPublicKeyDelegate), SignaturesType.GetRuntimeMethod("GetPublicKey", new[] { typeof(byte[]), typeof(bool) }));

        public delegate byte[] NormalizeSignatureDelegate(byte[] signature, out bool wasAlreadyNormalized);
        public static NormalizeSignatureDelegate NormalizeSignature = (NormalizeSignatureDelegate)Delegate.CreateDelegate(typeof(NormalizeSignatureDelegate), SignaturesType.GetRuntimeMethod("NormalizeSignature", new[] { typeof(byte[]), typeof(bool).MakeByRefType() }));


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

            int recoveryId = -1;
            var sigptr = SignCompact(data, seckey, out recoveryId);

            //4 - compressed | 27 - compact
            var sRez = Hex.Join(new[] { (byte)(recoveryId + 4 + 27) }, sigptr);
            return sRez;
        }

        public static bool IsCanonical(byte[] sig)
        {
            return !((sig[0] & 0x80) > 0)
                   && !(sig[0] == 0 && !((sig[1] & 0x80) > 0))
                   && !((sig[32] & 0x80) > 0)
                   && !(sig[32] == 0 && !((sig[33] & 0x80) > 0));
        }
    }
}
