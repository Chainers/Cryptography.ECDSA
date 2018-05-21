using System;
using Cryptography.ECDSA.Internal.Sha256;

namespace Cryptography.ECDSA
{
    public class Sha256Manager
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] GetHash(byte[] data)
        {
            Sha256T sha = new Sha256T();
            Hash.Initialize(sha);
            Hash.Write(sha, data, (UInt32)data.Length);
            byte[] outputSer = new byte[32];
            Hash.Finalize(sha, outputSer);
            return outputSer;
        }
    }
}
