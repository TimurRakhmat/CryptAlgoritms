using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Des
{
    internal class CryptoCenter : ICryptTransform2, IKeyGenerate
    {
        public byte[][] round_key;
        public enum CryptType
        {
            ECB, CBC, CFB, OFB, CTR, RD, RD_H
        }
        public CryptoCenter(byte[] key, CryptType type, string ipv = "12345678", params int[] other) 
        {
            round_key = generateKey(key);
        }

        public void cryptBytes(byte[] data, ref byte[] outdata) { }
        public void decryptBytes(byte[] data, ref byte[] outdata) { }

        public void cryptFile(string filepath, string outfilepath) { }
        public void decryptFile(string filepath, string outfilepath) { }

        public virtual byte[] crypt(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public virtual byte[] encrypt(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public virtual byte[][] generateKey(byte[] key)
        {
            throw new NotImplementedException();
        }
    }
}
