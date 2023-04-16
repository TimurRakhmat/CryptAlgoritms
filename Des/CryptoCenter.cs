using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Des
{
    internal class CryptoCenter : ICryptTransform2
    {
        public enum CryptType
        {
            ECB, CBC, CFB, OFB, CTR, RD, RD_H
        }
        public CryptoCenter(byte[] key, CryptType type, string ipv = "12345678", params int[] other) { }

        public void cryptBytes(byte[] data, ref byte[] outdata) { }
        public void decryptBytes(byte[] data, ref byte[] outdata) { }

        public void cryptFile(string filepath, string outfilepath) { }
        public void decryptFile(string filepath, string outfilepath) { }

        byte[] ICryptTransform2.crypt(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        byte[] ICryptTransform2.encrypt(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }
    }
}
