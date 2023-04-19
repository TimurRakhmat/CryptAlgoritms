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

        CryptType m_type;
        byte[] m_ipv;

        public enum CryptType
        {
            ECB, CBC, CFB, OFB, CTR, RD, RD_H
        }
        public CryptoCenter(byte[] key, CryptType type, byte[] ipv, params int[] other)
        {
            m_type = type;
            round_key = generateKey(key);
            m_ipv = ipv;
        }

        public void cryptBytes(byte[] data, ref byte[] outdata) 
        {
            if (m_type == CryptType.ECB)
            {
                int n = data.Length / 8;
                if (data.Length % 8 != 0)
                    n++;

                outdata = new byte[n*8];

                byte[] tmp = new byte[8];
                byte[] res;
                
                for(int i = 0; i < n; i++)
                {
                    int block_count = 8;
                    if (i == n - 1 && data.Length % 8 != 0)
                        block_count = data.Length % 8;
                    Buffer.BlockCopy(data, i * 8, tmp, 0, block_count);
                    if (i == n - 1)
                        add_padding(ref tmp, 8, block_count);
                    res = encrypt(tmp, null);
                    Buffer.BlockCopy(res, 0, outdata, i * 8, 8);
                }

                return;

            }
            else if (m_type == CryptType.CBC)
            {

            }
            else if (m_type == CryptType.CFB)
            {

            }
            else if (m_type == CryptType.OFB)
            {

            }
            else if (m_type == CryptType.CTR)
            {

            }
            else if (m_type == CryptType.RD)
            {

            }
            else if (m_type == CryptType.RD_H)
            {

            }
        }
        public void decryptBytes(byte[] data, ref byte[] outdata) 
        {
            if (m_type == CryptType.ECB)
            {
                int n = data.Length / 8;

                outdata = new byte[n * 8];

                byte[] tmp = new byte[8];
                byte[] res;

                int padding = 0;

                for (int i = 0; i < n; i++)
                {
                    Buffer.BlockCopy(data, i * 8, tmp, 0, 8);
                    res = decrypt(tmp, null);
                    if (i == n - 1)
                        padding = del_padding(ref res, 8);
                    Buffer.BlockCopy(res, 0, outdata, i * 8, 8 - padding);
                }

                if (padding > 0)
                    Array.Resize(ref outdata, outdata.Length - padding);
                return;

            }
            else if (m_type == CryptType.CBC)
            {

            }
            else if (m_type == CryptType.CFB)
            {

            }
            else if (m_type == CryptType.OFB)
            {

            }
            else if (m_type == CryptType.CTR)
            {

            }
            else if (m_type == CryptType.RD)
            {

            }
            else if (m_type == CryptType.RD_H)
            {

            }
        }

        public void cryptFile(string filepath, string outfilepath) { }
        public void decryptFile(string filepath, string outfilepath) { }

        public virtual byte[] encrypt(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public virtual byte[] decrypt(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public virtual byte[][] generateKey(byte[] key)
        {
            throw new NotImplementedException();
        }

        static public void add_padding(ref byte[] data, int size, int pad)
        {
            int count = size - pad;
            if (count == 0)
                return;

            byte[] res = new byte[size];
            data.CopyTo(res, 0);
            for (int i = 0; i < count; i++)
            {
                res[size - 1 - i] = (byte)count;
            }

            data = res;
        }

        static public int del_padding(ref byte[] data, int size)
        {
            int count = data[size - 1];

            if (count == 0 || count > size - 1)
                return 0;

            for (int i = 0; i < count && i < data.Length; i++)
            {
                if (data[size - 1 - i] != (byte)count)
                {
                    return 0;
                }
            }

            byte[] res = new byte[size - count];

            Buffer.BlockCopy(data, 0, res, 0, size - count);
            data = res;

            return count;
        }
    }
}
