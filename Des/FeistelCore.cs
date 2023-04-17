using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Des
{
    internal class FeistelCore : CryptoCenter
    {
        public FeistelCore(byte[] key, CryptType type, string ipv = "12345678", params int[] other) : base(key, type, ipv, other) { }


        public override byte[] crypt(byte[] data, byte[] key)
        {
            byte[] res = new byte[data.Length];


            CryptCore.Permutation(ref data, CryptCore.primaryPerm);

            int n = data.Length / 2;

            byte[] left = new byte[n];
            byte[] right = new byte[n];

            Buffer.BlockCopy(data, 0, left, 0, n);
            Buffer.BlockCopy(data, n, right, 0, n);

            byte[] tmpleft;
            byte[] tmpright;

            for (int i = 0; i < 16; i++)
            {
                tmpleft = feistelFunction(right, round_key[i]);
                tmpright = new byte[n];

                right.CopyTo(tmpright, 0);

                for (int j = 0; j < n; j++)
                {
                    tmpleft[j] ^= left[j];
                }

                tmpleft.CopyTo(right, 0);
                tmpright.CopyTo(left, 0);
            }

            Buffer.BlockCopy(left, 0, res, 0, n);
            Buffer.BlockCopy(right, 0, res, n, n);

            CryptCore.Permutation(ref res, CryptCore.reversePerm);

            return res;
        }

        public override byte[] encrypt(byte[] data, byte[] key)
        {
            byte[] res = new byte[data.Length];


            CryptCore.Permutation(ref data, CryptCore.primaryPerm);

            int n = data.Length / 2;

            byte[] left = new byte[n];
            byte[] right = new byte[n];

            Buffer.BlockCopy(data, 0, left, 0, n);
            Buffer.BlockCopy(data, n, right, 0, n);

            byte[] tmpleft;
            byte[] tmpright;

            for (int i = 0; i < 16; i++)
            {
                tmpleft = feistelFunction(right, round_key[15 - i]);
                tmpright = new byte[n];

                right.CopyTo(tmpright, 0);

                for (int j = 0; j < n; j++)
                {
                    tmpleft[j] ^= left[j];
                }

                tmpleft.CopyTo(right, 0);
                tmpright.CopyTo(left, 0);
            }

            Buffer.BlockCopy(left, 0, res, 0, n);
            Buffer.BlockCopy(right, 0, res, n, n);

            CryptCore.Permutation(ref res, CryptCore.reversePerm);

            return res;
        }

        public virtual byte[] feistelFunction(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public override byte[][] generateKey(byte[] key)
        {
            throw new NotImplementedException();
        }
    }
}
