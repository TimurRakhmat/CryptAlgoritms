using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Des
{
    internal class DesCore : FeistelCore
    {
        static int[] keyp = {
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
        };

        static int[] key_comp = {14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32};

        static int[] exp_d = {32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1};

        static int[] shift_table = {1, 1, 2, 2,
               2, 2, 2, 2,
               1, 2, 2, 2,
               2, 2, 2, 1};

        public DesCore(byte[] key, CryptType type, string ipv = "12345678", params int[] other):base(key, type, ipv, other) 
        {
            return;
        }

        public override byte[][] generateKey(byte[] key)
        {
            CryptCore.Permutation(ref key, keyp);

            int c = 0, d = 0;

            for (int i  = 0; i < 3; i++)
            {
                c += key[i] << (i * 8);
                d += key[4 + i] << (4 + i * 8);
            }
            c += (key[3] & 0x0F) << 24;
            d += (key[3] >> 4) & 0x0F;

            byte[][] bytes = new byte[16][];
            byte[] tmp = new byte[7];

            for (int i = 0; i < 16; i++)
            {
                bytes[i] = new byte[6];
                c = (c << shift_table[i]) | (c >> (28 - shift_table[i]) & (0x1 << (shift_table[i] - 1)));
                d = (d << shift_table[i]) | (d >> (28 - shift_table[i]) & (0x1 << (shift_table[i] - 1)));

                for (int j = 0; j < 3; j++)
                {
                    tmp[j] = (byte)(c >> (j * 8) & 0xFF);
                    tmp[4 + j] = (byte)(d >> (j * 8 + 4) & 0xFF);
                }

                tmp[3] |= (byte)((c >> 24) & 0x0F);
                tmp[3] |= (byte)((d & 0x0F) << 4);

                CryptCore.Permutation(ref tmp, key_comp);
                Buffer.BlockCopy(tmp, 0, bytes[i], 0, 6);
            }

            return bytes;
        }

        public override byte[] feistelFunction(byte[] data, byte[] key)
        {
            byte[] res = new byte[data.Length];

            byte[] tmp = new byte[6];
            data.CopyTo(tmp, 0 );
            CryptCore.Permutation(ref tmp, exp_d);
            CryptCore.set_sblock();

            long right = 0;

            for (int i = 0; i < 6; i++)
            {
                right += tmp[i] << (8*i);
            }

            for (int i = 0; i < 8; i++)
            {
                byte[] stmp = new byte[1];
                stmp[0] = (byte)((right >> (i * 6)) & 0x3F);
                CryptCore.sblcok_transform(ref stmp, CryptCore.box[i], 6);
                res[i / 2] |= (byte)(stmp[0] << (i % 2 * 4));
            }

            return res;
        }
    }
}
