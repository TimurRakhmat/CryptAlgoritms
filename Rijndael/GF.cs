using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace Rijndael
{
    internal class GF
    {
        public GF() { }

        static public byte add(byte left, byte right)
        {
            return (byte)(left ^ right);
        }

        static public byte mul(byte a, byte b, byte mod = 0x1b)
        {
            
            byte p = 0;

            while(b != 0)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                if ((a & 0x80) != 0)
                    a = (byte)((a << 1) ^ (0x100 | mod));
                else
                    a <<= 1;

                b >>= 1;
            }

            return p;
        }


        static public byte pow(byte a, int n, byte mod = 0x1b)
        {
            byte res = 1;
            while (n > 0)
            {
                if (n % 2 == 1)
                    res = GF.mul(res, a, mod);
                a = GF.mul(a, a, mod);
                n /= 2;
            }

            return res;
        }

        static public byte slowpow(byte a, int n, byte mod = 0x1b)
        {
            byte res = 1;
            for (int i = 0; i < n; i++)
            {
                res = GF.mul(res, a, mod);
            }

            return res;
        }

        static public byte inverse(byte a, byte mod = 0x1b)
        {
            return pow(a, 254, mod);
        }

        static public bool isPolynome(byte a)
        {
            HashSet<byte> set = new HashSet<byte>();

            byte tmp = 0x11;
            byte ttmp = 1;
            for (int i = 0; i < 255; i++)
            {
                ttmp = GF.mul(ttmp, tmp, a);
                if (set.Contains(ttmp))
                    return false;
                set.Add(ttmp);
            }

            return true;
        }

        static public List<byte> getPolynomes()
        {
            List<byte> list = new List<byte>();
            byte tmp;
            for (int i = 0; i < 128; i++)
            {
                tmp = (byte)((i << 1) | 0x01);
                if (isPolynome(tmp))
                    list.Add(tmp);
            }

            return list;
        }
    }
}
