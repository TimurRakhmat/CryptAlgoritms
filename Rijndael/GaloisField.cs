using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace Rijndael
{
    internal class GaloisField
    {
        public GaloisField() { }

        static public byte add(byte left, byte right)
        {
            return (byte)(left ^ right);
        }

        static public byte mul(byte a, byte b, byte mod = 0x1b)
        {
            byte p = 0;

            while(a != 0 && b != 0)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                if ((a & 0x80) != 0)
                    a = (byte)((a << 1) ^ mod);
                else
                    a <<= 1;

                b >>= 1;
            }

            return p;
        }


        static public byte pow(byte a, int n, byte mod = 0x1b)
        {
            if (n == 0)
                return 1;
            else if (n % 2 == 0)
            {
                return pow(mul(a, a, mod), n / 2, mod);
            }
            else
            {
                byte sq = mul(a, a, mod);
                return mul(sq, pow(a, n / 2, mod), mod);
            }
        }

        static public byte inverse(byte a, byte mod = 0x1b)
        {
            return pow(a, 254, mod);
        }
    }
}
