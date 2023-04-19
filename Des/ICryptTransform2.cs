using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Des
{
    internal interface ICryptTransform2
    {
        byte[] encrypt(byte[] data, byte[] key);
        byte[] decrypt(byte[] data, byte[] key);
    }
}
