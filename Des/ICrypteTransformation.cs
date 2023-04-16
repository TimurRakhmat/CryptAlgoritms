using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Des
{
    internal interface ICrypteTransformation
    {
        byte[] makeCrypteTransform(byte[] data, byte[] key);
    }
}
