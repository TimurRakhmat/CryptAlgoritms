using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Des
{
    internal class FeistelCore : CryptoCenter, IKeyGenerate
    {
        public FeistelCore(byte[] key, CryptType type, string ipv = "12345678", params int[] other) : base(key, type, ipv, other) { }



        public virtual byte[][] generateKey(byte[] key)
        {
            throw new NotImplementedException();
        }
    }
}
