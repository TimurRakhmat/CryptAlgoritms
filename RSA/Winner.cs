using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    internal class Winner
    {
        public static BigInteger winAttack(BigInteger e, BigInteger N)
        {
            BigInteger d = 0;

            var chain = get_chain(e, N);
            var frac = get_fractions(chain);


            foreach( var t in frac )
            {
                if (test_d(t.Item2, e, N))
                {
                    d = t.Item2; 
                    break;
                }
            }

            return d;
        }


        static bool test_d(BigInteger d, BigInteger e, BigInteger N) 
        {

            // TODO
            //RSAcore rs = new RSAcore(d, e, N);
            //string message = "12345678";
            //string temp = rs.encrypt(message);
            //if (message == rs.decrypt(temp))
            //    return true;

            // rsa написан на языке с++, ссылка на него тоже скниута
            return true;
        }


        public static List<(BigInteger, BigInteger)> get_fractions(List<BigInteger> x)
        {
            List<(BigInteger, BigInteger)> values = new List<(BigInteger, BigInteger)> ();

            BigInteger p0 = 1, q0 = 0, p1 = x[0], q1 = 1, pi, qi;
            int n = x.Count;

            for (int i = 1; i < n; i++)
            {
                pi = p1 * x[i] + p0;
                qi = q1 * x[i] + q0;
                values.Add((pi, qi));
                p0 = p1;
                q0 = q1;
                p1 = pi;
                q1 = qi;
            }

            return values;
        }
        public static List<BigInteger> get_chain(BigInteger e, BigInteger N) 
        {
            List<BigInteger> chain = new List<BigInteger>();

            BigInteger tempe = e, tempn = N, ost, temp;
            ost = tempe / tempn;

            chain.Add(ost);

            while (tempe != 0)
            {
                temp = tempe;
                tempe = tempn;
                tempn = temp;
                ost = tempe / tempn;
                chain.Add(ost);
                tempe %= tempn;
            }

            return chain;
        }
    }
}
