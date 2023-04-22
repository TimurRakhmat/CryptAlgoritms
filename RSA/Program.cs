using RSA;
using System.Numerics;

class Program
{
    async static Task Main(string[] args)
    {
        BigInteger a = 447, b = 723;
        var tmp = Winner.get_chain(a, b);
        var ch = Winner.get_fractions(tmp);


        BigInteger e = 1073780833;
        BigInteger N = 1220275921;
        Winner.winAttack(e, N);

    }

}