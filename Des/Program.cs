

using Des;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello world!");

        string keystring = "Ge2,wBf2";
        byte[] perma = Encoding.UTF8.GetBytes(keystring);
        Console.WriteLine(Encoding.Default.GetString(perma));
        CryptCore.Permutation(ref perma, CryptCore.primaryPerm);
        Console.WriteLine(Encoding.Default.GetString(perma));
        CryptCore.Permutation(ref perma, CryptCore.reversePerm);
        Console.WriteLine(Encoding.Default.GetString(perma));




        byte[] key = new byte[]
        {
            0xAA,
            0xBB,
            0x09,
            0x18,
            0x27,
            0x36,
            0xCC,
            0xDD
        };
        DesCore ds = new(key, CryptoCenter.CryptType.ECB);
        byte[] data = new byte[] {
            0x12,
            0x34,
            0x56,
            0xAB,
            0xCD,
            0x13,
            0x25,
            0x36 };

        byte[] res = ds.crypt(data, key);
        byte[] answ = ds.crypt(res, key);


        return;
    }
}
