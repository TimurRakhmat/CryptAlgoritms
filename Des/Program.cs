

using Des;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello world!");

        string keystring = "Ge2,wBf2";
        byte[] key = Encoding.UTF8.GetBytes(keystring);
        DesCore ds = new(key, CryptoCenter.CryptType.ECB);

    }
}
