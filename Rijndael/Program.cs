// See https://aka.ms/new-console-template for more information
using Des;
using Rijndael;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks.Dataflow;

class Programm
{
    static void Main(string[] args)
    {
        string ipv_string = "12345678123456781234567812345678";
        byte[] ipv = Encoding.UTF8.GetBytes(ipv_string);


        string data_str = "12345678123456781234567812345678";
        byte[] data = Encoding.UTF8.GetBytes(data_str);


        byte a = 0x57;
        


        Console.WriteLine(GF.isPolynome(a));
        Console.WriteLine(GF.isPolynome(0x1b));
        Console.WriteLine(GF.isPolynome(0x1d));

        var t = GF.getPolynomes();


        RijndaelCore rd = new(ipv, CryptoCenter.CryptType.ECB, ipv, new int[] { 32, 32 });
        rd.makeKeyGeneration();


        rd.Cipher(data);
    }
}
