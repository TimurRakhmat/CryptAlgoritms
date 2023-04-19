

using Des;
using System.Diagnostics;
using System.Text;

class Program
{
    async static Task Main(string[] args)
    {
        string ipv_string = "12345678";
        byte[] ipv = Encoding.UTF8.GetBytes(ipv_string);

        byte[] key = new byte[]
        {
            0x23,
            0xBB,
            0x09,
            0x18,
            0x27,
            0x3B,
            0xCC,
            0xDD
        };
        DesCore ds = new(ipv, CryptoCenter.CryptType.ECB, ipv, new int[]{ 8});

        string ipath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\in.txt";
        string opath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\out.txt";
        string oopath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\out.mp4";

        string vipath = "C:\\Users\\rahma\\Downloads\\invisible.mp4";


        //ds.encryptFile(ipath, opath);
        await ds.encryptFile(vipath, opath);
        await ds.decryptFile(opath, oopath);
        Console.WriteLine("end");

        //var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        //var stringChars = new char[2048];
        //var random = new Random();

        //for (int i = 0; i < stringChars.Length; i++)
        //{
        //    stringChars[i] = chars[random.Next(chars.Length)];
        //}

        //var finalString = new String(stringChars);
        //byte [] ds_bytes = Encoding.UTF8.GetBytes(finalString);
        //Console.WriteLine(finalString);
        //var sw = new Stopwatch();
        //sw.Start();
        //byte[] res = ds.encryptBytes(ds_bytes);
        //sw.Stop();
        //Console.WriteLine("ecb ecncrypt time" + sw.Elapsed);
        ////Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        ////Console.WriteLine(Encoding.Default.GetString(res));
        ////Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        //sw.Start();
        //byte[] answ = ds.decryptBytes(res);
        //sw.Stop();
        //Console.WriteLine("ecb decrypt time" + sw.Elapsed);
        //Console.WriteLine(Encoding.Default.GetString(answ));

        return;
    }
}
