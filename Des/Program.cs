

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
        

        //string ipath = "C:\\Users\\t.rakhmatullin\\Documents\\dmdir\\scam\\matrix2.txt";
        //string opath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\some.txt";
        //string oopath = "C:\\Users\\t.rakhmatullin\\Documents\\dmdir\\scam\\oout.txt";

        //string vipath = "C:\\Users\\rahma\\Downloads\\invisible.mp4";


        //ds.encryptFile(ipath, opath);
        //await ds.encryptFile(vipath, opath);
        //await ds.decryptFile(opath, oopath);
        //Console.WriteLine("end");

        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var stringChars = new char[514];
        var random = new Random();

        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = chars[random.Next(chars.Length)];
        }

        var finalString = new String(stringChars);
        byte[] ds_bytes = Encoding.UTF8.GetBytes(finalString);
        Console.WriteLine(finalString);

        DesCore ds = new(ipv, CryptoCenter.CryptType.OFB, CryptoCenter.Padding.PKCS, ipv, new int[] { 8 });
        byte[] res = ds.encryptBytes(ds_bytes);
        Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        byte[] answ = ds.decryptBytes(res);
        Console.WriteLine(Encoding.Default.GetString(answ));

        ds = new(ipv, CryptoCenter.CryptType.CBC, CryptoCenter.Padding.PKCS, ipv, new int[] { 8 });
        ds_bytes = Encoding.UTF8.GetBytes(finalString);
        res = ds.encryptBytes(ds_bytes);
        Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        res = ds.decryptBytes(res);
        Console.WriteLine(Encoding.Default.GetString(answ));

        ds = new(ipv, CryptoCenter.CryptType.CFB, CryptoCenter.Padding.PKCS, ipv, new int[] { 8 });
        ds_bytes = Encoding.UTF8.GetBytes(finalString);
        res = ds.encryptBytes(ds_bytes);
        Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        res = ds.decryptBytes(res);
        Console.WriteLine(Encoding.Default.GetString(answ));


        ds = new(ipv, CryptoCenter.CryptType.OFB, CryptoCenter.Padding.PKCS, ipv, new int[] { 8 });
        ds_bytes = Encoding.UTF8.GetBytes(finalString);
        res = ds.encryptBytes(ds_bytes);
        Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        res = ds.decryptBytes(res);
        Console.WriteLine(Encoding.Default.GetString(answ));

        ds = new(ipv, CryptoCenter.CryptType.CTR, CryptoCenter.Padding.PKCS, ipv, new int[] { 8 });
        ds_bytes = Encoding.UTF8.GetBytes(finalString);
        res = ds.encryptBytes(ds_bytes);
        Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        res = ds.decryptBytes(res);
        Console.WriteLine(Encoding.Default.GetString(answ));

        ds = new(ipv, CryptoCenter.CryptType.RD, CryptoCenter.Padding.PKCS, ipv, new int[] { 8 });
        ds_bytes = Encoding.UTF8.GetBytes(finalString);
        res = ds.encryptBytes(ds_bytes);
        Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        res = ds.decryptBytes(res);
        Console.WriteLine(Encoding.Default.GetString(answ));
        return;
    }

    public void time_tester()
    {
        var sw = new Stopwatch();
        sw.Start();

        {

        }

        sw.Stop();
        Console.WriteLine("ecb decrypt time" + sw.Elapsed);
    }
}
