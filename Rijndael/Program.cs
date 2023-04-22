// See https://aka.ms/new-console-template for more information
using Des;
using Rijndael;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks.Dataflow;

class Programm
{
    async static Task Main(string[] args)
    {
        //test_rijn();
        //Console.WriteLine("\n\n\n-------------Des--------------\n\n");
        //test_des();

        test_rijn();
    }

    public static async Task testaes()
    {
        string ipv_string = "1234567812345678";
        byte[] ipv = Encoding.UTF8.GetBytes(ipv_string);

        string key_string = "adgjl234228qwert";
        byte[] key = Encoding.UTF8.GetBytes(key_string);

        byte pln = 0x1b;
        RijndaelCore rn = new RijndaelCore(key, CryptoCenter.CryptType.OFB, CryptoCenter.Padding.PKCS, ipv, new int[] { 32, 16, pln });
        //DesCore ds = new Des.DesCore(ipv, CryptoCenter.CryptType.CFB, ipv, new int[] { 8 });

        string opath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\in.txt";
        string vidpath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\out.mp4";
        string ipath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\some.mp4";
        string opath2 = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\some2.txt";
        string ipath2 = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\some3.mp4";
        string oopath = "C:\\Users\\t.rakhmatullin\\Documents\\dmdir\\scam\\oout.txt";

        string vipath = "C:\\Users\\rahma\\Downloads\\snowNightSad.mp4";

        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var stringChars = new char[32];
        var random = new Random();

        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = chars[random.Next(chars.Length)];
        }

        var finalString = new String(stringChars);
        byte[] ds_bytes = Encoding.UTF8.GetBytes(finalString);

        byte[] res;
        await rn.encryptFile(opath, opath2);
        await rn.decryptFile(opath2, ipath2);
        Console.WriteLine(Encoding.Default.GetString(ds_bytes));
        res = rn.encryptBytes(ds_bytes);
        Console.WriteLine("\n\n\n------------------------------------------------------------\n\n\n");
        res = rn.decryptBytes(res);
        Console.WriteLine(Encoding.Default.GetString(res));

        await rn.encryptFile(vidpath, opath2);
        await rn.decryptFile(opath2, ipath2);
        Console.WriteLine("end");
    }

    public static void test_rijn()
    {
        string trash1 = "nvw[82a0";
        string trahs2 = "ofi_23fw";
        string ipv_string = "12345678adgjl234";
        byte[] ipv = Encoding.UTF8.GetBytes(ipv_string);

        string key_string =  "adgjl23412345678" + trahs2 + trash1;
        byte[] key = Encoding.UTF8.GetBytes(key_string);


        //string ipath = "C:\\Users\\t.rakhmatullin\\Documents\\dmdir\\scam\\matrix2.txt";
        //string opath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\some.txt";
        //string oopath = "C:\\Users\\t.rakhmatullin\\Documents\\dmdir\\scam\\oout.txt";

        //string vipath = "C:\\Users\\rahma\\Downloads\\invisible.mp4";


        //ds.encryptFile(ipath, opath);
        //await ds.encryptFile(vipath, opath);
        //await ds.decryptFile(opath, oopath);
        //Console.WriteLine("end");

        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var stringChars = new char[32];
        var random = new Random();

        int nb = 16, nk = 32;

        for (int j = 0; j < stringChars.Length; j++)
        {
            stringChars[j] = chars[random.Next(chars.Length)];
        }

        CryptoCenter.CryptType[] tmp = {
            CryptoCenter.CryptType.ECB,
            CryptoCenter.CryptType.CBC,
            CryptoCenter.CryptType.CFB,
            CryptoCenter.CryptType.OFB,
            CryptoCenter.CryptType.CTR,
            CryptoCenter.CryptType.RD
        };

        var finalString = new String(stringChars);
        Console.WriteLine(finalString);

        var pol = GF.getPolynomes();
        int i = 0;

        foreach ( CryptoCenter.CryptType t in tmp )
        {
            byte[] ds_bytes = Encoding.UTF8.GetBytes(finalString);
            RijndaelCore ds = new(key, t, CryptoCenter.Padding.PKCS, ipv, new int[] { nb, nk, pol[i] });
            byte[] res = ds.encryptBytes(ds_bytes);
            Console.WriteLine("\n\n\n----------------------------" + t + "-----------" + pol[i] + "---------------------\n\n\n");
            byte[] answ = ds.decryptBytes(res);
            Console.WriteLine(Encoding.Default.GetString(answ));
            i++;
        }

        return;
    }

    public static void test_des()
    {
        string ipv_string = "12345678";
        byte[] ipv = Encoding.UTF8.GetBytes(ipv_string);

        string key_string = "adgjl234";
        byte[] key = Encoding.UTF8.GetBytes(key_string);


        //string ipath = "C:\\Users\\t.rakhmatullin\\Documents\\dmdir\\scam\\matrix2.txt";
        //string opath = "C:\\Users\\rahma\\Documents\\6_term\\Crypta\\someFIles\\some.txt";
        //string oopath = "C:\\Users\\t.rakhmatullin\\Documents\\dmdir\\scam\\oout.txt";

        //string vipath = "C:\\Users\\rahma\\Downloads\\invisible.mp4";


        //ds.encryptFile(ipath, opath);
        //await ds.encryptFile(vipath, opath);
        //await ds.decryptFile(opath, oopath);
        //Console.WriteLine("end");

        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var stringChars = new char[93];
        var random = new Random();

        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = chars[random.Next(chars.Length)];
        }

        CryptoCenter.CryptType[] tmp = {
            CryptoCenter.CryptType.ECB,
            CryptoCenter.CryptType.CBC,
            CryptoCenter.CryptType.CFB,
            CryptoCenter.CryptType.OFB,
            CryptoCenter.CryptType.CTR,
            CryptoCenter.CryptType.RD
        };

        var finalString = new String(stringChars);
        Console.WriteLine(finalString);

        foreach (CryptoCenter.CryptType t in tmp)
        {
            byte[] ds_bytes = Encoding.UTF8.GetBytes(finalString);
            DesCore ds = new(key, t, CryptoCenter.Padding.PKCS, ipv, new int[] { 8 });
            byte[] res = ds.encryptBytes(ds_bytes);
            Console.WriteLine("\n\n\n----------------------------" + t + "--------------------------------\n\n\n");
            byte[] answ = ds.decryptBytes(res);
            Console.WriteLine(Encoding.Default.GetString(answ));
        }
    }
}
