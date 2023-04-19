

using Des;
using System.Text;

class Program
{
    static void Main(string[] args)
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
        DesCore ds = new(ipv, CryptoCenter.CryptType.ECB, ipv);
        byte[] data = new byte[] {
            0x12,
            0x34,
            0x56,
            0xAB,
            0xCD,
            0x13,
            0x25,
            0x36 };

        byte[] res = ds.encrypt(data, key);
        byte[] answ = ds.decrypt(res, key);


        string my_data = "qwerty12345678YXZ_+_10101010";
        byte [] ds_bytes = Encoding.UTF8.GetBytes(my_data);

        ds.cryptBytes(ds_bytes, ref res);
        Console.WriteLine(Encoding.Default.GetString(res));
        ds.decryptBytes(res, ref answ);
        Console.WriteLine(Encoding.Default.GetString(answ));

        return;
    }
}
