using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Des
{
    public class CryptoCenter : ICryptTransform2, IKeyGenerate
    {
        public byte[][] round_key;

        CryptType m_type;
        Padding m_padding;
        byte[] m_ipv;
        int BLOCK_LENGHT;
        static int THREAD_COUNT = 8;
        byte[] m__key;

        public enum CryptType
        {
            ECB, CBC, CFB, OFB, CTR, RD, RD_H
        }

        public enum Padding
        {
            PKCS, ANSI, ISO
        }
        public CryptoCenter(byte[] key, CryptType type, Padding pad, byte[] ipv, params int[] other)
        {
            m_padding = pad;
            m_type = type;
            m__key = new byte[key.Length];
            key.CopyTo(m__key, 0);
            m_ipv = new byte[ipv.Length];
            ipv.CopyTo(m_ipv, 0);
            BLOCK_LENGHT = other[0];
        }

        public void makeKeyGeneration()
        {
            round_key = generateKey(m__key);
        }

        public byte[] encryptBytes(byte[] data) 
        {
            int n = data.Length / BLOCK_LENGHT;
            byte[] outdata = new byte[(n + 1) * BLOCK_LENGHT];
            n++;


            if (m_type == CryptType.ECB)
            {
                Task[] tasks = new Task[THREAD_COUNT];
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index;
                        byte[] tmp = new byte[BLOCK_LENGHT];
                        while (index < n - 1)
                        {
                            Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            tmp = encrypt(tmp, null);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);

                n--;
                int block_count = BLOCK_LENGHT;
                if (data.Length % BLOCK_LENGHT != 0)
                {
                    byte[] tmp = new byte[BLOCK_LENGHT];
                    block_count = data.Length % BLOCK_LENGHT;
                    Buffer.BlockCopy(data, n * BLOCK_LENGHT, tmp, 0, block_count);
                    add_padding(ref tmp, BLOCK_LENGHT, block_count);
                    tmp = encrypt(tmp, null);
                    Buffer.BlockCopy(tmp, 0, outdata, n * BLOCK_LENGHT, BLOCK_LENGHT);
                }
                else
                {
                    byte[] tmp = new byte[BLOCK_LENGHT];
                    block_count = data.Length % BLOCK_LENGHT;
                    add_padding(ref tmp, BLOCK_LENGHT, 0);
                    tmp = encrypt(tmp, null);
                    Buffer.BlockCopy(tmp, 0, outdata, n * BLOCK_LENGHT, BLOCK_LENGHT);
                }

            }
            else if (m_type == CryptType.CBC)
            {

                byte[] tmp = new byte[BLOCK_LENGHT];
                byte[] res;

                byte[] ipv = new byte[BLOCK_LENGHT];
                m_ipv.CopyTo(ipv, 0);

                for (int i = 0; i < n; i++)
                {
                    int block_count = BLOCK_LENGHT;
                    if (i == n - 1)
                        block_count = data.Length % BLOCK_LENGHT;
                    Buffer.BlockCopy(data, i * BLOCK_LENGHT, tmp, 0, block_count);
                    if (i == n - 1)
                        add_padding(ref tmp, BLOCK_LENGHT, block_count);
                    tmp = xor_bytes(tmp, ipv);
                    res = encrypt(tmp, null);
                    res.CopyTo(ipv, 0);
                    Buffer.BlockCopy(res, 0, outdata, i * BLOCK_LENGHT, BLOCK_LENGHT);
                }
            }
            else if (m_type == CryptType.CFB)
            {
                byte[] tmp = new byte[BLOCK_LENGHT];
                byte[] res;

                byte[] ipv = new byte[BLOCK_LENGHT];
                m_ipv.CopyTo(ipv, 0);

                for (int i = 0; i < n; i++)
                {
                    int block_count = BLOCK_LENGHT;
                    if (i == n - 1)
                        block_count = data.Length % BLOCK_LENGHT;
                    Buffer.BlockCopy(data, i * BLOCK_LENGHT, tmp, 0, block_count);
                    if (i == n - 1)
                        add_padding(ref tmp, BLOCK_LENGHT, block_count);
                    res = encrypt(ipv, null);
                    tmp = xor_bytes(tmp, res);
                    tmp.CopyTo(ipv, 0);
                    Buffer.BlockCopy(tmp, 0, outdata, i * BLOCK_LENGHT, BLOCK_LENGHT);
                }
            }
            else if (m_type == CryptType.OFB)
            {
                byte[] tmp = new byte[BLOCK_LENGHT];
                byte[] res;

                byte[] ipv = new byte[BLOCK_LENGHT];
                m_ipv.CopyTo(ipv, 0);

                for (int i = 0; i < n; i++)
                {
                    int block_count = BLOCK_LENGHT;
                    if (i == n - 1)
                        block_count = data.Length % BLOCK_LENGHT;
                    Buffer.BlockCopy(data, i * BLOCK_LENGHT, tmp, 0, block_count);
                    if (i == n - 1)
                        add_padding(ref tmp, BLOCK_LENGHT, block_count);
                    res = encrypt(ipv, null);
                    res.CopyTo(ipv, 0);
                    tmp = xor_bytes(tmp, res);
                    Buffer.BlockCopy(tmp, 0, outdata, i * BLOCK_LENGHT, BLOCK_LENGHT);
                }
            }
            else if (m_type == CryptType.CTR)
            {
                Task[] tasks = new Task[THREAD_COUNT];
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index;
                        BigInteger bg = new BigInteger(m_ipv);
                        byte[] ipv;
                        byte[] tmp = new byte[BLOCK_LENGHT];
                        while (index < n)
                        {
                            if (index == n - 1)
                            {
                                int block_count = 0;
                                if (data.Length % BLOCK_LENGHT != 0)
                                    block_count = data.Length % BLOCK_LENGHT;
                                Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, block_count);
                                add_padding(ref tmp, BLOCK_LENGHT, block_count);
                            }
                            else
                            {
                                Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            }
                            bg += index;
                            ipv = bg.ToByteArray();

                            if (ipv.Length != tmp.Length)
                                Array.Resize(ref ipv, tmp.Length);
                            ipv = encrypt(ipv, null);
                            tmp = xor_bytes(tmp, ipv);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);
            }
            else if (m_type == CryptType.RD)
            {
                byte[] delta_array = new byte[m_ipv.Length / 2];
                Buffer.BlockCopy(m_ipv, m_ipv.Length / 2 - 1, delta_array, 0, m_ipv.Length / 2);
                BigInteger delta = new BigInteger(delta_array);

                

                Task[] tasks = new Task[THREAD_COUNT];
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index;
                        BigInteger bg = new BigInteger(m_ipv);
                        bg += index * delta;
                        byte[] ipv;
                        byte[] tmp = new byte[BLOCK_LENGHT];
                        while (index < n)
                        {
                            if (index == n - 1)
                            {
                                int block_count = 0;
                                if (data.Length % BLOCK_LENGHT != 0)
                                    block_count = data.Length % BLOCK_LENGHT;
                                Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, block_count);
                                add_padding(ref tmp, BLOCK_LENGHT, block_count);
                            }
                            else
                            {
                                Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            }
                            ipv = bg.ToByteArray();
                            bg += THREAD_COUNT * delta;
                            
                            if (ipv.Length != tmp.Length)
                                Array.Resize(ref ipv, tmp.Length);
                            ipv = encrypt(ipv, null);
                            tmp = xor_bytes(tmp, ipv);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);
            }
            else if (m_type == CryptType.RD_H)
            {
                byte[] delta_array = new byte[m_ipv.Length / 2];
                Buffer.BlockCopy(m_ipv, m_ipv.Length / 2 - 1, delta_array, 0, m_ipv.Length / 2);
                BigInteger delta = new BigInteger(delta_array);



                Task[] tasks = new Task[THREAD_COUNT];
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index;
                        BigInteger bg = new BigInteger(m_ipv);
                        bg += index * delta;
                        byte[] ipv;
                        byte[] tmp = new byte[BLOCK_LENGHT];
                        while (index < n)
                        {
                            if (index == n - 1)
                            {
                                int block_count = 0;
                                if (data.Length % BLOCK_LENGHT != 0)
                                    block_count = data.Length % BLOCK_LENGHT;
                                Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, block_count);
                                add_padding(ref tmp, BLOCK_LENGHT, block_count);
                            }
                            else
                            {
                                Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            }
                            ipv = bg.ToByteArray();
                            bg += THREAD_COUNT * delta;

                            if (ipv.Length != tmp.Length)
                                Array.Resize(ref ipv, tmp.Length);
                            ipv = encrypt(ipv, null);
                            tmp = xor_bytes(tmp, ipv);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);
            }

            return outdata;
        }
        public byte[] decryptBytes(byte[] data) 
        {
            int n = data.Length / BLOCK_LENGHT;
            byte[] outdata = new byte[n * BLOCK_LENGHT];

            if (m_type == CryptType.ECB)
            {
                Task[] tasks = new Task[THREAD_COUNT];
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index;
                        byte[] tmp = new byte[BLOCK_LENGHT];
                        while (index < n-1)
                        {
                            Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            tmp = decrypt(tmp, null);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);

                byte[] tmp = new byte[BLOCK_LENGHT];

                int padding = 0;
                Buffer.BlockCopy(data, (n - 1) * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                tmp = decrypt(tmp, null);
                padding = del_padding(ref tmp, BLOCK_LENGHT);
                Buffer.BlockCopy(tmp, 0, outdata, (n - 1) * BLOCK_LENGHT, BLOCK_LENGHT - padding);

                if (padding > 0)
                    Array.Resize(ref outdata, outdata.Length - padding);
            }
            else if (m_type == CryptType.CBC)
            {
                byte[] tmp = new byte[BLOCK_LENGHT];
                byte[] ipv = new byte[BLOCK_LENGHT];
                byte[] res;
                int padding = 0;
                m_ipv.CopyTo(ipv, 0);
                Buffer.BlockCopy(data, 0, tmp, 0, BLOCK_LENGHT);
                res = decrypt(tmp, null);
                res = xor_bytes(res, ipv);
                if (n == 1)
                    padding = del_padding(ref res, BLOCK_LENGHT);
                Buffer.BlockCopy(res, 0, outdata, 0, BLOCK_LENGHT - padding);


                Task[] tasks = new Task[THREAD_COUNT];
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index + 1;
                        byte[] tmp = new byte[BLOCK_LENGHT];
                        byte[] ipv = new byte[BLOCK_LENGHT];
                        while (index < n - 1)
                        {
                            Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            tmp = decrypt(tmp, null);
                            Buffer.BlockCopy(data, (index - 1) * BLOCK_LENGHT, ipv, 0, BLOCK_LENGHT);
                            tmp = xor_bytes(tmp, ipv);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);


                if (n > 1)
                {
                    Buffer.BlockCopy(data, (n - 1) * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                    Buffer.BlockCopy(data, (n - 2) * BLOCK_LENGHT, ipv, 0, BLOCK_LENGHT);
                    tmp = decrypt(tmp, null);
                    tmp = xor_bytes(tmp, ipv);
                    padding = del_padding(ref tmp, BLOCK_LENGHT);
                    Buffer.BlockCopy(tmp, 0, outdata, (n - 1) * BLOCK_LENGHT, BLOCK_LENGHT - padding);
                }
                if (padding > 0)
                    Array.Resize(ref outdata, outdata.Length - padding);
            }
            else if (m_type == CryptType.CFB)
            {
                byte[] tmp = new byte[BLOCK_LENGHT];
                byte[] res;

                int padding = 0;

                byte[] ipv = new byte[BLOCK_LENGHT];
                m_ipv.CopyTo(ipv, 0);

                for (int i = 0; i < n; i++)
                {
                    Buffer.BlockCopy(data, i * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                    res = encrypt(ipv, null);
                    tmp.CopyTo(ipv, 0);
                    res = xor_bytes(res, tmp);
                    if (i == n - 1)
                        padding = del_padding(ref res, BLOCK_LENGHT);
                    Buffer.BlockCopy(res, 0, outdata, i * BLOCK_LENGHT, BLOCK_LENGHT - padding);
                }
                if (padding > 0)
                    Array.Resize(ref outdata, outdata.Length - padding);
            }
            else if (m_type == CryptType.OFB)
            {
                byte[] tmp = new byte[BLOCK_LENGHT];
                byte[] res;

                int padding = 0;

                byte[] ipv = new byte[BLOCK_LENGHT];
                m_ipv.CopyTo(ipv, 0);

                for (int i = 0; i < n; i++)
                {
                    Buffer.BlockCopy(data, i * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                    res = encrypt(ipv, null);
                    res.CopyTo(ipv, 0);
                    res = xor_bytes(res, tmp);
                    if (i == n - 1)
                        padding = del_padding(ref res, BLOCK_LENGHT);
                    Buffer.BlockCopy(res, 0, outdata, i * BLOCK_LENGHT, BLOCK_LENGHT - padding);
                }
                if (padding > 0)
                    Array.Resize(ref outdata, outdata.Length - padding);
            }
            else if (m_type == CryptType.CTR)
            {
                Task[] tasks = new Task[THREAD_COUNT];
                int padding = 0;
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index;
                        BigInteger bg = new BigInteger(m_ipv);
                        byte[] ipv;

                        while (index < n)
                        {
                            byte[] tmp = new byte[BLOCK_LENGHT];
                            Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            bg += index;
                            ipv = bg.ToByteArray();
                            if (ipv.Length != tmp.Length)
                                Array.Resize(ref ipv, tmp.Length);
                            ipv = encrypt(ipv, null);
                            tmp = xor_bytes(tmp, ipv);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            if (index == n - 1)
                            {
                                padding = del_padding(ref tmp, BLOCK_LENGHT);
                                Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT - padding);
                            }
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);

                if (padding > 0)
                    Array.Resize(ref outdata, outdata.Length - padding);
            }
            else if (m_type == CryptType.RD)
            {
                byte[] delta_array = new byte[m_ipv.Length / 2];
                Buffer.BlockCopy(m_ipv, m_ipv.Length / 2 - 1, delta_array, 0, m_ipv.Length / 2);
                BigInteger delta = new BigInteger(delta_array);

                Task[] tasks = new Task[THREAD_COUNT];
                int padding = 0;
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index;
                        BigInteger bg = new BigInteger(m_ipv);
                        bg += delta * index;
                        byte[] ipv;

                        while (index < n)
                        {
                            byte[] tmp = new byte[BLOCK_LENGHT];
                            Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            ipv = bg.ToByteArray();
                            bg += THREAD_COUNT * delta;
                            if (ipv.Length != tmp.Length)
                                Array.Resize(ref ipv, tmp.Length);
                            ipv = encrypt(ipv, null);
                            tmp = xor_bytes(tmp, ipv);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            if (index == n - 1)
                            {
                                padding = del_padding(ref tmp, BLOCK_LENGHT);
                                Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT - padding);
                            }
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);

                if (padding > 0)
                    Array.Resize(ref outdata, outdata.Length - padding);
            }
            else if (m_type == CryptType.RD_H)
            {
                byte[] delta_array = new byte[m_ipv.Length / 2];
                Buffer.BlockCopy(m_ipv, m_ipv.Length / 2 - 1, delta_array, 0, m_ipv.Length / 2);
                BigInteger delta = new BigInteger(delta_array);

                Task[] tasks = new Task[THREAD_COUNT];
                int padding = 0;
                for (int i = 0; i < THREAD_COUNT; i++)
                {
                    int thread_index = i;
                    tasks[thread_index] = new Task(() =>
                    {
                        int index = thread_index;
                        BigInteger bg = new BigInteger(m_ipv);
                        bg += delta * index;
                        byte[] ipv;

                        while (index < n)
                        {
                            byte[] tmp = new byte[BLOCK_LENGHT];
                            Buffer.BlockCopy(data, index * BLOCK_LENGHT, tmp, 0, BLOCK_LENGHT);
                            ipv = bg.ToByteArray();
                            bg += THREAD_COUNT * delta;
                            if (ipv.Length != tmp.Length)
                                Array.Resize(ref ipv, tmp.Length);
                            ipv = encrypt(ipv, null);
                            tmp = xor_bytes(tmp, ipv);
                            Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT);
                            if (index == n - 1)
                            {
                                padding = del_padding(ref tmp, BLOCK_LENGHT);
                                Buffer.BlockCopy(tmp, 0, outdata, index * BLOCK_LENGHT, BLOCK_LENGHT - padding);
                            }
                            index += THREAD_COUNT;
                        }
                    });
                    tasks[thread_index].Start();
                }

                Task.WaitAll(tasks);

                if (padding > 0)
                    Array.Resize(ref outdata, outdata.Length - padding);
            }

            return outdata;
        }

        public async Task encryptFile(string filepath, string outfilepath) 
        {
            int BUF_SIZE = 1048576;
            FileStream file = new(filepath, FileMode.OpenOrCreate, FileAccess.Read);
            FileStream outf = new(outfilepath, FileMode.OpenOrCreate, FileAccess.Write);

            byte[] buffer = new byte[BUF_SIZE];
            int n = 1;
            while (n != 0)
            {
                n = await file.ReadAsync(buffer, 0, buffer.Length);
                if (n == 0)
                    break;
                if (n != BUF_SIZE)
                    Array.Resize(ref buffer, n);
                buffer = encryptBytes(buffer);
                await outf.WriteAsync(buffer, 0, buffer.Length);
            }
            file.Close();
            outf.Close();
        }
        public async Task decryptFile(string filepath, string outfilepath) 
        {
            int BUF_SIZE = 1048576;
            FileStream file = new(filepath, FileMode.OpenOrCreate, FileAccess.Read);
            FileStream outf = new(outfilepath, FileMode.OpenOrCreate, FileAccess.Write);

            byte[] buffer = new byte[BUF_SIZE];

            int n = 1;
            while (n != 0)
            {
                n = await file.ReadAsync(buffer, 0, buffer.Length);
                if (n == 0)
                    break;
                if (n != BUF_SIZE)
                    Array.Resize(ref buffer, n);
                buffer = decryptBytes(buffer);
                await outf.WriteAsync(buffer, 0, buffer.Length);
            }
            file.Close();
            outf.Close();
        }

        public virtual byte[] encrypt(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public virtual byte[] decrypt(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public virtual byte[][] generateKey(byte[] key)
        {
            throw new NotImplementedException();
        }


        static public byte[] xor_bytes(byte[] left, byte[] right)
        {
            byte[] res = new byte[left.Length];
            for (int i  = 0; i < left.Length; i++)
            {
                res[i] = (byte)(left[i] ^ right[i]);
            }
            return res;
        }

        public void add_padding(ref byte[] data, int size, int pad)
        {
            byte[] res = new byte[size];

            if (m_padding == Padding.PKCS)
            {
                int count = size - pad;
                if (count == 0)
                    return;

                data.CopyTo(res, 0);
                for (int i = 0; i < count; i++)
                {
                    res[size - 1 - i] = (byte)count;
                }
            }
            else if (m_padding == Padding.ANSI)
            {
                int count = size - pad;
                if (count == 0)
                    return;

                data.CopyTo(res, 0);
                res[size - 1] = (byte)count;
                for (int i = 1; i < count; i++)
                {
                    res[size - 1 - i] = 0x00;
                }
            }
            else if (m_padding == Padding.ISO)
            {
                int count = size - pad;
                if (count == 0)
                    return;

                data.CopyTo(res, 0);
                res[size - 1] = (byte)count;
                var random = new Random();
                for (int i = 1; i < count; i++)
                {
                    res[size - 1 - i] = (byte)random.Next(255);
                }
            }

            data = res;
        }

        public int del_padding(ref byte[] data, int size)
        {
            int count = data[size - 1];

            if (count == 0 || count > size)
                return 0;

            if (m_padding == Padding.PKCS)
            {

                for (int i = 0; i < count && i < data.Length; i++)
                {
                    if (data[size - 1 - i] != (byte)count)
                    {
                        return 0;
                    }
                }

                byte[] res = new byte[size - count];

                Buffer.BlockCopy(data, 0, res, 0, size - count);
                data = res;

            }
            else if (m_padding == Padding.ANSI)
            {
                byte[] res = new byte[size - count];

                Buffer.BlockCopy(data, 0, res, 0, size - count);
                data = res;
            }
            else if (m_padding == Padding.ISO)
            {
                byte[] res = new byte[size - count];

                Buffer.BlockCopy(data, 0, res, 0, size - count);
                data = res;
            }

            return count;
        }
    }
}
