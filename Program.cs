class RLAesDumper
{
    const uint POLY = 0x04C11DB7;
    static readonly uint[] CrcTable = BuildCrcTable();

    static uint[] BuildCrcTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i << 24;
            for (int j = 0; j < 8; j++)
                crc = (crc & 0x80000000) != 0 ? (crc << 1) ^ POLY : crc << 1;
            t[i] = crc;
        }
        return t;
    }

    static string DecodeAESKey(byte[] buf)
    {
        var r = new byte[buf.Length];

        for (int i = 0; i < buf.Length; i += 4)
        {
            uint crc = ~0x87636Bu;

            for (int j = 0; j < 4; j++)
                crc = (crc << 8) ^ CrcTable[(byte)(buf[i + j] ^ (crc >> 24))];

            crc = ~crc;

            r[i]     = (byte)crc;
            r[i + 1] = (byte)(crc >> 8);
            r[i + 2] = (byte)(crc >> 16);
            r[i + 3] = (byte)(crc >> 24);
        }

        return Convert.ToBase64String(r);
    }

    static int FindSig(byte[] data, byte[] sig)
    {
        for (int i = 0; i < data.Length - sig.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < sig.Length; j++)
                if (data[i + j] != sig[j]) { ok = false; break; }

            if (ok) return i;
        }
        return -1;
    }

    static void Main()
    {
        var data = File.ReadAllBytes(@"C:\Program Files\Epic Games\rocketleague\Binaries\Win64\RocketLeague.exe");

        byte[] startSig = { 0x40,0x55,0x48,0x8D,0xAC,0x24,0xC0,0x3C,0xFF,0xFF,0xB8,0x40,0xC4,0x00,0x00 };
        byte[] endSig   = { 0x48,0x81,0xC4,0x40,0xC4,0x00,0x00,0x5D,0xC3 };

        int start = FindSig(data, startSig);
        int end   = FindSig(data, endSig) + endSig.Length;

        if (start < 0 || end < 0)
        {
            Console.WriteLine("Signature not found"); // 0x15D230 - 0x17AD0B
            return;
        }

        var keys = new List<string>();
        var parts = new uint[8];
        int idx = 0, empty = 0;

        for (int i = start; i < end - 10; i++)
        {
            if (data[i] != 0xC7 || data[i + 1] != 0x85)
                continue;

            parts[idx++] = BitConverter.ToUInt32(data, i + 6);

            if (idx == 8)
            {
                bool allZero = true;
                for (int k = 0; k < 8; k++)
                    if (parts[k] != 0) { allZero = false; break; }

                if (!allZero)
                {
                    var key = new byte[32];
                    for (int k = 0; k < 8; k++)
                        BitConverter.GetBytes(parts[k]).CopyTo(key, k * 4);
                    
                    keys.Add(DecodeAESKey(key));
                }
                else empty++;

                idx = 0;
            }

            i += 9;
        }

        File.WriteAllLines("keys.txt", keys);
        Console.WriteLine($"Done: {keys.Count} keys and {empty} empty entries");
    }
}