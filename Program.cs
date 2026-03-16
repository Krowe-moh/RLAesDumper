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
    
    static int FindPattern(byte[] data, string pattern)
    {
        string[] tokens = pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        byte?[] sig = new byte?[tokens.Length];

        for (int i = 0; i < tokens.Length; i++)
        {
            if (tokens[i] == "??" || tokens[i] == "?")
                sig[i] = null;
            else
                sig[i] = Convert.ToByte(tokens[i], 16);
        }

        for (int i = 0; i <= data.Length - sig.Length; i++)
        {
            bool match = true;

            for (int j = 0; j < sig.Length; j++)
            {
                if (sig[j].HasValue && data[i + j] != sig[j].Value)
                {
                    match = false;
                    break;
                }
            }

            if (match)
                return i;
        }

        return -1;
    }

    static void Main()
    {
        Console.Write("Enter RocketLeague Binary path: ");
        string? input = Console.ReadLine();

        if (string.IsNullOrWhiteSpace(input))
        {
            Console.WriteLine("Invalid path.");
            return;
        }

        string path = input.Trim('"');

        if (!File.Exists(path))
        {
            Console.WriteLine("File not found.");
            return;
        }

        var data = File.ReadAllBytes(path);
        // 0x15D230 - 0x17AD0B
        int start = FindPattern(data, "75 E8 C7 85 ?? ?? ?? ?? C1 83 2A 9E 48 8D 8D ?? ?? ?? ??");
        int end   = FindPattern(data, "48 C7 85 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 33 CC E8 ?? ?? ?? ?? 48 81 C4 40 C4 00 00 5D C3");;

        if (start < 0 || end < 0)
        {
            // if invalid just search for this constant 0x9E2A83C1 (Main key)
            Console.WriteLine("Signature not found");
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