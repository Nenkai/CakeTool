using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool.Hashing;

public class CRC32C
{
    public static uint Hash(ReadOnlySpan<byte> data)
    {
        uint crc = ~0u;
        for (int i = 0; i < data.Length; i++)
            crc = BitOperations.Crc32C(crc, data[i]);
        return ~crc;
    }
}
