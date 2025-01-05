using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

public static class Utils
{
    public static uint ExtractU8_U32(uint val, int byteIndex)
        => (val >> (8 * byteIndex));

    public static ulong ExtractU8_U64(ulong val, int byteIndex)
        => (val >> (8 * byteIndex));

}
