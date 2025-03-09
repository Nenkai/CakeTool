using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

public class ResourceIds
{
    public static uint Texture => BinaryPrimitives.ReadUInt32LittleEndian("TEX!"u8);
    public static uint Resource => BinaryPrimitives.ReadUInt32LittleEndian("RES!"u8);
}
