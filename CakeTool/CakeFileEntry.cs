using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

using Syroot.BinaryData.Memory;

public class CakeFileEntry
{
    public uint StringOffset;
    public uint Unk;
    public uint Crc;
    public uint Size;
    public ulong Offset;
    public uint Type;

    public void Read(ref SpanReader sr)
    {
        StringOffset = sr.ReadUInt32();
        Unk = sr.ReadUInt32();
        Crc = sr.ReadUInt32();
        Size = sr.ReadUInt32();
        Offset = sr.ReadUInt64();
        Type = sr.ReadUInt32();
    }
}
