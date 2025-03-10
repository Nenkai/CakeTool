using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;

namespace CakeTool;

// SysCore::EntryLookup
public class CakeEntryLookup
{
    public ulong NameHash { get; set; }
    public uint BitFlags { get; set; }

    public uint EntryIndex
    {
        get => BitFlags & 0x7FFFFFFF;
        set => BitFlags = (uint)(value & 0x7FFFFFFFF);
    }

    public bool IsEmptyFile
    {
        get => (BitFlags >> 31) != 0;
        set => BitFlags |= (value ? 1u : 0u << 31);
    }

    public void Read(ref SpanReader sr)
    {
        NameHash = sr.ReadUInt64();
        BitFlags = sr.ReadUInt32();
    }

    public void Write(BinaryStream bs, byte versionMajor, byte versionMinor)
    {
        bs.WriteUInt64(NameHash);
        bs.WriteUInt32(BitFlags);
    }

    public uint GetSize(byte versionMajor, byte versionMinor)
    {
        return 0x0C;
    }
}
