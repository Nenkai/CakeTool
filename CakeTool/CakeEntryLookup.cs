using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Syroot.BinaryData.Memory;

namespace CakeTool;

// SysCore::EntryLookup
public class CakeEntryLookup
{
    public ulong NameHash { get; set; }
    public uint BitFlags { get; set; }

    public uint EntryIndex => BitFlags & 0x7FFFFFFF;
    public bool IsEmptyFile => (BitFlags >> 31) != 0;

    public void Read(ref SpanReader sr)
    {
        NameHash = sr.ReadUInt64();
        BitFlags = sr.ReadUInt32();
    }
}
