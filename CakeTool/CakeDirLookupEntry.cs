using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Syroot.BinaryData.Memory;

namespace CakeTool;

public class CakeDirLookupEntry
{
    public ulong NameHash { get; set; }
    public uint DirEntryIndex { get; set; }

    public void Read(ref SpanReader sr)
    {
        NameHash = sr.ReadUInt64();
        DirEntryIndex = sr.ReadUInt32();
    }
}
