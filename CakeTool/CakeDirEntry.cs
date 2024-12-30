using Syroot.BinaryData.Memory;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

public class CakeDirEntry
{
    public ulong DirNameHash;
    public uint Unk;

    public void Read(ref SpanReader sr)
    {
        DirNameHash = sr.ReadUInt64();
        Unk = sr.ReadUInt32();
    }
}
