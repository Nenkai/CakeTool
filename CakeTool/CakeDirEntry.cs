using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

using Syroot.BinaryData.Memory;

public class CakeDirEntry
{
    /// <summary>
    /// FNV1A64
    /// </summary>
    public ulong Hash { get; set; }
    public uint PathStringOffset { get; set; }
    public ushort SubFolderCount { get; set; }
    public ushort FileCount { get; set; }
    public List<uint> SubFolderIndices { get; set; } = [];
    public List<uint> FileIndices { get; set; } = [];

    public void Read(ref SpanReader sr)
    {
        Hash = sr.ReadUInt64();
        PathStringOffset = sr.ReadUInt32();
        SubFolderCount = sr.ReadUInt16(); // Confirmed read as ushort (but why?)
        sr.ReadUInt16();
        FileCount = sr.ReadUInt16(); // Confirmed read as ushort
        sr.ReadUInt16();

        for (int i = 0; i < SubFolderCount; i++)
            SubFolderIndices.Add(sr.ReadUInt32());

        for (int i = 0; i < FileCount; i++)
            FileIndices.Add(sr.ReadUInt32());
    }
}
