using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;

public class CakeDirInfo
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

    /// <summary>
    /// For building. Do not use
    /// </summary>
    public uint DirIndex { get; set; }

    /// <summary>
    /// For building. Do not use
    /// </summary>
    public string Path { get; set; }

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

    public void Write(BinaryStream bs, byte versionMajor, byte versionMinor)
    {
        bs.WriteUInt64(Hash);
        bs.WriteUInt32(PathStringOffset);
        bs.WriteUInt16(SubFolderCount);
        bs.WriteUInt16(0); // Padding
        bs.WriteUInt16(FileCount);
        bs.WriteUInt16(0); // Padding

        foreach (var index in SubFolderIndices)
            bs.WriteUInt32(index);

        foreach (var index in FileIndices)
            bs.WriteUInt32(index);
    }

    public uint GetSize(byte versionMajor, byte versionMinor)
    {
        uint size = 0x14;
        size += (uint)(SubFolderIndices.Count * sizeof(uint));
        size += (uint)(FileIndices.Count * sizeof(uint));
        return size;
    }
}
