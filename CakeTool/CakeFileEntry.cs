using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

using Syroot.BinaryData.Memory;

// SysCore::FileEntry
public class CakeFileEntry
{
    public uint StringOffset { get; set; }
    public uint ParentDirIndex { get; set; }
    public uint CompressedSize { get; set; }
    public uint ResourceTypeSignature { get; set; }
    public ulong DataOffset { get; set; }
    public uint ExpandedSize { get; set; }

    /// <summary>
    /// V6 only?
    /// </summary>
    public uint CRCChecksum { get; set; }

    public ushort NumChunks; // 0x1C
    // 8-8-14-2? bits - 2 upper bits may be unused
    public uint RawBitFlags; // 0x1E

    public byte UnkBits
    {
        get => (byte)(RawBitFlags & 0b11111111);
        set => RawBitFlags |= (byte)(value & 0b11111111);
    }

    public byte UnkBits2
    {
        get => (byte)((RawBitFlags >> 8) & 0b11111111);
        set => RawBitFlags |= (byte)((value & 0b11111111) << 8);
    }

    public ushort UnkFlags3
    {
        get => (ushort)((RawBitFlags >> 16) & 0b11_1111_1111_1111);
        set => RawBitFlags |= (byte)((value & 0b11_1111_1111_1111) << 16);
    }

    public List<uint> ChunkSizes = [];

    public void Read(ref SpanReader sr, byte versionMajor, byte versionMinor)
    {
        if (versionMajor >= 9)
        {
            StringOffset = sr.ReadUInt32();
            ParentDirIndex = sr.ReadUInt32();
            CompressedSize = sr.ReadUInt32();
            ResourceTypeSignature = sr.ReadUInt32();
            DataOffset = sr.ReadUInt64();
            ExpandedSize = sr.ReadUInt32();
            NumChunks = sr.ReadUInt16();
            RawBitFlags = sr.ReadUInt32();

            for (int i = 0; i < NumChunks; i++)
                ChunkSizes.Add(sr.ReadUInt32());
        }
        else if (versionMajor >= 8)
        {
            // 0x20
            StringOffset = sr.ReadUInt32();
            ParentDirIndex = sr.ReadUInt32();
            CRCChecksum = sr.ReadUInt32();
            CompressedSize = sr.ReadUInt32();
            DataOffset = sr.ReadUInt64();
            ResourceTypeSignature = sr.ReadUInt32();
            ExpandedSize = sr.ReadUInt32(); // New
        }
        else
        {
            // 0x1C
            StringOffset = sr.ReadUInt32();
            ParentDirIndex = sr.ReadUInt32();
            CRCChecksum = sr.ReadUInt32();
            CompressedSize = sr.ReadUInt32();
            DataOffset = sr.ReadUInt64();
            ResourceTypeSignature = sr.ReadUInt32();
        }
    }
}
