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
    public uint ParentDirIndex;
    public uint CompressedSize;
    public uint ResourceTypeSignature;
    public ulong DataOffset;
    public uint DecompressedSize;
    public ushort NumChunks; // 0x1C
    // 8-8-14-2? bits - 2 upper bits may be unused
    public uint RawBitFlags; // 0x1E

    public byte UnkBits
    {
        get => (byte)(RawBitFlags & 0b11111111);
        set => RawBitFlags |= (byte)(value & 0b11111111);
    }

    public byte UnkBits2 // Compression type?
    {
        get => (byte)((RawBitFlags >> 8) & 0b11111111);
        set => RawBitFlags |= (byte)((value & 0b11111111) << 8);
    }

    public CakeFileFlags UnkFlags3
    {
        get => (CakeFileFlags)((RawBitFlags >> 16) & 0b11_1111_1111_1111);
        set => RawBitFlags |= (byte)(((ushort)value & 0b11_1111_1111_1111) << 16);
    }

    public List<uint> ChunkSizes = [];

    public void Read(ref SpanReader sr)
    {
        StringOffset = sr.ReadUInt32();
        ParentDirIndex = sr.ReadUInt32();
        CompressedSize = sr.ReadUInt32();
        ResourceTypeSignature = sr.ReadUInt32();
        DataOffset = sr.ReadUInt64();
        DecompressedSize = sr.ReadUInt32();
        NumChunks = sr.ReadUInt16();
        RawBitFlags = sr.ReadUInt32();

        for (int i = 0; i < NumChunks; i++)
            ChunkSizes.Add(sr.ReadUInt32());
    }

    [Flags]
    public enum CakeFileFlags : ushort
    {
        Encrypted = 1 << 10
    }
}
