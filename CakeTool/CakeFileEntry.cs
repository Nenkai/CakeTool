using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

using Syroot.BinaryData;
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

    // 1 = compressed?
    public byte UnkBitsCompressedMaybe
    {
        get => (byte)(RawBitFlags & 0b11111111);
        set => RawBitFlags |= (byte)(value & 0b11111111);
    }

    // 1 = encrypted?
    public byte UnkBits2EncryptedMaybe
    {
        get => (byte)((RawBitFlags >> 8) & 0b11111111);
        set => RawBitFlags |= (byte)((value & 0b11111111) << 8);
    }

    // 1024 = ???? resource?
    public ushort UnkFlags3
    {
        get => (ushort)((RawBitFlags >> 16) & 0b11_1111_1111_1111);
        set => RawBitFlags |= (byte)((value & 0b11_1111_1111_1111) << 16);
    }

    public List<uint> ChunkEndOffsets = [];

    // For building. Do not use
    public uint FileEntryIndex { get; set; }
    public string FileName { get; set; }
    public string RelativePath { get; set; }
    public string LocalPath { get; set; }

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
                ChunkEndOffsets.Add(sr.ReadUInt32());
        }
        else if (versionMajor >= 8)
        {
            if (versionMinor == 7)
            {
                StringOffset = sr.ReadUInt32();
                ParentDirIndex = sr.ReadUInt32();
                CompressedSize = sr.ReadUInt32();
                DataOffset = sr.ReadUInt64();
                ResourceTypeSignature = sr.ReadUInt32();
                ExpandedSize = sr.ReadUInt32();
                RawBitFlags = sr.ReadByte(); //enc flag? seems to match when it's encrypted. storing to raw bit flags for now.
            }
            else
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

    public void Write(BinaryStream bs, byte versionMajor, byte versionMinor)
    {
        if (versionMajor >= 9)
        {
            bs.WriteUInt32(StringOffset);
            bs.WriteUInt32(ParentDirIndex);
            bs.WriteUInt32(CompressedSize);
            bs.WriteUInt32(ResourceTypeSignature);
            bs.WriteUInt64(DataOffset);
            bs.WriteUInt32(ExpandedSize);
            bs.WriteUInt16(NumChunks);
            bs.WriteUInt32(RawBitFlags);

            foreach (var offset in ChunkEndOffsets)
                bs.WriteUInt32(offset);
        }
        else if (versionMajor >= 8)
        {
            if (versionMinor == 7)
            {
                bs.WriteUInt32(StringOffset);
                bs.WriteUInt32(ParentDirIndex);
                bs.WriteUInt32(CompressedSize);
                bs.WriteUInt64(DataOffset);
                bs.WriteUInt32(ResourceTypeSignature);
                bs.WriteUInt32(ExpandedSize);
                bs.WriteByte((byte)RawBitFlags); //enc flag? seems to match when it's encrypted. storing to raw bit flags for now.
            }
            else
            {
                // 0x20
                bs.WriteUInt32(StringOffset);
                bs.WriteUInt32(ParentDirIndex);
                bs.WriteUInt32(CRCChecksum);
                bs.WriteUInt32(CompressedSize);
                bs.WriteUInt64(DataOffset);
                bs.WriteUInt32(ResourceTypeSignature);
                bs.WriteUInt32(ExpandedSize); // New
            }
        }
        else
        {
            // 0x1C
            bs.WriteUInt32(StringOffset);
            bs.WriteUInt32(ParentDirIndex);
            bs.WriteUInt32(CRCChecksum);
            bs.WriteUInt32(CompressedSize);
            bs.WriteUInt64(DataOffset);
            bs.WriteUInt32(ResourceTypeSignature);
        }
    }

    public uint GetSize(byte versionMajor, byte versionMinor)
    {
        if (versionMajor >= 9)
            return 0x22 + ((uint)ChunkEndOffsets.Count * 4);
        else if (versionMajor >= 8)
        {
            if (versionMinor == 7)
                return 0x1D;
            else
                return 0x20;
        }
        else
        {
            return 0x1C;
        }
    }
}
