using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Syroot.BinaryData;

namespace CakeTool.GameFiles.Textures;

public class TextureMeta
{
    // v10 = 22
    // v11 = 23
    // v13 = 24
    // v14 = 25
    public byte Version { get; set; }

    public byte Field_0x01 { get; set; }
    public ushort Width { get; set; }
    public ushort Height { get; set; }
    public ushort Depth { get; set; }
    public ulong Field_0x08 { get; set; }
    public ushort Field_0x10 { get; set; }
    public ushort Field_0x12 { get; set; }
    public ushort Field_0x14 { get; set; }
    public ushort Field_0x16 { get; set; }

    /// <summary>
    /// Used in V11, V13.
    /// </summary>
    public uint DecompressedFileSize { get; set; }

    /// <summary>
    /// Used in V10, V11, V14. 
    /// </summary>
    public uint CompressedFileSize { get; set; }

    /// <summary>
    /// Used in V11.
    /// </summary>
    public bool IsCompressed { get; set; }

    public GEBaseFmt Format { get; set; }
    public GEType Type { get; set; }
    public bool IsSRGB { get; set; }
    public byte Field_0x20 { get; set; }
    public byte NumMipmaps { get; set; }
    public byte Field_0x22 { get; set; }
    public byte Field_0x23 { get; set; }
    public byte UnkBitflags_0x24 { get; set; }
    public ulong FilePathHash { get; set; }

    public void Read(Stream stream)
    {
        var bs = stream is BinaryStream ? (BinaryStream)stream : new BinaryStream(stream);
        Version = bs.Read1Byte();

        if (Version == 10 || Version == 11)
        {
            bs.Position += 3;
            Width = bs.ReadUInt16();
            Height = bs.ReadUInt16();
            Depth = bs.ReadUInt16();
            NumMipmaps = bs.Read1Byte();
            Field_0x01 = bs.Read1Byte();
            Field_0x10 = bs.ReadUInt16();
            Field_0x12 = bs.ReadUInt16();
            Field_0x14 = bs.ReadUInt16();
            Field_0x16 = bs.ReadUInt16();
            Format = TextureUtils.FormatHashToFormat[bs.ReadUInt32()];
            Type = TextureUtils.TypeHashToType[bs.ReadUInt32()];
            IsSRGB = bs.ReadBoolean();

            if (Version == 10)
            {
                bs.Align(0x04);
                CompressedFileSize = bs.ReadUInt32();
                uint crunchRelatedMaybe = bs.ReadUInt32();
            }
            else if (Version == 11)
            {
                bs.Position += 1;
                byte mipmapCountMaybe = bs.Read1Byte();
                IsCompressed = bs.ReadBoolean();
                DecompressedFileSize = bs.ReadUInt32();

                if (IsCompressed)
                    CompressedFileSize = bs.ReadUInt32();
            }
        }
        else
        {
            Field_0x01 = bs.Read1Byte();
            Width = bs.ReadUInt16();
            Height = bs.ReadUInt16();
            Depth = bs.ReadUInt16();
            Field_0x08 = bs.ReadUInt64();
            Field_0x10 = bs.ReadUInt16();
            Field_0x12 = bs.ReadUInt16();
            Field_0x14 = bs.ReadUInt16();
            Field_0x16 = bs.ReadUInt16();

            if (Version == 13)
                DecompressedFileSize = bs.ReadUInt32();
            else if (Version == 14)
                CompressedFileSize = bs.ReadUInt32();

            Format = TextureUtils.FormatHashToFormat[bs.ReadUInt32()];

            byte bits = bs.Read1Byte();
            IsSRGB = (bits & 1) == 1;
            Type = (GEType)(bits >> 1);

            NumMipmaps = bs.Read1Byte();
            Field_0x22 = bs.Read1Byte();
            Field_0x23 = bs.Read1Byte();
            UnkBitflags_0x24 = bs.Read1Byte();
            bs.Position += 3;

            if (Version >= 14)
                FilePathHash = bs.ReadUInt64();
        }
    }
}
