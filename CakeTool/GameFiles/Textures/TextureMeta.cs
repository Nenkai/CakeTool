using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Syroot.BinaryData;

using static CakeTool.GameFiles.Textures.TextureMeta;

namespace CakeTool.GameFiles.Textures;

public class TextureMeta
{
    // v9 = 20
    // v10 = 22
    // v11 = 23
    // v13 = 24
    // v14 = 25
    public byte Version { get; set; }

    public byte Field_0x01 { get; set; }
    public ushort Width { get; set; }
    public ushort Height { get; set; }
    public ushort DepthMaybe { get; set; }
    public ulong Field_0x08 { get; set; }
    public ushort Field_0x10 { get; set; }
    public ushort Field_0x12 { get; set; }
    public ushort Field_0x14 { get; set; }
    public ushort Field_0x16 { get; set; }

    /// <summary>
    /// Used in V11, V13.
    /// </summary>
    public uint ExpandedFileSize { get; set; }

    /// <summary>
    /// Used in V10, V11, V14. 
    /// </summary>
    public uint CompressedFileSize { get; set; }

    /// <summary>
    /// Used in V11.
    /// </summary>
    public bool IsCompressedByte { get; set; }

    public GEBaseFmt Format { get; set; }
    public GEType Type { get; set; }
    public bool IsSRGB { get; set; }
    public byte Field_0x20 { get; set; }
    public byte NumMipmaps { get; set; }
    public byte Field_0x22 { get; set; }
    public byte Field_0x23 { get; set; }

    /// <summary>
    /// Used in >=V13.
    /// </summary>
    public TexMetaFlags UnkBitflags_0x24 { get; set; }

    /// <summary>
    /// Used in >=V14.
    /// </summary>
    public ulong FilePathHash { get; set; }

    public bool IsCompressedTexture()
    {
        if (Version >= 13)
            return UnkBitflags_0x24.HasFlag(TexMetaFlags.HeaderWithCompressedData);
        else if (Version == 11)
            return IsCompressedByte;
        else
            throw new NotImplementedException($"{nameof(IsCompressedTexture)}: <= v11 not yet supported");
    }

    public void SetCompressed(bool flag)
    {
        if (Version >= 13)
        {
            if (flag)
                UnkBitflags_0x24 |= TexMetaFlags.HeaderWithCompressedData;
            else
                UnkBitflags_0x24 &= ~TexMetaFlags.HeaderWithCompressedData;
        }
        else if (Version == 11)
            IsCompressedByte = flag;
        else
            throw new NotImplementedException($"{nameof(SetCompressed)}: <= v11 not yet supported");
    }

    public void Read(Stream stream)
    {
        var bs = stream is BinaryStream ? (BinaryStream)stream : new BinaryStream(stream);
        Version = bs.Read1Byte();

        if (Version == 9 || Version == 10 || Version == 11)
        {
            bs.Position += 3;
            Width = bs.ReadUInt16();
            Height = bs.ReadUInt16();
            DepthMaybe = bs.ReadUInt16();
            NumMipmaps = bs.Read1Byte();
            Field_0x01 = bs.Read1Byte();
            Field_0x10 = bs.ReadUInt16();
            Field_0x12 = bs.ReadUInt16();
            Field_0x14 = bs.ReadUInt16();
            Field_0x16 = bs.ReadUInt16();
            Format = TextureUtils.FormatHashToFormat[bs.ReadUInt32()];
            Type = TextureUtils.TypeHashToType[bs.ReadUInt32()];
            IsSRGB = bs.ReadBoolean();

            if (Version == 9)
            {
                bs.Read1Byte();
                bs.Read1Byte();
                bs.Read1Byte();
                ExpandedFileSize = bs.ReadUInt32();
                uint crunch = bs.ReadUInt32(); // "CRN!"

                // TODO: Support crunch.
                // Game can use https://github.com/BinomialLLC/crunch for bc compression
                // Maybe expand over https://github.com/jacano/ManagedCrunch ?
                // Or reuse AssetRipper implementation
                // https://github.com/AssetRipper/AssetRipper/blob/8435c391bd4db44f6d53aa00515258d2b68f7dda/Source/AssetRipper.Export.Modules.Textures/

                // Relevant calls:
                // crnd::crn_unpacker::init
                // crnd::crn_unpacker::unpack_level
            }
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
                IsCompressedByte = bs.ReadBoolean();
                ExpandedFileSize = bs.ReadUInt32();

                if (IsCompressedByte)
                    CompressedFileSize = bs.ReadUInt32();
            }
        }
        else if (Version >= 13)
        {
            Field_0x01 = bs.Read1Byte();
            Width = bs.ReadUInt16();
            Height = bs.ReadUInt16();
            DepthMaybe = bs.ReadUInt16();
            Field_0x08 = bs.ReadUInt64();
            Field_0x10 = bs.ReadUInt16();
            Field_0x12 = bs.ReadUInt16();
            Field_0x14 = bs.ReadUInt16();
            Field_0x16 = bs.ReadUInt16();

            if (Version == 13)
                ExpandedFileSize = bs.ReadUInt32();
            else if (Version == 14)
                CompressedFileSize = bs.ReadUInt32();

            Format = TextureUtils.FormatHashToFormat[bs.ReadUInt32()];

            byte bits = bs.Read1Byte();
            IsSRGB = (bits & 1) == 1;
            Type = (GEType)(bits >> 1);

            NumMipmaps = bs.Read1Byte();
            Field_0x22 = bs.Read1Byte();
            Field_0x23 = bs.Read1Byte();
            UnkBitflags_0x24 = (TexMetaFlags)bs.Read1Byte();
            bs.Position += 3; // always 0

            if (Version >= 14)
                FilePathHash = bs.ReadUInt64();
        }
    }

    public void Write(Stream stream)
    {
        var bs = new BinaryStream(stream);
        bs.WriteByte(Version);
        if (Version >= 13)
        {
            bs.WriteByte(Field_0x01);
            bs.WriteUInt16(Width);
            bs.WriteUInt16(Height);
            bs.WriteUInt16(DepthMaybe);
            bs.WriteUInt64(0); // No idea, weird hash

            bs.WriteUInt16(0);
            bs.WriteUInt16(0);
            bs.WriteUInt16(0);
            bs.WriteUInt16(0);

            if (Version == 13)
                bs.WriteUInt32(ExpandedFileSize);
            else if (Version == 14)
                bs.WriteUInt32(CompressedFileSize);
            bs.WriteUInt32(TextureUtils.GEFormatToHash[Format]);

            byte bits = (byte)(((byte)Type << 1) | (IsSRGB ? 1 : 0));
            bs.WriteByte(bits);
            bs.WriteByte(NumMipmaps);
            bs.WriteByte(0);
            bs.WriteByte(0);
            bs.WriteByte((byte)UnkBitflags_0x24);
            bs.Position += 3;

            if (Version >= 14)
                bs.WriteUInt64(FilePathHash);
        }
        else
            throw new NotImplementedException("Textures version <v13 not yet supported");
    }

    public static uint GetSize(uint version)
    {
        if (version == 14)
            return 0x30;
        else if (version == 13)
            return 0x28;

        throw new NotImplementedException("Textures version <v13 not yet supported");
    }

    [Flags]
    public enum TexMetaFlags : byte
    {
        Unk1 = 1 << 1,

        /// <summary>
        /// Whether  the data is compressed, ONLY when the data follows the header. <br/>
        /// Does not apply to V9.3 cakes where the header exists only in _textures.tdb.
        /// </summary>
        HeaderWithCompressedData = 1 << 2,
    }
}
