using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

public class ResourceIds
{
    public static uint Texture => BinaryPrimitives.ReadUInt32LittleEndian("TEX!"u8);
    public static uint Resource => BinaryPrimitives.ReadUInt32LittleEndian("RES!"u8);
    public static uint JsFlatBuffer => BinaryPrimitives.ReadUInt32LittleEndian("JSFB"u8);
    public static uint Clip => BinaryPrimitives.ReadUInt32LittleEndian("CLIP"u8);
    public static uint Materials => BinaryPrimitives.ReadUInt32LittleEndian("MTLs"u8);
    public static uint MCD => BinaryPrimitives.ReadUInt32LittleEndian("MCD!"u8);
    public static uint INST => BinaryPrimitives.ReadUInt32LittleEndian("INST"u8);
    public static uint YCL => BinaryPrimitives.ReadUInt32LittleEndian("YCL!"u8);
    public static uint MaskInfo => BinaryPrimitives.ReadUInt32LittleEndian("MSKI"u8);
    public static uint CACD => BinaryPrimitives.ReadUInt32LittleEndian("CACD"u8);
    public static uint HCYW => BinaryPrimitives.ReadUInt32LittleEndian("HCYW"u8);
    public static uint HYWA => BinaryPrimitives.ReadUInt32LittleEndian("HYWA"u8);
    public static uint HPL => BinaryPrimitives.ReadUInt32LittleEndian("HPL!"u8);
    public static uint OCYW => BinaryPrimitives.ReadUInt32LittleEndian("OCYW"u8);
    public static uint OYWA => BinaryPrimitives.ReadUInt32LittleEndian("OYWA"u8);
    public static uint CTG => BinaryPrimitives.ReadUInt32LittleEndian("CTG!"u8);
    public static uint WDF => BinaryPrimitives.ReadUInt32LittleEndian("WDF!"u8);
    public static uint MKRS => BinaryPrimitives.ReadUInt32LittleEndian("MKRS"u8);
    public static uint TEXT => BinaryPrimitives.ReadUInt32LittleEndian("TEXT"u8);
    public static uint PKFX => BinaryPrimitives.ReadUInt32LittleEndian("PKFX"u8);
    public static uint PKMN => BinaryPrimitives.ReadUInt32LittleEndian("PKMN"u8);
    public static uint DatabaseTable => BinaryPrimitives.ReadUInt32LittleEndian("DTAB"u8);
    public static uint Alembic => BinaryPrimitives.ReadUInt32LittleEndian("ABC!"u8);
    public static uint Material => BinaryPrimitives.ReadUInt32LittleEndian("MTL!"u8);
    public static uint FontPack => BinaryPrimitives.ReadUInt32LittleEndian("FTPK"u8);
    public static uint StringDatabase => BinaryPrimitives.ReadUInt32LittleEndian("XLOC"u8);
    public static uint SLUG => BinaryPrimitives.ReadUInt32LittleEndian("SLUG"u8);
    public static uint YSH => BinaryPrimitives.ReadUInt32LittleEndian("YSH!"u8);

    public static Dictionary<string, uint> ExtensionToResourceId = new()
    {
        [".jsfb"] = JsFlatBuffer, // JSFB
        [".clips"] = Clip, // CLIP
        [".mtls"] = Materials, // MTLs
        [".tex"] = Texture, // TEX!
        [".mcd"] = MCD, // MCD!
        [".inst"] = INST, // INST
        [".ycl"] = YCL, // YCL!
        [".mskinfo"] = MaskInfo, // MSKI
        [".cacd"] = CACD, // CACD
        [".hair_corr_ywa"] = HCYW, // HCYW
        [".hair_ywa"] = HYWA, // HYWA
        [".hpl"] = HPL, // HPL!
        [".other_corr_ywa"] = OCYW, // OCYW
        [".other_ywa"] = OYWA, // OYWA
        [".ctg"] = CTG, // CTG!
        [".wdf"] = WDF, // WDF!
        [".mfc"] = MKRS, // MKRS
        [".txt"] = TEXT, // TEXT
        [".pkma"] = PKFX, // PKFX
        [".pkmn"] = PKMN, // PKMN
        [".tbl"] = DatabaseTable, // DTAB
        [".alembic"] = Alembic, // ABC!
        [".mtl"] = Material, // MTL!
        [".fntpck"] = FontPack, // FTPK
        [".sdb"] = StringDatabase, // XLOC
        [".slug"] = SLUG, // SLUG
        [".ysh"] = YSH, // YSH!
    };
}
