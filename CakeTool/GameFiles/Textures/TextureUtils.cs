using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool.GameFiles.Textures;

public class TextureUtils
{
    public static readonly Dictionary<uint, GEBaseFmt> FormatHashToFormat = new()
    {
        [0xFFFFFFFF] = GEBaseFmt.Invalid,
        [0x7FD9CD97] = GEBaseFmt.BC1,
        [0x4A28D98B] = GEBaseFmt.BC4,
        [0x6C893E63] = GEBaseFmt.BC2,
        [0x9EE2BD60] = GEBaseFmt.BC3,
        [0xB8435A88] = GEBaseFmt.BC5,
        [0x85121088] = GEBaseFmt.BC6H,
        [0x59782A7F] = GEBaseFmt.BC7,
        [0xD34782C5] = GEBaseFmt.R8,

        [0xE5238BD5] = GEBaseFmt.R8_G8,
        [0x3C26D39D] = GEBaseFmt.R16,
        [0x767C77E0] = GEBaseFmt.R8_G8_B8_A8,
        [0xA453BBA5] = GEBaseFmt.R16_G16,
        [0xDCF9746C] = GEBaseFmt.R32,
        [0x6706FB25] = GEBaseFmt.R10_G10_B10_A2,
        [0xFA0EA0DB] = GEBaseFmt.R11_G11_B10,

        [0x6426214C] = GEBaseFmt.R16_G16_B16_A16,
        [0x7F450227] = GEBaseFmt.R32_G32,
        [0x25207D67] = GEBaseFmt.R32_G32_B32,
        [0x99F9905E] = GEBaseFmt.R32_G32_B32_A32,
        [0x9D355800] = GEBaseFmt.D16,
        [0x7DEAFFF1] = GEBaseFmt.D32,
        [0xF9522E43] = GEBaseFmt.R32_S8,
    };

    public static readonly Dictionary<GEBaseFmt, uint> GEFormatToHash = new()
    {
        [GEBaseFmt.Invalid] = 0xFFFFFFFF,
        [GEBaseFmt.BC1]    = 0x7FD9CD97, 
        [GEBaseFmt.BC4]    = 0x4A28D98B, 
        [GEBaseFmt.BC2]    = 0x6C893E63, 
        [GEBaseFmt.BC3]    = 0x9EE2BD60, 
        [GEBaseFmt.BC5]    = 0xB8435A88, 
        [GEBaseFmt.BC6H]   = 0x85121088, 
        [GEBaseFmt.BC7]    = 0x59782A7F, 
        [GEBaseFmt.R8]     = 0xD34782C5, 

        [GEBaseFmt.R8_G8]          = 0xE5238BD5, 
        [GEBaseFmt.R16]            = 0x3C26D39D, 
        [GEBaseFmt.R8_G8_B8_A8]    = 0x767C77E0, 
        [GEBaseFmt.R16_G16]        = 0xA453BBA5, 
        [GEBaseFmt.R32]            = 0xDCF9746C, 
        [GEBaseFmt.R10_G10_B10_A2] = 0x6706FB25, 
        [GEBaseFmt.R11_G11_B10]    = 0xFA0EA0DB, 

        [GEBaseFmt.R16_G16_B16_A16] = 0x6426214C, 
        [GEBaseFmt.R32_G32]        = 0x7F450227, 
        [GEBaseFmt.R32_G32_B32]    = 0x25207D67, 
        [GEBaseFmt.R32_G32_B32_A32] = 0x99F9905E, 
        [GEBaseFmt.D16]            = 0x9D355800, 
        [GEBaseFmt.D32]            = 0x7DEAFFF1, 
        [GEBaseFmt.R32_S8]         = 0xF9522E43, 
    };

    public static readonly Dictionary<uint, GEType> TypeHashToType = new()
    {
        [0xFFFFFFFF] = GEType.Invalid,
        [0x47B58E5F] = GEType.Float,
        [0x5C0D3942] = GEType.UNorm,
        [0xCC6A58AA] = GEType.SNorm,
        [0x2938935] = GEType.UInt,
        [0x0C6D69B47] = GEType.SInt,
        [0x0C9D983AA] = GEType.UF16,
        [0x0D9C91D8] = GEType.SF16,
    };

    public static void ConvertToDDS(TextureMeta texMeta, Stream imageDataStream, Stream outputStream)
    {
        var header = new DdsHeader();
        header.Flags = DDSHeaderFlags.TEXTURE | DDSHeaderFlags.LINEARSIZE;
        header.Width = texMeta.Width;
        header.Height = texMeta.Height;
        header.FormatFlags = DDSPixelFormatFlags.DDPF_FOURCC;
        header.FourCCName = "DX10";
        header.LastMipmapLevel = texMeta.NumMipmaps;
        if (texMeta.NumMipmaps > 1)
            header.Flags |= DDSHeaderFlags.MIPMAP;
        header.DxgiFormat = TextureUtils.GEFormatToDXGIFormat(texMeta.Format, texMeta.Type, texMeta.IsSRGB);
        header.Write(outputStream, imageDataStream);
    }

    public static DXGI_FORMAT GEFormatToDXGIFormat(GEBaseFmt format, GEType type, bool isSRGB)
    {
        return format switch
        {
            GEBaseFmt.Invalid => throw new NotImplementedException($"GEFormatToDXGIFormat: Got {GEBaseFmt.Invalid}"),

            // Known to be used
            GEBaseFmt.BC1 => type switch 
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_BC1_TYPELESS,
                GEType.UNorm => isSRGB ? DXGI_FORMAT.DXGI_FORMAT_BC1_UNORM_SRGB : DXGI_FORMAT.DXGI_FORMAT_BC1_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: BC1 format type {type} not supported"),
            },

            // Known to be used
            GEBaseFmt.BC4 => type switch
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_BC4_TYPELESS,
                GEType.UNorm => DXGI_FORMAT.DXGI_FORMAT_BC4_UNORM,
                GEType.SNorm => DXGI_FORMAT.DXGI_FORMAT_BC4_SNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: BC4 format type {type} not supported"),
            },

            GEBaseFmt.BC2 => type switch
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_BC2_TYPELESS,
                GEType.UNorm => isSRGB ? DXGI_FORMAT.DXGI_FORMAT_BC2_UNORM_SRGB : DXGI_FORMAT.DXGI_FORMAT_BC2_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: BC2 forma type {type} not supported"),
            },

            // Known to be used
            GEBaseFmt.BC3 => type switch
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_BC3_TYPELESS,
                GEType.UNorm => isSRGB ? DXGI_FORMAT.DXGI_FORMAT_BC3_UNORM_SRGB : DXGI_FORMAT.DXGI_FORMAT_BC3_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: BC3 format type {type} not supported"),
            },

            // Known to be used
            GEBaseFmt.BC5 => type switch
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_BC5_TYPELESS,
                GEType.UNorm => DXGI_FORMAT.DXGI_FORMAT_BC5_UNORM,
                GEType.SNorm => DXGI_FORMAT.DXGI_FORMAT_BC5_SNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: BC5 format type {type} not supported"),
            },

            // Known to be used
            GEBaseFmt.BC6H => type switch
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_BC6H_TYPELESS,
                GEType.SF16 => DXGI_FORMAT.DXGI_FORMAT_BC6H_SF16,
                GEType.UF16 => DXGI_FORMAT.DXGI_FORMAT_BC6H_UF16,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: BC6H format type {type} not supported"),
            },

            // Known to be used
            GEBaseFmt.BC7 => type switch
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_BC7_TYPELESS,
                GEType.UNorm => isSRGB ? DXGI_FORMAT.DXGI_FORMAT_BC7_UNORM_SRGB : DXGI_FORMAT.DXGI_FORMAT_BC7_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: BC7 format type {type} not supported"),
            },

            GEBaseFmt.R8 => type switch
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_R8_TYPELESS, // according to game
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R8_SINT,
                GEType.SNorm => DXGI_FORMAT.DXGI_FORMAT_R8_SNORM,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R8_UINT,
                GEType.UNorm => DXGI_FORMAT.DXGI_FORMAT_R8_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R8 format type {type} not supported"),
            },
            GEBaseFmt.R8_G8 => throw new NotImplementedException("R8_G8 is not implemented, sorry!"),
            GEBaseFmt.R16 => type switch
            {
                GEType.Invalid => DXGI_FORMAT.DXGI_FORMAT_R16_TYPELESS, // according to game
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R16_FLOAT,
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R16_SINT,
                GEType.SNorm => DXGI_FORMAT.DXGI_FORMAT_R16_SNORM,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R16_UINT,
                GEType.UNorm => DXGI_FORMAT.DXGI_FORMAT_R16_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R16 format type {type} not supported"),
            },
            // Known to be used
            GEBaseFmt.R8_G8_B8_A8 => type switch
            {
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_SINT,
                GEType.SNorm => DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_SNORM,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UINT,
                GEType.UNorm => isSRGB ? DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM_SRGB : DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R8_G8_B8_A8 format type {type} not supported"),
            },
            GEBaseFmt.R16_G16 => type switch
            {
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R16G16_FLOAT,
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R16G16_SINT,
                GEType.SNorm => DXGI_FORMAT.DXGI_FORMAT_R16G16_SNORM,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R16G16_UINT,
                GEType.UNorm => DXGI_FORMAT.DXGI_FORMAT_R16G16_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R16_G16 format type {type} not supported"),
            },
            GEBaseFmt.R32 => type switch
            {
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R32_FLOAT,
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R32_SINT,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R32_UINT,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R32 format type {type} not supported"),
            },
            GEBaseFmt.R10_G10_B10_A2 => type switch
            {
                GEType.UNorm => DXGI_FORMAT.DXGI_FORMAT_R10G10B10A2_UNORM,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R10G10B10A2_UINT,
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R11G11B10_FLOAT,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R10_G10_B10_A2 format type {type} not supported"),
            },
            GEBaseFmt.R11_G11_B10 => DXGI_FORMAT.DXGI_FORMAT_R11G11B10_FLOAT,
            GEBaseFmt.R16_G16_B16_A16 => type switch
            {
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_FLOAT,
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_SINT,
                GEType.SNorm => DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_SNORM,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_UINT,
                GEType.UNorm => DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R16_G16_B16_A16 format type {type} not supported"),
            },
            GEBaseFmt.R32_G32 => type switch
            {
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R32G32_FLOAT,
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R32G32_SINT,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R32G32_UINT,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R32_G32 format type {type} not supported"),
            },
            GEBaseFmt.R32_G32_B32 => type switch
            {
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R32G32B32_FLOAT,
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R32G32B32_SINT,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R32G32B32_UINT,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R32_G32_B32 format type {type} not supported"),
            },
            // Known to be used
            GEBaseFmt.R32_G32_B32_A32 => type switch
            {
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R32G32B32A32_FLOAT,
                GEType.SInt => DXGI_FORMAT.DXGI_FORMAT_R32G32B32A32_SINT,
                GEType.UInt => DXGI_FORMAT.DXGI_FORMAT_R32G32B32A32_UINT,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R32_G32_B32_A32 format type {type} not supported"),
            },
            GEBaseFmt.D16 => type switch
            {
                GEType.UNorm => DXGI_FORMAT.DXGI_FORMAT_D16_UNORM,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: D16 format type {type} not supported"),
            },
            GEBaseFmt.D32 => type switch
            {
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_D32_FLOAT,
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: D32 format type {type} not supported"),
            },
            GEBaseFmt.R32_S8 => type switch
            {
                GEType.Float => DXGI_FORMAT.DXGI_FORMAT_R32G8X24_TYPELESS, // Or DXGI_FORMAT_D32_FLOAT_S8X24_UINT?
                _ => throw new NotImplementedException($"{nameof(GEFormatToDXGIFormat)}: R32_S8 format type {type} not supported"),
            },
            _ => throw new NotImplementedException(),
        };
    }

    public static void DXGIFormatToGE(DXGI_FORMAT format, out GEBaseFmt geFormat, out GEType geType, out bool isSRGB)
    {
        switch (format)
        {
            case DXGI_FORMAT.DXGI_FORMAT_BC1_TYPELESS:
                geFormat = GEBaseFmt.BC1;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC1_UNORM:
            case DXGI_FORMAT.DXGI_FORMAT_BC1_UNORM_SRGB:
                geFormat = GEBaseFmt.BC1;
                geType = GEType.UNorm;
                isSRGB = format == DXGI_FORMAT.DXGI_FORMAT_BC1_UNORM_SRGB;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_BC4_TYPELESS:
                geFormat = GEBaseFmt.BC4;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC4_UNORM:
                geFormat = GEBaseFmt.BC4;
                geType = GEType.UNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC4_SNORM:
                geFormat = GEBaseFmt.BC4;
                geType = GEType.SNorm;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_BC2_TYPELESS:
                geFormat = GEBaseFmt.BC2;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC2_UNORM:
            case DXGI_FORMAT.DXGI_FORMAT_BC2_UNORM_SRGB:
                geFormat = GEBaseFmt.BC2;
                geType = GEType.UNorm;
                isSRGB = format == DXGI_FORMAT.DXGI_FORMAT_BC2_UNORM_SRGB;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_BC3_TYPELESS:
                geFormat = GEBaseFmt.BC3;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC3_UNORM:
            case DXGI_FORMAT.DXGI_FORMAT_BC3_UNORM_SRGB:
                geFormat = GEBaseFmt.BC3;
                geType = GEType.UNorm;
                isSRGB = isSRGB = format == DXGI_FORMAT.DXGI_FORMAT_BC3_UNORM_SRGB;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_BC5_TYPELESS:
                geFormat = GEBaseFmt.BC5;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC5_UNORM:
                geFormat = GEBaseFmt.BC5;
                geType = GEType.UNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC5_SNORM:
                geFormat = GEBaseFmt.BC5;
                geType = GEType.SNorm;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_BC6H_TYPELESS:
                geFormat = GEBaseFmt.BC6H;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC6H_SF16:
                geFormat = GEBaseFmt.BC6H;
                geType = GEType.SF16;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC6H_UF16:
                geFormat = GEBaseFmt.BC6H;
                geType = GEType.UF16;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_BC7_TYPELESS:
                geFormat = GEBaseFmt.BC7;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_BC7_UNORM:
            case DXGI_FORMAT.DXGI_FORMAT_BC7_UNORM_SRGB:
                geFormat = GEBaseFmt.BC7;
                geType = GEType.UNorm;
                isSRGB = format == DXGI_FORMAT.DXGI_FORMAT_BC7_UNORM_SRGB;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R8_TYPELESS:
                geFormat = GEBaseFmt.R8;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R8_SINT:
                geFormat = GEBaseFmt.R8;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R8_SNORM:
                geFormat = GEBaseFmt.R8;
                geType = GEType.SNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R8_UINT:
                geFormat = GEBaseFmt.R8;
                geType = GEType.UInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R8_UNORM:
                geFormat = GEBaseFmt.R8;
                geType = GEType.UNorm;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R16_TYPELESS:
                geFormat = GEBaseFmt.R16;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16_SINT:
                geFormat = GEBaseFmt.R16;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16_SNORM:
                geFormat = GEBaseFmt.R16;
                geType = GEType.SNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16_UINT:
                geFormat = GEBaseFmt.R16;
                geType = GEType.UInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16_UNORM:
                geFormat = GEBaseFmt.R16;
                geType = GEType.UNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16_FLOAT:
                geFormat = GEBaseFmt.R16;
                geType = GEType.Float;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_SINT:
                geFormat = GEBaseFmt.R8_G8_B8_A8;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_SNORM:
                geFormat = GEBaseFmt.R8_G8_B8_A8;
                geType = GEType.SNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UINT:
                geFormat = GEBaseFmt.R8_G8_B8_A8;
                geType = GEType.UInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM:
            case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
                geFormat = GEBaseFmt.R8_G8_B8_A8;
                geType = GEType.UNorm;
                isSRGB = format == DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R16G16_TYPELESS:
                geFormat = GEBaseFmt.R16_G16;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16_SINT:
                geFormat = GEBaseFmt.R16_G16;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16_SNORM:
                geFormat = GEBaseFmt.R16_G16;
                geType = GEType.SNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16_UINT:
                geFormat = GEBaseFmt.R16_G16;
                geType = GEType.UInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16_UNORM:
                geFormat = GEBaseFmt.R16_G16;
                geType = GEType.UNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16_FLOAT:
                geFormat = GEBaseFmt.R16_G16;
                geType = GEType.Float;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R32_FLOAT:
                geFormat = GEBaseFmt.R32;
                geType = GEType.Float;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R32_SINT:
                geFormat = GEBaseFmt.R32;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R32_UINT:
                geFormat = GEBaseFmt.R32;
                geType = GEType.UInt;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R10G10B10A2_TYPELESS:
                geFormat = GEBaseFmt.R10_G10_B10_A2;
                geType = GEType.Invalid;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R10G10B10A2_UNORM:
                geFormat = GEBaseFmt.R10_G10_B10_A2;
                geType = GEType.UNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R10G10B10A2_UINT:
                geFormat = GEBaseFmt.R10_G10_B10_A2;
                geType = GEType.UInt;
                isSRGB = false;
                break;


            case DXGI_FORMAT.DXGI_FORMAT_R11G11B10_FLOAT:
                geFormat = GEBaseFmt.R11_G11_B10;
                geType = GEType.Float;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_FLOAT:
                geFormat = GEBaseFmt.R16_G16_B16_A16;
                geType = GEType.Float;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_SINT:
                geFormat = GEBaseFmt.R16_G16_B16_A16;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_SNORM:
                geFormat = GEBaseFmt.R16_G16_B16_A16;
                geType = GEType.SNorm;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_UINT:
                geFormat = GEBaseFmt.R16_G16_B16_A16;
                geType = GEType.UInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_UNORM:
                geFormat = GEBaseFmt.R16_G16_B16_A16;
                geType = GEType.UNorm;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R32G32_FLOAT:
                geFormat = GEBaseFmt.R32_G32;
                geType = GEType.Float;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R32G32_SINT:
                geFormat = GEBaseFmt.R32_G32;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R32G32_UINT:
                geFormat = GEBaseFmt.R32_G32;
                geType = GEType.UInt;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R32G32B32_FLOAT:
                geFormat = GEBaseFmt.R32_G32_B32;
                geType = GEType.Float;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R32G32B32_SINT:
                geFormat = GEBaseFmt.R32_G32_B32;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R32G32B32_UINT:
                geFormat = GEBaseFmt.R32_G32_B32;
                geType = GEType.UInt;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R32G32B32A32_FLOAT:
                geFormat = GEBaseFmt.R32_G32_B32_A32;
                geType = GEType.Float;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R32G32B32A32_SINT:
                geFormat = GEBaseFmt.R32_G32_B32_A32;
                geType = GEType.SInt;
                isSRGB = false;
                break;
            case DXGI_FORMAT.DXGI_FORMAT_R32G32B32A32_UINT:
                geFormat = GEBaseFmt.R32_G32_B32_A32;
                geType = GEType.UInt;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_D16_UNORM:
                geFormat = GEBaseFmt.D16;
                geType = GEType.UNorm;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_D32_FLOAT:
                geFormat = GEBaseFmt.D32;
                geType = GEType.Float;
                isSRGB = false;
                break;

            case DXGI_FORMAT.DXGI_FORMAT_R32G8X24_TYPELESS:
                geFormat = GEBaseFmt.R32_S8;
                geType = GEType.Float;
                isSRGB = false;
                break;

            default:
                throw new NotSupportedException($"{nameof(DXGIFormatToGE)}: Texture format {format} is not supported.");
        }
    }
}
