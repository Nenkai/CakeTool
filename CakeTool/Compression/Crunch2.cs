using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;

using CommunityToolkit.HighPerformance.Buffers;

namespace CakeTool.Compression;

// This is for custom version of crunch (https://github.com/BinomialLLC/crunch) by Unity:
// https://github.com/Unity-Technologies/crunch/tree/unity
// The game seems to use this version.

// All known tools seem to use this specific exe to handle the game's crunched textures https://github.com/Unity-Technologies/crunch/blob/unity/bin/crunch_x64.exe
// It has extra formats among with other breaking changes. Using the original crunch (self-compiled with latest or not) will not work (textures come out garbled).

// However compiling the unity branch from source doesn't quite seem to have all changes they made
// as it still seems to produce incorrect dds files when built.
// Furthermore crnd::crn_unpacker::unpack_level handles up to format 14 based on IDA research
// Which the source only goes up to 12?.. What happened here?

// Did unity never actually fully update the source or something?
// Many repos on github still seem to have the relevant new stuff (i.e cCRNFmtETC2AS)
// But I can't find anything from unity themselves. Besides, the executable, of course.

// What I think happened is that unity just, never publicly sourced ALL the changes, besides maybe privately (unity source?)
// Crunch2 seems to have all the changes (along with UABE2 and other unity related projects) - https://github.com/FrozenStormInteractive/Crunch2
// So we use that for now.

// I compiled crunch2 and added some extern "C" for C# bindings.
// Compiled as Release-X64 (Release), commit d5cd924754a1b39ea597335a979273ce71ef95a3.

public static partial class Crunch2
{
    [SupportedOSPlatform("windows")]
    [LibraryImport("Libraries/crn2")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(CallConvCdecl) })]
    public static partial nint crn_decompress_crn_to_dds(ReadOnlySpan<byte> pCRN_file_data, ref uint file_size);

    [SupportedOSPlatform("windows")]
    [LibraryImport("Libraries/crn2")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(CallConvCdecl) })]
    private static partial void crn_free_block(nint pBlock);

    /// <summary>
    /// Decompresses Crunch2 data. (Don't forget to dispose of the uncompressed bytes).
    /// </summary>
    /// <param name="data">Compressed data.</param>
    /// <param name="size">Size of the data to decompress.</param>
    /// <param name="uncompressedBytes">Uncompressed bytes. Don't forget to dispose it.</param>
    /// <returns></returns>
    public static bool DecompressToDds(ReadOnlySpan<byte> data, uint size, [NotNullWhen(true)] out MemoryOwner<byte>? uncompressedBytes)
    {
        nint uncompressedData = default;
        try
        {
            uncompressedData = crn_decompress_crn_to_dds(data, ref size);
            if (uncompressedData != default)
            {
                uncompressedBytes = MemoryOwner<byte>.Allocate((int)size);
                ref byte decompRef = ref MemoryMarshal.GetReference(uncompressedBytes.Span.Slice(0, (int)size));

                unsafe
                {
                    Unsafe.CopyBlock(ref decompRef,
                        ref Unsafe.AsRef<byte>((void*)uncompressedData),
                        size);
                }

                return true;
            }
            else
            {
                uncompressedBytes = default;
                return false;
            }
        }
        finally
        {
            if (uncompressedData != default)
                crn_free_block(uncompressedData);
        }
    }
}
