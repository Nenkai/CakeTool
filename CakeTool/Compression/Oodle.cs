using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool.Compression;

public partial class Oodle
{
    /// <summary>
    /// Oodle Library Path
    /// </summary>
    private const string OodleLibraryPath = "oo2core_9_win64";

    /// <summary>
    /// Oodle64 Decompression Method 
    /// </summary>
    [LibraryImport(OodleLibraryPath, EntryPoint = "OodleLZ_Decompress")]
    public static partial long OodleLZ_Decompress(in byte compBuf, long bufferSize, in byte decodeTo, long outputBufferSize, int fuzz,
        int crc, int verbose, long dst_base, long e, long cb, long cb_ctx, long scratch, long scratch_size, int threadPhase);

    public static uint GetCompressedBounds(uint BufferSize)
        => BufferSize + 274 * ((BufferSize + 0x3FFFF) / 0x400000);

    /// <summary>
    /// Decompresses a byte array of Oodle Compressed Data (Requires Oodle DLL)
    /// </summary>
    /// <param name="input">Input Compressed Data</param>
    /// <param name="decompressedLength">Decompressed Size</param>
    /// <returns>Resulting Array if success, otherwise null.</returns>
    public static long Decompress(in byte input, int inputLength, in byte output, long decompressedLength)
    {
        // Decode the data (other parameters such as callbacks not required)
        return OodleLZ_Decompress(input, inputLength, output, decompressedLength, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3);
    }
}
