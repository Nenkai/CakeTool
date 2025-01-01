using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using CommunityToolkit.HighPerformance;

using CakeTool.Crypto;
using CakeTool.Hashing;
using CakeTool.Compression;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;
using System.Buffers;
using CommunityToolkit.HighPerformance.Buffers;
using Microsoft.Extensions.Logging;
using System.Reflection.Metadata.Ecma335;

namespace CakeTool;

/// <summary>
/// Cake registry file (disposable object).
/// </summary>
public class CakeRegistryFile : IDisposable
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;

    private FileStream _fileStream;

    public const uint DirSignature = 0x52494446; // 'FDIR'

    public const int DIR_LOOKUP_TABLE_SECTION_INDEX = 0;
    public const int FILE_LOOKUP_TABLE_SECTION_INDEX = 1;
    public const int FILE_INFO_TABLE_SECTION_INDEX = 2;
    public const int DIR_INFO_TABLE_SECTION_INDEX = 3;
    public const int STRING_TABLE_SECTION_INDEX = 4;

    public string FileName { get; set; } = string.Empty;

    // Main header stuff
    public byte VersionMajor { get; set; }
    public byte VersionMinor { get; set; }

    public byte TypeIndex { get; set; }

    /// <summary>
    /// Whether the cake is encrypted.
    /// </summary>
    public bool IsEncrypted { get; set; }

    // Encryption stuff
    public const string ConstantKey = "V9w0ooTmKK'{z!mg6b$E%1,s2)nj2o_";
    public const string ConstantIV = "XC;JQm8";
    public uint CryptoKey { get; set; }
    private ChaCha20 _chaCha20Ctx;

    // Sections
    private List<CakeFileHeaderSection> _sections = [];

    /// <summary>
    /// Lookup table for actual file entries. Should always be sorted by hash for binary search.
    /// </summary>
    private Dictionary<ulong, CakeDirLookupEntry> _dirLookupTable = [];

    /// <summary>
    /// Lookup table for actual directory entries. Should always be sorted by hash for binary search.
    /// </summary>
    private Dictionary<ulong, CakeFileLookupEntry> _fileLookupTable = [];

    /// <summary>
    /// List of all directories and their information.
    /// </summary>
    private List<CakeDirEntry> _dirEntries = [];

    /// <summary>
    /// List of all files and their information.
    /// </summary>
    private List<CakeFileEntry> _fileEntries = [];

    /// <summary>
    /// String/path table.
    /// </summary>
    private Dictionary<uint, string> _strings = [];

    private CakeRegistryFile(string fileName, FileStream fs, ILoggerFactory? loggerFactory = null)
    {
        _fileStream = fs;
        FileName = Path.GetFileName(fileName);

        if (loggerFactory is not null)
            _logger = loggerFactory.CreateLogger(GetType().ToString());
    }

    public static CakeRegistryFile Open(string file, ILoggerFactory? loggerFactory = null)
    {
        var fs = File.OpenRead(file);
        if (fs.Length < 0x5C)
            throw new InvalidDataException("Invalid cake file. Header is too small, corrupted?");

        var cake = new CakeRegistryFile(file, fs, loggerFactory);
        cake.OpenInternal();
        return cake;
    }

    private void OpenInternal()
    {
        BinaryStream bs = new BinaryStream(_fileStream);

        byte[] headerBytes = new byte[0x5C];
        bs.ReadExactly(headerBytes);

        SpanReader hdrReader = new SpanReader(headerBytes, Syroot.BinaryData.Core.Endian.Little);
        uint magic = hdrReader.ReadUInt32();
        if (magic != DirSignature)
            throw new InvalidDataException("Not a valid cake file, signature did not match.");

        ushort version = hdrReader.ReadUInt16();
        uint bitFlags = hdrReader.ReadUInt16();
        VersionMajor = (byte)(version & 0xFF);
        VersionMinor = (byte)(version >> 8);

        _logger?.LogInformation("Cake Version: v{major}.{minor}", VersionMajor, VersionMinor);

        // 8 bits
        byte unk = (byte)(bitFlags & 0b11111111);
        TypeIndex = (byte)((bitFlags >> 8) & 0b111111); // 7 bits - encryption type?
        IsEncrypted = (bitFlags >> 15) == 1; // 1 bit

        CryptoKey = GenerateCryptoXorKey();
        _logger?.LogInformation("Crypto Key: {key:X8}", CryptoKey);

        if (IsEncrypted)
            CryptCRCData(headerBytes.AsSpan(0x08, 0x54));

        ReadSections(bs, hdrReader);
    }

    public void ExtractAll(string outputDir)
    {
        foreach (CakeFileEntry? fileEntry in _fileEntries)
        {
            var name = _strings[fileEntry.StringOffset];
            ExtractEntry(fileEntry, name, outputDir);
        }
    }

    public bool ExtractFile(string file, string outputDir)
    {
        ulong hash = FNV1A64.HashPath(file);
        if (!_fileLookupTable.TryGetValue(hash, out CakeFileLookupEntry? lookupEntry))
            return false;

        CakeFileEntry fileEntry = _fileEntries[(int)lookupEntry.FileEntryIndex];
        ExtractEntry(fileEntry, file, outputDir);
        return true;
    }

    private void ExtractEntry(CakeFileEntry entry, string fileName, string outputDir)
    {
        CakeDirEntry parentDir = _dirEntries[(int)entry.ParentDirIndex];
        string dirName = _strings[parentDir.PathStringOffset];
        string outputPath = Path.Combine(outputDir, dirName, fileName);

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath));

        _logger?.LogInformation("Extracting: {file}", Path.Combine(dirName, fileName));

        if (entry.CompressedSize == 0)
        {
            File.WriteAllBytes(outputPath, []);
        }
        else
        {
            _fileStream.Position = (long)entry.DataOffset;

            uint key = GetKeyForFile(CryptoKey, entry.CompressedSize, entry.DataOffset);

            using var inputBuffer = MemoryOwner<byte>.Allocate((int)entry.CompressedSize);
            _fileStream.ReadExactly(inputBuffer.Span);
            CryptFileData(inputBuffer.Span, entry.CompressedSize, key); // only the first 0x100 bytes are ever encrypted.


            if (entry.ResourceTypeSignature == 0x21584554) // 'TEX!'
            {
                // TODO: Extract texture into dds. For now just extract the tex raw
                // ProcessTexture(entry, inputBuffer.Span, outputPath);

                using FileStream outputStream = File.Create(outputPath);
                outputStream.Write(inputBuffer.Span);
            }
            else
            {
                using FileStream outputStream = File.Create(outputPath);

                if (entry.DecompressedSize != 0)
                {
                    using var outputBuffer = MemoryOwner<byte>.Allocate((int)entry.DecompressedSize);
                    long decoded = Oodle.Decompress(in MemoryMarshal.GetReference(inputBuffer.Span), (int)entry.CompressedSize,
                                                    in MemoryMarshal.GetReference(outputBuffer.Span), entry.DecompressedSize);
                    if (decoded != entry.DecompressedSize)
                        _logger?.LogError("ERROR: Failed to decompress oodle data ({file}), skipping!", Path.Combine(dirName, fileName));
                    else
                        outputStream.Write(outputBuffer.Span);
                }
                else
                {
                    outputStream.Write(inputBuffer.Span);
                }
            }
        }
    }

    private void ProcessTexture(CakeFileEntry fileEntry, Span<byte> data, string outputPath)
    {
        const int TextureResourceHeaderSize = 0x28;

        SpanReader sr = new SpanReader(data);
        ushort unk1 = sr.ReadUInt16(); // 1 byte Version? then unknown byte?
        ushort width = sr.ReadUInt16();
        ushort height = sr.ReadUInt16();
        sr.ReadUInt16();
        ulong unkHash1 = sr.ReadUInt64();
        ulong empty = sr.ReadUInt64();
        uint decompressedSize = sr.ReadUInt32();
        uint unk = sr.ReadUInt32();

        // Not sure which is the pixel format.

        // 4 = BC5/DXT5
        // 6 = BC7
        byte unkByte = sr.ReadByte();

        byte numMips = sr.ReadByte();
        sr.ReadInt16();

        // 4 = BC5/DXT5
        // 6 = BC7
        uint formatMaybe2 = sr.ReadUInt32();

        using FileStream outputStream = File.Create(outputPath);
        using var outputBuffer = MemoryOwner<byte>.Allocate((int)decompressedSize);

        long pixelData = Oodle.Decompress(in MemoryMarshal.GetReference(data.Slice(TextureResourceHeaderSize)), data.Length - TextureResourceHeaderSize,
                                          in MemoryMarshal.GetReference(outputBuffer.Span), decompressedSize);
    }

    // UI/Projects/ShowAssets/superstar_nameplates
    public CakeDirEntry? GetDirEntry(string dir)
    {
        ulong hash = FNV1A64.HashPath(dir);
        if (_dirLookupTable.TryGetValue(hash, out CakeDirLookupEntry? dirLookupEntry))
        {
            return _dirEntries[(int)dirLookupEntry.DirEntryIndex];
        }

        return null;
    }

    public CakeFileEntry? GetFileEntry(string file, out bool isEmpty)
    {
        isEmpty = true;

        ulong hash = FNV1A64.HashPath(file);
        if (_fileLookupTable.TryGetValue(hash, out CakeFileLookupEntry? fileLookupEntry))
        {
            isEmpty = fileLookupEntry.IsEmptyFile;
            return _fileEntries[(int)fileLookupEntry.FileEntryIndex];
        }

        return null;
    }

    #region Private
    private void ReadSections(BinaryStream bs, SpanReader hdrReader)
    {
        _logger?.LogInformation("Reading Sections..");

        uint fileCount = hdrReader.ReadUInt32();
        uint dirCount = hdrReader.ReadUInt32();
        uint chunkCount = hdrReader.ReadUInt32(); // Sum of all number of chunks from each file entry

        _logger?.LogInformation("Num Files: {fileCount}", fileCount);
        _logger?.LogInformation("Num Folders: {folderCount}", dirCount);
        _logger?.LogInformation("Num Chunks: {chunkCount}", chunkCount);

        for (int i = 0; i < 5; i++)
        {
            uint secSize = hdrReader.ReadUInt32();
            uint secCrc = hdrReader.ReadUInt32();
            uint secOffset = hdrReader.ReadUInt32();
            _sections.Add(new CakeFileHeaderSection(secSize, secCrc, secOffset));
        }
        uint pad1 = hdrReader.ReadUInt32();
        uint pad2 = hdrReader.ReadUInt32();
        uint totalTocSize = hdrReader.ReadUInt32(); // aka header (0x5C) + all sections

        if (bs.Length < totalTocSize)
            throw new InvalidDataException($"Stream/file size is smaller than expected toc size. stream: 0x{bs.Length:X} < expected: {totalTocSize:X}");

        ReadDirLookupTable(bs, dirCount);
        ReadFileLookupTable(bs, fileCount);
        ReadFileEntries(bs, fileCount);
        ReadDirEntries(bs, dirCount);
        ReadStringTable(bs);

        Debug.Assert(bs.Position == totalTocSize);

        _logger?.LogInformation("Done reading sections.");
    }

    private void ReadFileLookupTable(BinaryStream bs, uint numFiles)
    {
        bs.Position = _sections[FILE_LOOKUP_TABLE_SECTION_INDEX].Offset;
        byte[] sectionData = new byte[_sections[FILE_LOOKUP_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(sectionData);

        if (IsEncrypted)
        {
            uint crc = CryptCRCData(sectionData);
            if (crc != _sections[FILE_LOOKUP_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("File lookup section checksum did not match. Invalid or corrupted?");
        }

        SpanReader sectionReader = new SpanReader(sectionData);
        for (int i = 0; i < numFiles; i++)
        {
            var fileEntry = new CakeFileLookupEntry();
            fileEntry.Read(ref sectionReader);
            _fileLookupTable.Add(fileEntry.NameHash, fileEntry);
        }
    }

    private void ReadDirEntries(BinaryStream bs, uint dirCount)
    {
        bs.Position = _sections[DIR_INFO_TABLE_SECTION_INDEX].Offset;
        byte[] sectionData = new byte[_sections[DIR_INFO_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(sectionData);

        if (IsEncrypted)
        {
            uint crc = CryptCRCData(sectionData);
            if (crc != _sections[3].Checksum)
                throw new InvalidCastException("Dir entries section checksum did not match. Invalid or corrupted?");
        }

        SpanReader sectionReader = new SpanReader(sectionData);
        for (int i = 0; i < dirCount; i++)
        {
            var dirEntry = new CakeDirEntry();
            dirEntry.Read(ref sectionReader);
            _dirEntries.Add(dirEntry);
        }
    }

    private void ReadDirLookupTable(BinaryStream bs, uint numFolders)
    {
        bs.Position = _sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Offset;
        byte[] sectionData = new byte[_sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(sectionData);

        if (IsEncrypted)
        {
            uint crc = CryptCRCData(sectionData);
            if (crc != _sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("Dir section checksum did not match. Invalid or corrupted?");
        }

        SpanReader srr = new SpanReader(sectionData);
        for (int i = 0; i < numFolders; i++)
        {
            var dirEntry = new CakeDirLookupEntry();
            dirEntry.Read(ref srr);
            _dirLookupTable.Add(dirEntry.NameHash, dirEntry);
        }
    }

    private void ReadFileEntries(BinaryStream bs, uint numFiles)
    {
        bs.Position = _sections[FILE_INFO_TABLE_SECTION_INDEX].Offset;
        byte[] entries = new byte[_sections[FILE_INFO_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(entries);

        if (IsEncrypted)
        {
            uint crc = CryptCRCData(entries);
            if (crc != _sections[FILE_INFO_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("File info section checksum did not match. Invalid or corrupted?");
        }

        SpanReader entriesReader = new SpanReader(entries);
        for (int i = 0; i < numFiles; i++)
        {
            var fileEntry = new CakeFileEntry();
            fileEntry.Read(ref entriesReader);
            _fileEntries.Add(fileEntry);
        }
    }

    private void ReadStringTable(BinaryStream bs)
    {
        // String table section
        bs.Position = _sections[STRING_TABLE_SECTION_INDEX].Offset;
        byte[] stringTableSection = new byte[_sections[STRING_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(stringTableSection);

        if (IsEncrypted)
        {
            uint crc = CryptCRCData(stringTableSection);
            if (crc != _sections[STRING_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("String table checksum did not match. Invalid or corrupted?");
        }

        ReadStringEntries(stringTableSection);
    }

    private uint GenerateCryptoXorKey()
    {
        if (!FileName.StartsWith("bakedfile") && !FileName.StartsWith("rs"))
            throw new InvalidOperationException("File name should start with bakedfile or rs (never rename the cake files!)");

        if (VersionMajor == 9 && VersionMinor == 2)
            return GenerateCryptoKeyV9_2();
        else if (VersionMajor == 9 && VersionMinor == 1)
            return GenerateCryptoKeyV9_1();
        else
            throw new NotSupportedException($"Cake v{VersionMajor}.{VersionMinor} are not yet supported.");
    }

    private void ReadStringEntries(byte[] stringTableSection)
    {
        SpanReader sr = new SpanReader(stringTableSection);
        uint unk = sr.ReadUInt16();

        while (!sr.IsEndOfSpan)
        {
            uint strOffset = (uint)sr.Position;
            string str;
            if (IsEncrypted)
                str = ReadScrambledString(ref sr);
            else
                str = sr.ReadString1();
            _strings.Add(strOffset, str);
        }
    }

    private static string ReadScrambledString(ref SpanReader sr)
    {
        int strOffset = sr.Position;

        byte strLen = sr.ReadByte();
        byte[] bytes = sr.ReadBytes(strLen + 1);
        for (int i = 0; i < strLen; i++)
        {
            int what = (strOffset >> (8 * (i % 4)));
            bytes[i] ^= (byte)(i + what);
        }

        return Encoding.ASCII.GetString(bytes.AsSpan(0, bytes.Length - 1));
    }

    static uint ExtractU8_U32(uint val, int byteIndex)
        => (val >> (8 * byteIndex));

    static ulong ExtractU8_U64(ulong val, int byteIndex)
        => (val >> (8 * byteIndex));

    public static uint GetKeyForFile(uint baseKey, uint size, ulong offset)
    {
        // Signedness matters
        ulong base_ = 0xCBF29CE484222325;
        for (int i = 0; i < 4; i++)
            base_ = 0x100000001B3L * (ulong)((sbyte)ExtractU8_U32(~size, i) ^ (long)base_);

        for (int i = 0; i < 4; i++)
            base_ = 0x100000001B3L * (ulong)((sbyte)ExtractU8_U32(size, i) ^ (long)base_);

        for (int i = 0; i < 4; i++)
            base_ = 0x100000001B3L * (ulong)((sbyte)ExtractU8_U32(~baseKey, i) ^ (long)base_);

        for (int i = 0; i < 4; i++)
            base_ = 0x100000001B3L * (ulong)((sbyte)ExtractU8_U32(baseKey, i) ^ (long)base_);

        for (int i = 0; i < 8; i++)
            base_ = 0x100000001B3L * (ulong)((sbyte)ExtractU8_U64(~offset, i) ^ (long)base_);

        return (uint)((base_ & 0xFFFFFFFF) ^ ~(base_ >> 32));
    }

    static void CryptFileData(Span<byte> data, long fileSize, uint key)
    {
        for (int i = 0; i < Math.Min(fileSize, 0x100); i++)
        {
            byte val = byte.RotateRight(data[i], (i - 1) % 8 ^ 0xD);
            val = byte.RotateLeft((byte)(val ^ (i - 1 + ExtractU8_U32(key, (i + 1) % 4))), (i + 1) % 8);
            data[i] = val;
        }
    }

    /// <summary>
    /// En/Decrypts data and CRC32C it in one go.
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    private uint CryptCRCData(Span<byte> data)
    {
        uint lastkey = CryptoKey;
        uint crc = ~0u;
        while (data.Length >= 8)
        {
            Span<uint> asUints = MemoryMarshal.Cast<byte, uint>(data);
            uint v1 = asUints[0];
            uint v2 = asUints[1];
            asUints[0] ^= lastkey;
            asUints[1] ^= v1;
            lastkey = v2;

            crc = BitOperations.Crc32C(crc, BinaryPrimitives.ReadUInt64LittleEndian(data));
            data = data[8..];
        }

        // NOTE: remaining bytes xor the key. therefore remaining 7 bytes should always be processed separately
        while (data.Length > 0)
        {
            data[0] ^= (byte)lastkey;
            lastkey ^= data[0];

            crc = BitOperations.Crc32C(crc, data[0]);
            data = data[1..];
        }

        return ~crc;
    }

    private static uint ScrambleGenSeed(Span<byte> bytes)
    {
        uint val = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            val = (val << 4) + bytes[i];
            val = (val ^ ((val & 0xF0000000) >> 24)) & 0x0FFFFFFF;
        }
        return val;
    }

    private uint GenerateCryptoKeyV9_1()
    {
        string nameSeed = $"{FileName.ToLower()}{VersionMajor:D3}{VersionMinor:D3}";
        Memory<byte> keyOne = CreateInitialKeyTableFromNameSeed(nameSeed);
        ChaChaTweakKeyTable(keyOne);

        byte[] crcKey = MetroHashUnkCustomV9_1(keyOne.Span, 0x80, BinaryPrimitives.ReadUInt32LittleEndian(keyOne.Span));

        // Final step
        uint val = ~0u;

        byte[] keyOneCopy = keyOne.ToArray();
        Span<uint> keyOneUints = MemoryMarshal.Cast<byte, uint>(keyOneCopy);
        Span<ulong> keyOneUlongs = MemoryMarshal.Cast<byte, ulong>(keyOneCopy);
        for (int i = 0; i < keyOneUlongs.Length; i++)
            val = BitOperations.Crc32C(val, keyOneUlongs[i]);
        val = ~val;

        Span<uint> crcKeyUint = MemoryMarshal.Cast<byte, uint>(crcKey);
        uint lastVal = crcKeyUint[0] ^ crcKeyUint[1] ^ crcKeyUint[2] ^ crcKeyUint[3];
        for (int i = 0; i < 32; i++)
        {
            keyOneUints[i] ^= lastVal;
            lastVal = keyOneUints[i];
        }

        _chaCha20Ctx.ResetCounter();
        _chaCha20Ctx.DecryptBytes(keyOneCopy, 0x40); // lower 0x40 bytes only

        byte[] lastCrcKey = MetroHashUnkCustomV9_1(keyOneCopy, 0x80, val);
        Span<uint> lastCrcKeyUint = MemoryMarshal.Cast<byte, uint>(lastCrcKey);

        uint finalKey = lastCrcKeyUint[0] ^ lastCrcKeyUint[1] ^ lastCrcKeyUint[2] ^ lastCrcKeyUint[3];
        return finalKey;
    }

    private uint GenerateCryptoKeyV9_2()
    {
        // Step 1: Generate seed
        string nameSeed = $"{FileName}-{VersionMajor}-{VersionMinor}".ToUpper();

        // Step 2: Generate hash table from name seed
        Memory<byte> keyOne = CreateInitialKeyTableFromNameSeed(nameSeed);

        // Step 3: Generate a mt seed (lower 32) before hashing hash table
        uint mtSeed1 = ScrambleGenSeed(keyOne.Span);

        // Step 4: Crypt hash table
        ChaChaTweakKeyTable(keyOne);

        // Step 5: Generate a mt seed (upper 32) before hashing hash table
        uint mtSeed2 = ScrambleGenSeed(keyOne.Span);

        // Step 6: SFMT/CRC table
        Span<ulong> keyUlongs = MemoryMarshal.Cast<byte, ulong>(keyOne.Span);

        // NOTE: Higher 32bit is effectively useless. But that's what the game does so
        var sfmtRand = new SFMT(mtSeed2);
        ulong baseVal = ((ulong)mtSeed2 << 32) | mtSeed1;
        for (int i = 0; i < 8; i++)
            baseVal = BitOperations.Crc32C((uint)baseVal, keyUlongs[(int)(sfmtRand.Nextuint() % 16)]);

        // Step 7: SFMT XOR & Metro hash part 1
        ulong metroHashSeed = baseVal ^ sfmtRand.Nextuint();
        ulong[] outMetroHash = new ulong[2];
        MetroHash.Metrohash128crc_2(keyOne.Span, (ulong)keyOne.Length, metroHashSeed, MemoryMarshal.Cast<ulong, byte>(outMetroHash));

        // Step 8: SFMT XOR & Metro hash part 2
        ulong metroHashSeed2 = BitOperations.Crc32C(BitOperations.Crc32C((uint)baseVal, outMetroHash[0]), ~outMetroHash[1]) ^ sfmtRand.Nextuint();
        ulong[] outMetroHash2 = new ulong[2];
        MetroHash.Metrohash128crc_2(keyOne.Span, (ulong)keyOne.Length, metroHashSeed2, MemoryMarshal.Cast<ulong, byte>(outMetroHash2));

        // Step 9: Gen seed from final metrohash data
        uint finalSeed = ScrambleGenSeed(MemoryMarshal.Cast<ulong, byte>(outMetroHash2));

        // Step 10: Gen crc (again), many details here are unused
        uint crc = 0;
        byte mask = 0xFF;
        for (int i = 0; i < 0x80; i++)
        {
            var data = keyOne.Span[i];
            crc = BitOperations.Crc32C(crc, data);

            // Not really used
            int byteIndex = (i + 1) % 4;
            byte piece = (byte)(mask + (byte)(finalSeed >> (8 * byteIndex)));
            byte rotated = byte.RotateRight(data, i + 1);
            keyOne.Span[i] = byte.RotateLeft((byte)(piece ^ rotated), mask ^ 5);

            mask++;
        }

        // Step 11: XOR CRC and SFMT to create final key.
        uint key = crc ^ sfmtRand.Nextuint();
        return key;
    }

    private byte[] MetroHashUnkCustomV9_1(Span<byte> key, uint len, uint seed)
    {
        // Some weird metrohash variant, the constants are unknown.
        Span<ulong> ulongs = MemoryMarshal.Cast<byte, ulong>(key);

        const ulong k0 = 0x63516654;
        const ulong k1 = 0x68576D5A;
        const ulong k2 = 0x482B4D62;
        const ulong k3 = 0x51655468;

        Span<ulong> v = stackalloc ulong[4];
        v[0] = (seed - k0) * k3 + len;
        v[1] = (seed + k1) * k2 + len;
        v[2] = (seed + k0) * k2 + len;
        v[3] = (seed - k1) * k3 + len;

        for (int j = 0; j < 4; j++)
        {
            v[0] ^= BitOperations.Crc32C((uint)v[0], ulongs[0]);
            v[1] ^= BitOperations.Crc32C((uint)v[1], ulongs[1]);
            v[2] ^= BitOperations.Crc32C((uint)v[2], ulongs[2]);
            v[3] ^= BitOperations.Crc32C((uint)v[3], ulongs[3]);
            ulongs = ulongs[4..];
        }

        v[2] ^= (k1 * BitOperations.RotateRight(v[1] + k0 * (v[3] + v[0]), 34));
        v[3] ^= (k0 * BitOperations.RotateRight(v[0] + k1 * (v[1] + v[2]), 37));
        v[0] ^= (k1 * BitOperations.RotateRight(v[3] + k0 * (v[0] + v[2]), 34)); // v22
        v[1] ^= (k0 * BitOperations.RotateRight(v[2] + k1 * (v[3] + v[1]), 37)); // v23

        v[0] += BitOperations.RotateRight(v[1] + k0 * v[0], 11); // v24
        v[1] += BitOperations.RotateRight(v[0] + k1 * v[1], 26); // v25
        v[0] += BitOperations.RotateRight(v[1] + k0 * v[0], 11);
        v[1] += BitOperations.RotateRight(v[0] + k1 * v[1], 26);

        byte[] crcKey = new byte[0x10];
        BinaryPrimitives.WriteUInt64LittleEndian(crcKey.AsSpan(0x00), v[0]);
        BinaryPrimitives.WriteUInt64LittleEndian(crcKey.AsSpan(0x08), v[1]);
        return crcKey;
    }

    private Memory<byte> CreateInitialKeyTableFromNameSeed(string nameSeed)
    {
        byte[] k = new byte[0x100];
        if (VersionMajor == 9 && VersionMinor == 1)
        {
            int seedIndex = 0;
            int incDirection = 1;
            for (int i = 0; i < 0x80; i++)
            {
                k[i] = (byte)(~nameSeed[seedIndex] ^ (i + 0x1C));

                seedIndex += incDirection;
                if (seedIndex == nameSeed.Length - 1 || seedIndex == 0)
                    incDirection = -incDirection; // Increment the other way around
            }
        }
        else
        {
            int i = 0;
            while (i < 0x80)
            {
                for (int j = 0; j < nameSeed.Length; j++)
                {
                    k[i] = (byte)(nameSeed[j] ^ (nameSeed[j] + (i++ ^ 0x1C)));
                }

                for (int j = nameSeed.Length - 2; j > 0; j--)
                {
                    k[i] = (byte)(nameSeed[j] ^ (nameSeed[j] + (i++ ^ 0x1C)));
                }
            }
        }

        return k.AsMemory(0, 0x80);
    }

    private void ChaChaTweakKeyTable(Memory<byte> keyOne)
    {
        byte[] key = new byte[32];
        Encoding.ASCII.GetBytes(ConstantKey, key);

        byte[] iv = new byte[12];
        Encoding.ASCII.GetBytes(ConstantIV, iv.AsSpan(4));

        ChaCha20.sigma = Encoding.ASCII.GetBytes("Ym<q}it&('oU^}t_");
        _chaCha20Ctx = new ChaCha20(key, iv, 0);

        _chaCha20Ctx.DecryptBytes(keyOne.Span, keyOne.Length);
    }
    #endregion

    public void Dispose()
    {
        ((IDisposable)_fileStream).Dispose();
        _chaCha20Ctx?.Dispose();
        GC.SuppressFinalize(this);
    }
}
