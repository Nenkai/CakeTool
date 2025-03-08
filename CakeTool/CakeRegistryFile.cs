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

using Microsoft.Extensions.Logging;

using CommunityToolkit.HighPerformance;
using CommunityToolkit.HighPerformance.Buffers;

using CakeTool.Crypto;
using CakeTool.Hashing;
using CakeTool.Compression;
using CakeTool.PRNG;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;
namespace CakeTool;

/// <summary>
/// Cake registry file (disposable object).
/// </summary>
public class CakeRegistryFile : IDisposable
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;

    public const uint FILESYS_DIR_SIGNATURE = 0x52494446; // 'FDIR'
    public const int FILESYS_DIR_HEADER_SIZE = 0x08;

    public const int DIR_LOOKUP_TABLE_SECTION_INDEX = 0;
    public const int FILE_LOOKUP_TABLE_SECTION_INDEX = 1;
    public const int FILE_INFO_TABLE_SECTION_INDEX = 2;
    public const int DIR_INFO_TABLE_SECTION_INDEX = 3;
    public const int STRING_TABLE_SECTION_INDEX = 4;

    public string FileName { get; set; } = string.Empty;

    // Main header stuff
    // v6.7/6.8 = 20
    // v8.1 = 21
    // v8.2/v8.3 = 22
    // v8.7 = 23
    // v9.1/v9.2 = 24
    public byte VersionMajor { get; set; } 
    public byte VersionMinor { get; set; }

    public CakeRegistryType TypeOrParam { get; set; }

    /// <summary>
    /// Whether the cake is encrypted, at least the header and toc.
    /// </summary>
    public bool IsHeaderEncrypted { get; set; }

    /// <summary>
    /// For V6 through 8.3, otherwise look into <see cref="CakeFileEntry"/> for later versions
    /// </summary>
    public bool IsFileDataEncrypted { get; set; }

    public uint MainCryptoKey { get; set; }

    // Sections
    private List<CakeFileHeaderSection> _sections = [];

    /// <summary>
    /// Lookup table for actual file entries. Should always be sorted by hash for binary search.
    /// </summary>
    private Dictionary<ulong, CakeEntryLookup> _dirLookupTable = [];

    /// <summary>
    /// Lookup table for actual directory entries. Should always be sorted by hash for binary search.
    /// </summary>
    private Dictionary<ulong, CakeEntryLookup> _fileLookupTable = [];

    /// <summary>
    /// List of all directories and their information.
    /// </summary>
    private List<CakeDirInfo> _dirEntries = [];

    /// <summary>
    /// List of all files and their information.
    /// </summary>
    private List<CakeFileEntry> _fileEntries = [];

    /// <summary>
    /// String/path table.
    /// </summary>
    private Dictionary<uint, string> _strings = [];

    private FileStream _fileStream;

    // This is needed for certain cakes that do not have encryption despite their headers marked as such.
    // Game basically correctly checks the header and goes into a function for handling encryption, but they're stubbed in those builds.
    private bool _forceNoEncryption;

    private ChaCha20 _chaCha20Ctx;

    // Encryption stuff
    public const string ConstantKeyV9 = "V9w0ooTmKK'{z!mg6b$E%1,s2)nj2o_";
    public const string ConstantIVV9 = "XC;JQm8";

    public const string ConstantKeyV8 = "r-v4WVyWOprRr7Qw9kN0myq5KCXGaaf";
    public const string ConstantIVV8 = "xTKmfw_";

    private CakeRegistryFile(string fileName, FileStream fs, ILoggerFactory? loggerFactory = null, bool forceNoEncryption = false)
    {
        _fileStream = fs;
        FileName = Path.GetFileName(fileName);
        _forceNoEncryption = forceNoEncryption;

        if (loggerFactory is not null)
            _logger = loggerFactory.CreateLogger(GetType().ToString());
    }

    public static CakeRegistryFile Open(string file, ILoggerFactory? loggerFactory = null, bool forceNoEncryption = false)
    {
        var fs = File.OpenRead(file);
        if (fs.Length < 0x58)
            throw new InvalidDataException("Invalid cake file. Header is too small, corrupted?");

        var cake = new CakeRegistryFile(file, fs, loggerFactory, forceNoEncryption);
        cake.OpenInternal();
        return cake;
    }

    private bool IsVersion(byte versionMajor, byte versionMinor)
    {
        return VersionMajor == versionMajor && VersionMinor == versionMinor;
    }

    private bool IsAtLeastVersion(byte versionMajor, byte versionMinor = 0)
    {
        if (VersionMajor < versionMajor)
            return false;

        return VersionMajor > versionMajor || (VersionMajor == versionMajor && VersionMinor >= versionMinor);
    }

    public uint GetHeaderAndSectionInfoSize()
    {
        if (IsAtLeastVersion(9))
            return 0x5Cu;
        else
            return 0x58u;
    }

    // UI/Projects/ShowAssets/superstar_nameplates
    public CakeDirInfo? GetDirEntry(string dir)
    {
        ulong hash = FNV1A64.FNV64StringI(dir);
        if (_dirLookupTable.TryGetValue(hash, out CakeEntryLookup? dirLookupEntry))
        {
            return _dirEntries[(int)dirLookupEntry.EntryIndex];
        }

        return null;
    }

    public CakeFileEntry? GetFileEntry(string file, out bool isEmpty)
    {
        isEmpty = true;

        ulong hash = FNV1A64.FNV64StringI(file);
        if (_fileLookupTable.TryGetValue(hash, out CakeEntryLookup? fileLookupEntry))
        {
            isEmpty = fileLookupEntry.IsEmptyFile;
            return _fileEntries[(int)fileLookupEntry.EntryIndex];
        }

        return null;
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
        ulong hash = FNV1A64.FNV64StringI(file);
        if (!_fileLookupTable.TryGetValue(hash, out CakeEntryLookup? lookupEntry))
            return false;

        CakeFileEntry fileEntry = _fileEntries[(int)lookupEntry.EntryIndex];
        ExtractEntry(fileEntry, file, outputDir);
        return true;
    }


    private void OpenInternal()
    {
        BinaryStream bs = new BinaryStream(_fileStream);
        if (bs.Length < 0x58)
            throw new InvalidDataException("Invalid cake file. file is too small to contain main header, corrupted?");

        Span<byte> headerBytes = stackalloc byte[0x08]; 
        bs.ReadExactly(headerBytes);
        FilesysDirHeader header = MemoryMarshal.Cast<byte, FilesysDirHeader>(headerBytes)[0];

        if (header.Signature != FILESYS_DIR_SIGNATURE)
            throw new InvalidDataException("Not a valid cake file, signature did not match 'FDIR'.");

        VersionMajor = (byte)(header.Version & 0xFF);
        VersionMinor = (byte)(header.Version >> 8);

        _logger?.LogInformation("Cake Version: v{major}.{minor}", VersionMajor, VersionMinor);

        if (VersionMajor == 6 || (VersionMajor == 8 && VersionMinor < 7)) // v6, v8.1 thru 6? maybe?
        {
            TypeOrParam = (CakeRegistryType)(header.Flags & 0b11_1111_1111_1111); // Is it 8 and 6 bits split?

            // is bit 14 header/toc encryption, and bit 15 file encryption maybe?
            // needs further testing tbh.
            IsHeaderEncrypted = ((header.Flags >> 14) & 1) == 1;
            IsFileDataEncrypted = (header.Flags >> 15) == 1;
        }
        else if (IsAtLeastVersion(8, 7)) // >=v8.7 - encryption flag on files moved to entry infos.
        {
            byte unk = (byte)(header.Flags & 0b11111111);
            TypeOrParam = (CakeRegistryType)((header.Flags >> 8) & 0b1111111);
            IsHeaderEncrypted = (header.Flags >> 15) == 1; // 1 bit
        }

        _logger?.LogInformation("Type: {type} ({typeNumber})", TypeOrParam, (int)TypeOrParam);

        MainCryptoKey = GenerateCryptoXorKey();
        _logger?.LogInformation("Crypto Key: {key:X8}", MainCryptoKey);

        uint headerPlusSectionTocSize = GetHeaderAndSectionInfoSize();
        if (bs.Length < headerPlusSectionTocSize)
            throw new InvalidDataException("Invalid cake file. file is too small to contain main header + section, corrupted?");

        byte[] sectionHeaderBytes = new byte[headerPlusSectionTocSize];
        bs.Position = 0;
        bs.ReadExactly(sectionHeaderBytes);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            Span<byte> sectionInfoBytes = sectionHeaderBytes.AsSpan(FILESYS_DIR_HEADER_SIZE,
                (int)(headerPlusSectionTocSize - FILESYS_DIR_HEADER_SIZE));

            CryptHeaderData(sectionInfoBytes, MainCryptoKey);
        }

        SpanReader sectionReader = new SpanReader(sectionHeaderBytes, Syroot.BinaryData.Core.Endian.Little);
        sectionReader.Position = FILESYS_DIR_HEADER_SIZE;
        ReadSections(bs, sectionReader);

        if (TypeOrParam == CakeRegistryType.External)
        {
            _logger?.LogInformation("External Entries ({count}):", _fileEntries.Count);
            foreach (CakeFileEntry? fileEntry in _fileEntries)
            {
                var name = _strings[fileEntry.StringOffset];

                CakeDirInfo parentDir = _dirEntries[(int)fileEntry.ParentDirIndex];
                string dirName = _strings[parentDir.PathStringOffset];

                _logger?.LogInformation("- {file}", Path.Combine(dirName, name));
            }
        }
    }

    private void ExtractEntry(CakeFileEntry entry, string fileName, string outputDir)
    {
        string gamePath;
        if (IsAtLeastVersion(8))
        {
            CakeDirInfo parentDir = _dirEntries[(int)entry.ParentDirIndex];
            string dirName = _strings[parentDir.PathStringOffset];
            gamePath = Path.Combine(dirName, fileName);
        }
        else
            gamePath = fileName; // Old versions has the full path.

        string outputPath = Path.Combine(outputDir, gamePath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        _logger?.LogInformation("Extracting: {file}", gamePath);

        if (entry.CompressedSize == 0)
        {
            File.WriteAllBytes(outputPath, []);
        }
        else
        {
            _fileStream.Position = (long)entry.DataOffset;

            using var inputBuffer = MemoryOwner<byte>.Allocate((int)entry.CompressedSize);
            _fileStream.ReadExactly(inputBuffer.Span);

            if ((VersionMajor == 6 && IsFileDataEncrypted) ||
                ((IsVersion(8, 2) || IsVersion(8, 3)) && IsFileDataEncrypted) ||
                (IsVersion(8, 7) && entry.RawBitFlags != 0) ||
                (VersionMajor >= 9 && (entry.UnkBits2 & 1) != 0))
            {
                uint key = GetFileManglingKey(entry);
                CryptFileDataAndCheck(inputBuffer.Span, entry, key);
            }

            if (entry.CompressedSize >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(inputBuffer.Span) == 0x21534552) // 'RES!' aka resource
            {
                ExtractResource(fileName, gamePath, outputPath, inputBuffer);
            }
            else if (entry.ResourceTypeSignature == 0x21584554) // 'TEX!'
            {
                // TODO: Extract texture into dds. For now just extract the tex raw
                // ProcessTexture(entry, inputBuffer.Span, outputPath);

                using FileStream outputStream = File.Create(outputPath);
                outputStream.Write(inputBuffer.Span);
            }
            else
            {
                using FileStream outputStream = File.Create(outputPath);

                if (entry.ExpandedSize != entry.CompressedSize)
                {
                    using var outputBuffer = MemoryOwner<byte>.Allocate((int)entry.ExpandedSize);
                    long decoded = Oodle.Decompress(in MemoryMarshal.GetReference(inputBuffer.Span), (int)entry.CompressedSize,
                                                    in MemoryMarshal.GetReference(outputBuffer.Span), entry.ExpandedSize);
                    if (decoded != entry.ExpandedSize)
                        _logger?.LogError("ERROR: Failed to decompress oodle data ({file}), skipping!", gamePath);
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


    // Mostly used in Version 6/8.
    private void ExtractResource(string fileName, string dirName, string outputPath, MemoryOwner<byte> inputBuffer)
    {
        const int ResourceHeaderSize = 0x18;

        SpanReader resReader = new SpanReader(inputBuffer.Span);
        uint resourceSignature = resReader.ReadUInt32();
        uint versionMaybe = resReader.ReadUInt32(); // version? this doesn't appear to be read
        uint resourceType = resReader.ReadUInt32();
        uint compressedSize = resReader.ReadUInt32();
        uint compressionType = resReader.ReadUInt32();
        uint decompressedSize = resReader.ReadUInt32();

        using FileStream outputStream = File.Create(outputPath);
        switch (compressionType)
        {
            case 0:
                {
                    ReadOnlySpan<byte> resourceData = inputBuffer.Span.Slice(ResourceHeaderSize, (int)compressedSize);
                    outputStream.Write(resourceData);
                }
                break;

            case 0x4C444F4F: // 'OODL'
            case 0x214B524B: // 'KRK!'
                {
                    ReadOnlySpan<byte> resourceData = inputBuffer.Span.Slice(ResourceHeaderSize, (int)compressedSize);

                    using var outputBuffer = MemoryOwner<byte>.Allocate((int)decompressedSize);
                    long decoded = Oodle.Decompress(in MemoryMarshal.GetReference(resourceData), (int)compressedSize,
                                                    in MemoryMarshal.GetReference(outputBuffer.Span), decompressedSize);
                    if (decoded != decompressedSize)
                        _logger?.LogError("ERROR: Failed to decompress oodle data ({file}), skipping!", Path.Combine(dirName, fileName));
                    else
                        outputStream.Write(outputBuffer.Span);
                }
                break;

            default:
                throw new NotSupportedException($"Resource compression type {compressionType:X8} not supported for file {Path.Combine(dirName, fileName)}");
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

    #region Private
    private void ReadSections(BinaryStream bs, SpanReader hdrReader)
    {
        _logger?.LogInformation("Reading Sections..");

        uint fileCount = hdrReader.ReadUInt32();
        uint dirCount = hdrReader.ReadUInt32();

        _logger?.LogInformation("Num Files: {fileCount}", fileCount);
        _logger?.LogInformation("Num Folders: {folderCount}", dirCount);

        if (IsAtLeastVersion(9))
        {
            uint chunkCount = hdrReader.ReadUInt32(); // Sum of all number of chunks from each file entry
            _logger?.LogInformation("Num Chunks: {chunkCount}", chunkCount);
        }

        for (int i = 0; i < 5; i++)
        {
            uint secSize = hdrReader.ReadUInt32();
            uint secCrc = hdrReader.ReadUInt32(); // always 1 in 2K21 where there's no encryption
            uint secOffset = hdrReader.ReadUInt32();
            _sections.Add(new CakeFileHeaderSection(secSize, secCrc, secOffset));
        }

        // These two seem to be always empty.
        uint pad1 = hdrReader.ReadUInt32();
        uint pad2 = hdrReader.ReadUInt32();
        uint totalTocSize = hdrReader.ReadUInt32(); // aka header (0x5C) + all sections

        if (bs.Length < totalTocSize)
            throw new InvalidDataException($"Stream/file size is smaller than expected header+toc size. stream: 0x{bs.Length:X} < expected: {totalTocSize:X}");

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

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            uint crc = CryptHeaderData(sectionData, MainCryptoKey);
            if (crc != _sections[FILE_LOOKUP_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("File lookup section checksum did not match. Invalid or corrupted?");
        }

        SpanReader sectionReader = new SpanReader(sectionData);
        for (int i = 0; i < numFiles; i++)
        {
            var fileEntry = new CakeEntryLookup();
            fileEntry.Read(ref sectionReader);
            _fileLookupTable.Add(fileEntry.NameHash, fileEntry);
        }
    }

    private void ReadDirEntries(BinaryStream bs, uint dirCount)
    {
        bs.Position = _sections[DIR_INFO_TABLE_SECTION_INDEX].Offset;
        byte[] sectionData = new byte[_sections[DIR_INFO_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(sectionData);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            uint crc = CryptHeaderData(sectionData, MainCryptoKey);
            if (crc != _sections[DIR_INFO_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("Dir entries section checksum did not match. Invalid or corrupted?");
        }

        SpanReader sectionReader = new SpanReader(sectionData);
        for (int i = 0; i < dirCount; i++)
        {
            var dirEntry = new CakeDirInfo();
            dirEntry.Read(ref sectionReader);
            _dirEntries.Add(dirEntry);
        }
    }

    private void ReadDirLookupTable(BinaryStream bs, uint numFolders)
    {
        bs.Position = _sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Offset;
        byte[] sectionData = new byte[_sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(sectionData);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            uint crc = CryptHeaderData(sectionData, MainCryptoKey);
            if (crc != _sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("Dir section checksum did not match. Invalid or corrupted?");
        }

        SpanReader srr = new SpanReader(sectionData);
        for (int i = 0; i < numFolders; i++)
        {
            var dirEntry = new CakeEntryLookup();
            dirEntry.Read(ref srr);
            _dirLookupTable.Add(dirEntry.NameHash, dirEntry);
        }
    }

    private void ReadFileEntries(BinaryStream bs, uint numFiles)
    {
        bs.Position = _sections[FILE_INFO_TABLE_SECTION_INDEX].Offset;
        byte[] entries = new byte[_sections[FILE_INFO_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(entries);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            uint crc = CryptHeaderData(entries, MainCryptoKey);
            if (crc != _sections[FILE_INFO_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("File info section checksum did not match. Invalid or corrupted?");
        }

        SpanReader entriesReader = new SpanReader(entries);
        for (int i = 0; i < numFiles; i++)
        {
            var fileEntry = new CakeFileEntry();
            fileEntry.Read(ref entriesReader, VersionMajor, VersionMinor);
            _fileEntries.Add(fileEntry);
        }
    }

    private void ReadStringTable(BinaryStream bs)
    {
        // String table section
        bs.Position = _sections[STRING_TABLE_SECTION_INDEX].Offset;
        byte[] stringTableSection = new byte[_sections[STRING_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(stringTableSection);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            uint crc = CryptHeaderData(stringTableSection, MainCryptoKey);
            if (crc != _sections[STRING_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("String table checksum did not match. Invalid or corrupted?");
        }

        ReadStringEntries(stringTableSection);
    }

    private void ReadStringEntries(byte[] stringTableSection)
    {
        SpanReader sr = new SpanReader(stringTableSection);

        
        if (IsAtLeastVersion(9))
        {
            string mainDirMaybe = ReadScrambledString(ref sr);
            _logger?.LogInformation("Original or Base Dir (?): {mainDir}", !string.IsNullOrEmpty(mainDirMaybe) ? mainDirMaybe : "<none>");
        }

        while (!sr.IsEndOfSpan)
        {
            uint strOffset = (uint)sr.Position;
            string str;
            if (IsAtLeastVersion(8))
            {
                // This has a length, but is still null terminated
                if (!_forceNoEncryption && IsHeaderEncrypted)
                    str = ReadScrambledString(ref sr);
                else
                    str = sr.ReadString1();
            }
            else
                str = sr.ReadString0();

            _strings.Add(strOffset, str);
        }
    }

    /***************************************
     * 
     * Welcome to the crypto zone!
     * 
     ***************************************/

    private uint GenerateCryptoXorKey()
    {
        if (IsVersion(6, 7))
            return GenerateCryptoKeyV6_7();
        if (IsVersion(6, 8) || IsVersion(8, 1))
            return GenerateCryptoKeyV6_8();
        else if (IsVersion(8, 2))
            return GenerateCryptoKeyV8_2();
        else if (IsVersion(8, 3))
            return GenerateCryptoKeyV8_3();
        else if (IsVersion(8, 7))
            return GenerateCryptoKeyV8_7();
        else if (IsVersion(9, 1))
            return GenerateCryptoKeyV9_1();
        else if (IsVersion(9, 2))
            return GenerateCryptoKeyV9_2();
        else if (IsVersion(9, 3))
            return GenerateCryptoKeyV9_3();
        throw new NotSupportedException($"Cake v{VersionMajor}.{VersionMinor} are not yet supported.");
    }

    private string ReadScrambledString(ref SpanReader sr)
    {
        uint key;
        if (IsVersion(8, 2))
            key = (uint)BinaryPrimitives.ReverseEndianness(sr.Position);
        else
            key = (uint)sr.Position;

        byte strLen = sr.ReadByte();
        byte[] bytes = sr.ReadBytes(strLen + 1);

        if (IsVersion(8, 3))
        {
            RotateCrypt(bytes, key);
        }
        else // v6, >=8.7
        {
            ScrambleBytes(bytes, key);
        }

        return Encoding.ASCII.GetString(bytes.AsSpan(0, bytes.Length - 1));
    }

    // SysCore::BakedDataFile::GetFileManglingKey
    private uint GetFileManglingKey(CakeFileEntry entry)
    {
        if (IsVersion(6, 7))
        {
            return ~(entry.CompressedSize ^ MainCryptoKey);
        }
        else if (IsVersion(6, 8))
        {
            return entry.CompressedSize ^ MainCryptoKey;
        }
        else if (IsVersion(8, 2))
        {
            return BinaryPrimitives.ReverseEndianness(entry.CRCChecksum);
        }
        else if (IsVersion(8, 3))
        {
            Span<byte> toHash = stackalloc byte[3 * sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x00..], MainCryptoKey);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x08..], entry.CompressedSize);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x10..], entry.DataOffset);

            ulong val = 0xCBF29CE484222325;
            for (int i = 0; i < 0x18; i++)
                val = 0x100000001B3L * (ulong)((sbyte)toHash[i] ^ (long)val);

            return (uint)((val & 0xFFFFFFFF) ^ (val >> 32));
        }
        else if (IsVersion(8, 7) || IsVersion(9, 1))
        {
            Span<byte> toHash = stackalloc byte[4 + 4 + 8 + 4 + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x00..], MainCryptoKey);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x04..], ~MainCryptoKey);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x08..], entry.DataOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x10..], entry.CompressedSize);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x14..], ~entry.CompressedSize);

            ulong val = 0xCBF29CE484222325;
            for (int i = 0; i < 0x18; i++)
                val = 0x100000001B3L * (ulong)((sbyte)toHash[i] ^ (long)val);

            return (uint)((val & 0xFFFFFFFF) ^ (val >> 32));
        }
        else if (IsVersion(9, 2))
        {
            // Order was changed a bit.
            Span<byte> toHash = stackalloc byte[4 + 4 + 4 + 4 + 8];
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x00..], ~entry.CompressedSize);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x04..], entry.CompressedSize);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x08..], ~MainCryptoKey);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x0C..], MainCryptoKey);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x10..], ~entry.DataOffset);

            ulong val = 0xCBF29CE484222325;
            for (int i = 0; i < 0x18; i++)
                val = 0x100000001B3L * (ulong)((sbyte)toHash[i] ^ (long)val);

            return (uint)((val & 0xFFFFFFFF) ^ ~(val >> 32)); // We also flip bits of the higher 32.
        }
        else if (IsVersion(9, 3))
        {
            Span<byte> toHash = stackalloc byte[4 + 4 + 8 + 4 + 4 + 4 + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x00..], MainCryptoKey);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x04..], ~entry.CompressedSize);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x08..], ~(entry.DataOffset ^ MainCryptoKey));
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x10..], entry.CompressedSize);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x14..], ~MainCryptoKey);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x18..], BitOperations.Crc32C(0xFFFFFFFF, (uint)~(entry.DataOffset ^ MainCryptoKey)));
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x1C..], BitOperations.Crc32C(~MainCryptoKey, entry.CompressedSize));

            ulong fnv1a = 0xCBF29CE484222325;
            for (int i = 0; i < toHash.Length; i++)
                fnv1a = 0x100000001B3L * (ulong)((sbyte)toHash[i] ^ (long)fnv1a);

            uint final = ScrambleGenSeed(BitConverter.GetBytes(fnv1a));
            return ~final;
        }

        throw new NotSupportedException();
    }

    private void CryptFileDataAndCheck(Span<byte> data, CakeFileEntry fileEntry, uint key)
    {
        if (VersionMajor == 6)
        {
            uint crc = XORCRCData(data, key);
            if (crc != fileEntry.CRCChecksum)
                throw new Exception("V6 File decryption checksum failed.");
        }
        else if (IsVersion(8, 2))
        {
            ScrambleBytes(data, key);
            if (CRC32C.Hash(data) != fileEntry.CRCChecksum)
                throw new Exception("V8.2 File decryption checksum failed.");

        }
        else if (IsVersion(8, 3))
        {
            for (int i = 0; i < data.Length; i++)
            {
                byte val = byte.RotateRight(data[i], (i - 1) % 8 ^ 0xD);
                val = byte.RotateLeft((byte)(val ^ (i - 1 + Utils.ExtractU8_U32(key, (i + 1) % 4))), (i + 1) % 8);
                data[i] = val;
            }

            if (CRC32C.Hash(data) != fileEntry.CRCChecksum)
                throw new Exception("V8.3 File decryption checksum failed.");
        }
        else if (IsAtLeastVersion(8, 7))
        {
            // only the first 0x100 bytes are ever encrypted.
            for (int i = 0; i < Math.Min(fileEntry.CompressedSize, 0x100); i++)
            {
                byte val = byte.RotateRight(data[i], (i - 1) % 8 ^ 0xD);
                val = byte.RotateLeft((byte)(val ^ (i - 1 + Utils.ExtractU8_U32(key, (i + 1) % 4))), (i + 1) % 8);
                data[i] = val;
            }
        }
    }

    private uint CryptHeaderData(Span<byte> data, uint key)
    {
        if (VersionMajor == 6) // 6.x
        {
            return XORCRCData(data, key);
        }
        else if (IsVersion(8, 2)) // 8.2
        {
            byte[] bytes = BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(key));
            for (int i = 0; i < data.Length; i++)
                data[i] ^= (byte)((byte)i + bytes[i % 4]);
            return CRC32C.Hash(data);
        }
        else if (IsVersion(8, 3)) // 8.3
        {
            RotateCrypt(data, key);
            return CRC32C.Hash(data);
        }
        else if (IsAtLeastVersion(8, 7)) // >= 8.7
        {
            return XORCRCData(data, key);
        }
        else
            throw new NotImplementedException();
    }

    private static void RotateCrypt(Span<byte> bytes, uint key)
    {
        byte[] keyBytes = BitConverter.GetBytes(key);
        for (int i = 0; i < bytes.Length; i++)
        {
            byte rotated = byte.RotateRight(bytes[i], (i - 1) ^ 5);
            bytes[i] = byte.RotateLeft((byte)(rotated ^ (i + keyBytes[((byte)i + 1) % 4] - 1)), i + 1);
        }
    }

    static void ScrambleBytes(Span<byte> data, uint key)
    {
        for (int i = 0; i < data.Length; i++)
        {
            int byteOffset = (int)Utils.ExtractU8_U32(key, i);
            data[i] ^= (byte)(i + byteOffset);
        }
    }

    /// <summary>
    /// En/Decrypts data and CRC32C it in one go.
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    private uint XORCRCData(Span<byte> data, uint key)
    {
        uint lastkey = key;
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

    private uint GenerateCryptoKeyV6_7()
    {
        ulong hash = FNV1A64.FNV64StringI(FileName);
        return (uint)((hash & 0xFFFFFFFF) ^ (hash >> 32));
    }

    // SysCore::BuildKey63FromName
    // SysCore::GenerateEncryptionKey
    private uint GenerateCryptoKeyV6_8()
    {
        Memory<byte> keyOne = CreateInitialKeyTableFromNameSeed(FileName, 0x40);
        Span<byte> outHash = stackalloc byte[0x10];
        MetroHash.Metrohash128crc_1(keyOne.Span.Slice(0, 0x3F), 0x3F, 0, outHash);

        Span<uint> hashInts = MemoryMarshal.Cast<byte, uint>(outHash);
        uint key = hashInts[0] ^ hashInts[1] ^ hashInts[2] ^ hashInts[3];
        return key;
    }

    private uint GenerateCryptoKeyV8_2()
    {
        string nameSeed = $"{FileName.ToLower()}{VersionMajor:D2}{VersionMinor:D2}";
        Memory<byte> table = CreateInitialKeyTableFromNameSeed(nameSeed, 0x40);
        Chacha20Crypt(table.Span);

        Span<byte> metroHash = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span.Slice(0, 0x3F), 0x3F, 0, metroHash);

        Span<uint> hashInts = MemoryMarshal.Cast<byte, uint>(metroHash);
        uint key = hashInts[0] ^ hashInts[1] ^ hashInts[2] ^ hashInts[3];
        return key;
    }

    private uint GenerateCryptoKeyV8_3()
    {
        string nameSeed = $"{FileName.ToLower()}{VersionMajor:D2}{VersionMinor:D2}";
        Memory<byte> table = CreateInitialKeyTableFromNameSeed(nameSeed, 0x40);
        Chacha20Crypt(table.Span.Slice(0, 0x3F));

        // Alter table by putting a metrohash in it
        Span<byte> metroHash = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span.Slice(0, 0x3F), 0x3F, 0, metroHash);

        Span<uint> tableInts = MemoryMarshal.Cast<byte, uint>(table.Span);
        Span<uint> hashInts = MemoryMarshal.Cast<byte, uint>(metroHash);
        uint seed = hashInts[0] ^ hashInts[1] ^ hashInts[2] ^ hashInts[3];
        for (int i = 0; i < 14; i++)
        {
            tableInts[i] ^= seed;
            seed = tableInts[i];
        }

        seed = table.Span[52];
        for (int i = 56; i < 63; i++)
        {
            table.Span[i] ^= (byte)seed;
            seed = table.Span[i];
        }

        Span<byte> metroHash2 = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span.Slice(0, 0x3F), 0x3F, 0, metroHash2);

        Span<uint> hashInts2 = MemoryMarshal.Cast<byte, uint>(metroHash2);
        uint key = hashInts2[0] ^ hashInts2[1] ^ hashInts2[2] ^ hashInts2[3];

        return key;
    }

    private uint GenerateCryptoKeyV8_7()
    {
        string nameSeed = $"{FileName.ToLower()}{VersionMajor:D2}{VersionMinor:D2}";
        Memory<byte> table = CreateInitialKeyTableFromNameSeed(nameSeed, 0x80);
        Chacha20Crypt(table.Span);

        Span<byte> metroHash = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span, 0x80, BinaryPrimitives.ReadUInt32LittleEndian(table.Span), metroHash);

        uint crcSeed = ~0u;

        byte[] keyOneCopy = table.ToArray();
        Span<uint> keyOneUints = MemoryMarshal.Cast<byte, uint>(keyOneCopy);
        Span<ulong> keyOneUlongs = MemoryMarshal.Cast<byte, ulong>(keyOneCopy);
        for (int i = 0; i < keyOneUlongs.Length; i++)
            crcSeed = BitOperations.Crc32C(crcSeed, keyOneUlongs[i]);
        crcSeed = ~crcSeed;

        Span<uint> metroHashInts = MemoryMarshal.Cast<byte, uint>(metroHash);
        uint seed = metroHashInts[0] ^ metroHashInts[1] ^ metroHashInts[2] ^ metroHashInts[3];
        for (int i = 0; i < 32; i++)
        {
            keyOneUints[i] ^= seed;
            seed = keyOneUints[i];
        }

        _chaCha20Ctx.ResetCounter();
        _chaCha20Ctx.DecryptBytes(keyOneCopy, 0x40); // lower 0x40 bytes only

        Span<byte> metroHash2 = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(keyOneCopy, 0x80, crcSeed, metroHash2);
        Span<uint> metroHash2Ints = MemoryMarshal.Cast<byte, uint>(metroHash2);

        uint key = metroHash2Ints[0] ^ metroHash2Ints[1] ^ metroHash2Ints[2] ^ metroHash2Ints[3];
        return key;
    }

    private uint GenerateCryptoKeyV9_1()
    {
        // Same as 8.7, but we use D3 this time
        string nameSeed = $"{FileName.ToLower()}{VersionMajor:D3}{VersionMinor:D3}";
        Memory<byte> table = CreateInitialKeyTableFromNameSeed(nameSeed, 0x80);
        Chacha20Crypt(table.Span);

        Span<byte> metroHash = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span, 0x80, BinaryPrimitives.ReadUInt32LittleEndian(table.Span), metroHash);

        byte[] keyOneCopy = table.ToArray();
        Span<uint> keyOneUints = MemoryMarshal.Cast<byte, uint>(keyOneCopy);
        Span<ulong> keyOneUlongs = MemoryMarshal.Cast<byte, ulong>(keyOneCopy);

        uint crcSeed = ~0u;
        for (int i = 0; i < keyOneUlongs.Length; i++)
            crcSeed = BitOperations.Crc32C(crcSeed, keyOneUlongs[i]);
        crcSeed = ~crcSeed;

        Span<uint> metroHashInts = MemoryMarshal.Cast<byte, uint>(metroHash);
        uint seed = metroHashInts[0] ^ metroHashInts[1] ^ metroHashInts[2] ^ metroHashInts[3];
        for (int i = 0; i < 32; i++)
        {
            keyOneUints[i] ^= seed;
            seed = keyOneUints[i];
        }

        Chacha20Crypt(keyOneCopy.AsSpan(0, 0x40)); // lower 0x40 bytes only

        Span<byte> metroHash2 = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(keyOneCopy, 0x80, crcSeed, metroHash2);
        Span<uint> metroHash2Ints = MemoryMarshal.Cast<byte, uint>(metroHash2);

        uint key = metroHash2Ints[0] ^ metroHash2Ints[1] ^ metroHash2Ints[2] ^ metroHash2Ints[3];
        return key;
    }

    private uint GenerateCryptoKeyV9_2()
    {
        // Step 1: Generate seed
        string nameSeed = $"{FileName}-{VersionMajor}-{VersionMinor}".ToUpper();

        // Step 2: Generate hash table from name seed
        Memory<byte> keyOne = CreateInitialKeyTableFromNameSeed(nameSeed, 0x80);

        // Step 3: Generate a mt seed (lower 32) before hashing hash table
        uint mtSeed1 = ScrambleGenSeed(keyOne.Span);

        // Step 4: Crypt hash table
        Chacha20Crypt(keyOne.Span);

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
            byte piece = (byte)(mask + (byte)Utils.ExtractU8_U32(finalSeed, byteIndex));
            byte rotated = byte.RotateRight(data, i + 1);
            keyOne.Span[i] = byte.RotateLeft((byte)(piece ^ rotated), mask ^ 5);

            mask++;
        }

        // Step 11: XOR CRC and SFMT to create final key.
        uint key = crc ^ sfmtRand.Nextuint();
        return key;
    }

    private uint GenerateCryptoKeyV9_3()
    {
        // Step 1: Generate seed
        string nameSeed = $"{FileName}-{VersionMajor}-{VersionMinor}".ToUpper();

        // TODO.
        Dictionary<string, uint> headerKeys = new()
        {
            ["bakedfile00"] = 0x2A158AB8,
            ["bakedfile01"] = 0x2A158AB8,
            ["bakedfile02"] = 0x976D8958,
            ["bakedfile03"] = 0x976D8958, // Incase
            ["bakedfile50"] = 0xAE0B193A,
            ["bakedfile51"] = 0xAE0B193A,
            ["bakedfile52"] = 0x25ED8EBC,
            ["bakedfile53"] = 0x25ED8EBC, // Incase
            ["bakedfile56"] = 0x3B340725,
            ["bakedfile57"] = 0x3B340725,
            ["bakedfile60"] = 0x9BF4B101,
            ["bakedfile61"] = 0x9BF4B101,
            ["bakedfile62"] = 0xAD471170,
            ["bakedfile63"] = 0xAD471170, // Incase
            ["rs"] = 0xEBB165D9,
        };

        if (!headerKeys.TryGetValue(Path.GetFileNameWithoutExtension(FileName.ToLower()), out uint key))
            throw new NotSupportedException($"Could not find header key for cake file '{FileName}'.");

        return key;
    }

    private Memory<byte> CreateInitialKeyTableFromNameSeed(string nameSeed, int length)
    {
        byte[] k = new byte[length];
        if (VersionMajor == 6)
        {
            // Repeat string till we have 64 bytes
            // "hello" = "hellohellohello..."
            int j = 0;
            for (int i = 0; i < 0x3F + 1; i++)
            {
                if (j == nameSeed.Length)
                    j = 0;

                k[i] = (byte)nameSeed[j++];
            }
            k[0x3F] = 0; // Null termination, not needed, but that's what happens
        }
        else if (IsVersion(8, 2) || IsVersion(8, 3))
        {
            // same, but this time go in reverse everytime we reach the start or end of the string
            // hello = "helloollehhello..."

            int seedIndex = 0;
            int incDirection = 1;
            for (int i = 0; i < length; i++)
            {
                k[i] = (byte)nameSeed[seedIndex];

                seedIndex += incDirection;
                if (seedIndex == nameSeed.Length - 1 || seedIndex == 0)
                    incDirection = -incDirection; // Increment the other way around
            }
            k[length - 1] = 0;

        }
        else if (IsVersion(8, 7))
        {
            int i = 0;
            while (i < length)
            {
                for (int j = 0; j < nameSeed.Length && i < length; j++)
                    k[i++] = (byte)(nameSeed[j] ^ 0x32);

                for (int j = nameSeed.Length - 2; j > 0 && i < length; j--)
                    k[i++] = (byte)(nameSeed[j] ^ 0x32);
            }
        }
        else if (IsVersion(9, 1))
        {
            // same, but flip bits
            int seedIndex = 0;
            int incDirection = 1;
            for (int i = 0; i < length; i++)
            {
                k[i] = (byte)(~nameSeed[seedIndex] ^ (i + 0x1C));

                seedIndex += incDirection;
                if (seedIndex == nameSeed.Length - 1 || seedIndex == 0)
                    incDirection = -incDirection; // Increment the other way around
            }
        }
        else if (IsVersion(9, 2))
        {
            int i = 0;
            while (i < length)
            {
                for (int j = 0; j < nameSeed.Length && i < length; j++)
                    k[i] = (byte)(nameSeed[j] ^ (nameSeed[j] + (i++ ^ 0x1C)));

                for (int j = nameSeed.Length - 2; j > 0 && i < length; j--)
                    k[i] = (byte)(nameSeed[j] ^ (nameSeed[j] + (i++ ^ 0x1C)));
            }
        }

        return k.AsMemory(0, length);
    }

    private void Chacha20Crypt(Span<byte> keyOne)
    {
        if (_chaCha20Ctx is null)
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[12];

            if (VersionMajor >= 9)
            {
                Encoding.ASCII.GetBytes(ConstantKeyV9, key);
                Encoding.ASCII.GetBytes(ConstantIVV9, iv.AsSpan(4));
                ChaCha20.sigma = Encoding.ASCII.GetBytes("Ym<q}it&('oU^}t_"); // yeah that was also changed for some reason
            }
            else
            {
                Encoding.ASCII.GetBytes(ConstantKeyV8, key);
                Encoding.ASCII.GetBytes(ConstantIVV8, iv.AsSpan(4));
            }

            _chaCha20Ctx = new ChaCha20(key, iv, 0);
        }
        else
        {
            _chaCha20Ctx.ResetCounter();
        }

        _chaCha20Ctx.DecryptBytes(keyOne, keyOne.Length);

    }
    #endregion

    public void Dispose()
    {
        ((IDisposable)_fileStream).Dispose();
        _chaCha20Ctx?.Dispose();
        GC.SuppressFinalize(this);
    }
}

public enum CakeRegistryType : byte
{
    Unk1 = 1,
    Unk2 = 2,
    Unk3 = 3,
    
    /// <summary>
    /// rs.cak
    /// </summary>
    RSPatch = 4,

    /// <summary>
    /// For tiny packs, refering to files outside the cake
    /// </summary>
    External = 5,
}
