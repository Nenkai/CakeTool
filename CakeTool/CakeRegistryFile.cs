using Syroot.BinaryData;
using Syroot.BinaryData.Memory;

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

using CakeTool.Crypto;
using CakeTool.Hashing;

namespace CakeTool;

public class CakeRegistryFile
{
    public const int DIR_ENTRIES_SECTION_INDEX = 0;
    public const int FILE_ENTRIES_SECTION_INDEX = 2;
    public const int STRING_TABLE_SECTION_INDEX = 4;

    public string FileName { get; set; }

    // Main header stuff
    public byte VersionMajor { get; set; }
    public byte VersionMinor { get; set; }

    // Encryption stuff
    public const string ConstantKey = "V9w0ooTmKK'{z!mg6b$E%1,s2)nj2o_";
    public const string ConstantIV = "XC;JQm8";
    public uint CryptoKey { get; set; }
    private ChaCha20 _chaCha20Ctx;

    // Sections
    private List<CakeFileHeaderSection> _sections = [];

    public List<CakeDirEntry> _dirEntries = [];
    public List<CakeFileEntry> _fileEntries = [];
    private List<string> _strings = [];

    public void Open(string file)
    {
        using BinaryStream bs = new BinaryStream(File.OpenRead(file));
        FileName = Path.GetFileName(file);

        if (bs.Length < 0x5C)
            throw new InvalidDataException("Invalid cake file. Header is too small, corrupted?");

        byte[] headerBytes = new byte[0x5C];
        bs.ReadExactly(headerBytes);

        SpanReader hdrReader = new SpanReader(headerBytes, Syroot.BinaryData.Core.Endian.Little);
        uint magic = hdrReader.ReadUInt32();
        ushort version = hdrReader.ReadUInt16();
        uint flags = hdrReader.ReadUInt16();
        VersionMajor = (byte)(version & 0xFF);
        VersionMinor = (byte)(version >> 8);

        CryptoKey = GenerateCryptoXorKey();
        DecryptData(headerBytes.AsSpan(0x08, 0x54));

        ReadSections(bs, hdrReader);
    }

    private void ReadSections(BinaryStream bs, SpanReader hdrReader)
    {
        uint numFiles = hdrReader.ReadUInt32();
        uint numFolders = hdrReader.ReadUInt32();
        uint count3 = hdrReader.ReadUInt32();

        for (int i = 0; i < 5; i++)
        {
            uint secSize = hdrReader.ReadUInt32();
            uint secCrc = hdrReader.ReadUInt32();
            uint secOffset = hdrReader.ReadUInt32();
            _sections.Add(new CakeFileHeaderSection(secSize, secCrc, secOffset));
        }
        uint empty = hdrReader.ReadUInt32();

        ReadDirEntries(bs, numFolders);
        ReadEntries2(bs, numFiles);
        ReadFileEntries(bs, numFiles);
        ReadEntries3(bs);
        ReadStringTable(bs);
    }

    private void ReadEntries2(BinaryStream bs, uint numFiles)
    {
        bs.Position = _sections[1].Offset;
        byte[] dat2 = new byte[_sections[1].Size];
        bs.ReadExactly(dat2);
        DecryptData(dat2);
        SpanReader dat2Reader = new SpanReader(dat2);
        for (int i = 0; i < numFiles; i++)
        {
            ulong hash = dat2Reader.ReadUInt64();
            uint what = dat2Reader.ReadUInt32();
        }
    }

    private void ReadEntries3(BinaryStream bs)
    {
        bs.Position = _sections[3].Offset;
        byte[] data4 = new byte[_sections[3].Size];
        bs.ReadExactly(data4);
        DecryptData(data4);
    }

    private void ReadDirEntries(BinaryStream bs, uint numFolders)
    {
        bs.Position = _sections[DIR_ENTRIES_SECTION_INDEX].Offset;
        byte[] dat = new byte[_sections[DIR_ENTRIES_SECTION_INDEX].Size];
        bs.ReadExactly(dat);
        DecryptData(dat);
        SpanReader srr = new SpanReader(dat);
        for (int i = 0; i < numFolders; i++)
        {
            var dirEntry = new CakeDirEntry();
            dirEntry.Read(ref srr);
            _dirEntries.Add(dirEntry);
        }
    }

    private void ReadFileEntries(BinaryStream bs, uint numFiles)
    {
        bs.Position = _sections[FILE_ENTRIES_SECTION_INDEX].Offset;
        byte[] entries = new byte[_sections[FILE_ENTRIES_SECTION_INDEX].Size];
        bs.ReadExactly(entries);
        DecryptData(entries);
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
        DecryptData(stringTableSection);
        ReadStringEntries(stringTableSection);
    }

    private uint GenerateCryptoXorKey()
    {
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
        uint unk = sr.ReadUInt32();

        while (!sr.IsEndOfSpan)
        {
            string str = ReadScrambledString(ref sr);
            _strings.Add(str);
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

    private void DecryptData(Span<byte> data)
    {
        uint lastkey = CryptoKey;

        while (data.Length >= 4)
        {
            uint temp = BinaryPrimitives.ReadUInt32LittleEndian(data);
            BinaryPrimitives.WriteUInt32LittleEndian(data, temp ^ lastkey);
            lastkey = temp;

            data = data[4..];
        }

        while (data.Length > 0)
        {
            byte temp = data[0];
            data[0] = (byte)(temp ^ (byte)lastkey);
            lastkey = temp;

            data = data[1..];
        }
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
        Span<uint> uints = MemoryMarshal.Cast<byte, uint>(key);
        Span<ulong> ulongs = MemoryMarshal.Cast<byte, ulong>(key);

        const ulong k0 = 0x63516654;
        const ulong k1 = 0x68576D5A;
        const ulong k2 = 0x482B4D62;
        const ulong k3 = 0x51655468;

        ulong[] v = new ulong[4];
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

    public static uint fnv1a(string str)
    {
        uint result = 0x811c9dc5, prime = 16777619;
        foreach (var c in str)
        {
            result ^= (byte)c;
            result *= prime;
        }

        return result;

    }
}
