using CakeTool.Hashing;

using Microsoft.Extensions.Logging;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

public class CakeFileBuilder
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;

    private List<CakeFileEntry> _files = [];
    private List<CakeDirInfo> _dirs = [];
    private SortedDictionary<ulong, CakeEntryLookup> _dirLookup = [];
    private SortedDictionary<ulong, CakeEntryLookup> _fileLookup = [];
    private byte[] _stringTable;

    private List<CakeFileHeaderSection> _sections = [];

    public uint TotalChunkCount { get; set; } = 0;

    public byte VersionMajor { get; set; } = 9;
    public byte VersionMinor { get; set; } = 3;

    public bool EncryptHeader { get; set; } = false;

    private string OriginalDirName { get; set; } = string.Empty;

    private BinaryStream _cakeStream;

    public CakeFileBuilder(ILoggerFactory? loggerFactory = null)
    {
        if (loggerFactory is not null)
            _logger = loggerFactory.CreateLogger(GetType().ToString());
    }

    public void RegisterFiles(string mainDir)
    {
        _logger?.LogInformation("Indexing '{mainDir}' for a new cake...", mainDir);
        BuildFileTree(mainDir, mainDir);
    }

    private CakeDirInfo BuildFileTree(string mainDir, string currentDir)
    {
        var dirEntry = new CakeDirInfo();
        string parentRelative = Path.GetRelativePath(mainDir, currentDir);
        if (parentRelative == ".")
            parentRelative = "";
        else
            dirEntry.Hash = FNV1A64.FNV64StringI(parentRelative.Replace('\\', '/'));

        dirEntry.Path = parentRelative;

        _dirs.Add(dirEntry);
        dirEntry.DirIndex = (uint)(_dirs.Count - 1);

        foreach (var fileSysPath in Directory.EnumerateFileSystemEntries(currentDir, "*"))
        {
            string relativeSubEntryPath = Path.GetRelativePath(mainDir, fileSysPath);

            var info = new FileInfo(fileSysPath);
            if (info.Attributes.HasFlag(FileAttributes.Directory))
            {
                CakeDirInfo child = BuildFileTree(mainDir, fileSysPath);

                dirEntry.SubFolderIndices.Add(child.DirIndex);
            }
            else
            {
                var fileEntry = new CakeFileEntry()
                {
                    CompressedSize = (uint)info.Length,
                    CRCChecksum = 0,
                    ParentDirIndex = dirEntry.DirIndex,
                    FileName = Path.GetFileName(relativeSubEntryPath),
                    RelativePath = relativeSubEntryPath,
                    LocalPath = fileSysPath,
                    NumChunks = 1,
                    ChunkEndOffsets = [(uint)info.Length],
                };

                if (ResourceIds.ExtensionToResourceId.TryGetValue(fileSysPath, out var resourceId))
                {
                    fileEntry.ResourceTypeSignature = resourceId;
                    fileEntry.UnkFlags3 = 0x400;
                }

                _files.Add(fileEntry);
                fileEntry.FileEntryIndex = (uint)(_files.Count - 1);
                dirEntry.FileIndices.Add(fileEntry.FileEntryIndex);

                _logger?.LogInformation("Registered {gamePath} ({sizeString})...", fileEntry.RelativePath, Utils.BytesToString(fileEntry.ExpandedSize));
            }
        }

        dirEntry.SubFolderCount = (ushort)dirEntry.SubFolderIndices.Count;
        dirEntry.FileCount = (ushort)dirEntry.FileIndices.Count;

        return dirEntry;
    }

    private void FinalizeTree()
    {
        foreach (var dirInfo in _dirs)
        {
            string normalized = dirInfo.Path.Replace('\\', '/');
            ulong hash = FNV1A64.FNV64StringI(normalized);
            _dirLookup.Add(hash, new CakeEntryLookup()
            {
                NameHash = !string.IsNullOrEmpty(dirInfo.Path) ? hash : 0,
                EntryIndex = dirInfo.DirIndex
            });
        }

        foreach (var fileInfo in _files)
        {
            string normalized = fileInfo.RelativePath.Replace('\\', '/');
            ulong hash = FNV1A64.FNV64StringI(normalized);
            _fileLookup.Add(hash, new CakeEntryLookup()
            {
                NameHash = hash,
                EntryIndex = fileInfo.FileEntryIndex,
                IsEmptyFile = fileInfo.ExpandedSize == 0,
            });
        }

        _stringTable = SerializeStringTable();
    }

    private byte[] SerializeStringTable()
    {
        using var ms = new MemoryStream();
        using var bs = new BinaryStream(ms);

        if (IsAtLeastVersion(9))
            WriteString(bs, OriginalDirName);

        foreach (CakeDirInfo dirInfo in _dirs)
        {
            dirInfo.PathStringOffset = (uint)bs.Position;
            WriteString(bs, dirInfo.Path);
        }

        foreach (CakeFileEntry fileInfo in _files)
        {
            fileInfo.StringOffset = (uint)bs.Position;
            WriteString(bs, fileInfo.FileName);
        }

        return ms.ToArray();
    }

    public void Write(string path)
    {
        _logger?.LogInformation("Baking cake started.");

        FinalizeTree();

        // FilesysDirHeader
        using var fs = File.Create(path);
        _cakeStream = new BinaryStream(fs);
        _cakeStream.Write("FDIR"u8);
        _cakeStream.WriteByte(VersionMajor);
        _cakeStream.WriteByte(VersionMinor);

        if (IsAtLeastVersion(8, 7))
            _cakeStream.WriteUInt16(((ushort)CakeRegistryType.Unk1 << 8));
        else
            _cakeStream.WriteUInt16((ushort)CakeRegistryType.Unk1);

        uint tocSize = GetFullHeaderSize();
        _cakeStream.Position = Utils.AlignValue(tocSize, 0x04);

        // Skip header & section toc for now.
        _logger?.LogInformation("Writing files.");
        WriteFiles();

        // Write sections.
        _cakeStream.Position = GetHeaderAndSectionInfoSize();
        {
            WriteSection((BinaryStream bs) =>
            {
                foreach (var dirLookupEntry in _dirLookup)
                    dirLookupEntry.Value.Write(bs, VersionMajor, VersionMinor);
            });

            WriteSection((BinaryStream bs) =>
            {
                foreach (var fileLookupEntry in _fileLookup)
                    fileLookupEntry.Value.Write(bs, VersionMajor, VersionMinor);
            });

            WriteSection((BinaryStream bs) =>
            {
                foreach (var fileEntry in _files)
                    fileEntry.Write(bs, VersionMajor, VersionMinor);
            });

            WriteSection((BinaryStream bs) =>
            {
                foreach (var dirEntry in _dirs)
                    dirEntry.Write(bs, VersionMajor, VersionMinor);
            });

            WriteSection((BinaryStream bs) => bs.WriteBytes(_stringTable));
            Debug.Assert(_cakeStream.Position == Utils.AlignValue(tocSize, 0x04));
        }

        _cakeStream.Position = 0x08;

        var sectionInfoBytes = new byte[GetHeaderAndSectionInfoSize() - 0x08];
        SpanWriter sectionInfoWriter = new SpanWriter(sectionInfoBytes);
        sectionInfoWriter.WriteUInt32((uint)_files.Count);
        sectionInfoWriter.WriteUInt32((uint)_dirs.Count);
        if (IsAtLeastVersion(9))
            sectionInfoWriter.WriteUInt32(TotalChunkCount);

        // Write section infos.
        for (int i = 0; i < _sections.Count; i++)
        {
            sectionInfoWriter.WriteUInt32(_sections[i].Size);
            sectionInfoWriter.WriteUInt32(_sections[i].Checksum);
            sectionInfoWriter.WriteUInt32(_sections[i].Offset);
        }
        sectionInfoWriter.WriteUInt32(0);
        sectionInfoWriter.WriteUInt32(0);
        sectionInfoWriter.WriteUInt32(tocSize);

        if (EncryptHeader)
        {
            throw new NotImplementedException();
        }

        _cakeStream.Write(sectionInfoBytes);

        _logger?.LogInformation("Finished. Cake size: {sizeString}", Utils.BytesToString((ulong)_cakeStream.Length));
    }

    private void WriteSection(Action<BinaryStream> writeCallback)
    {
        uint sectionOffset = (uint)_cakeStream.Position;

        using var ms = new MemoryStream();
        using var bs = new BinaryStream(ms);

        writeCallback(bs);
        uint sectionSize = (uint)bs.Length;

        bs.Align(0x04, grow: true);

        uint sectionCrc = 1;
        byte[] bytes = ms.ToArray();

        if (EncryptHeader)
        {
            throw new NotImplementedException();

            sectionCrc = CRC32C.Hash(bytes);
        }

        _cakeStream.Write(bytes);
        _cakeStream.Align(0x04, grow: true);

        _sections.Add(new CakeFileHeaderSection(sectionSize, sectionCrc, sectionOffset));
    }

    private void WriteFiles()
    {
        for (int i = 0; i < _files.Count; i++)
        {
            CakeFileEntry? file = _files[i];
            _logger?.LogInformation("[{index}/{numFiles}] Writing {file}...", i + 1, _files.Count, file.RelativePath);
            WriteFile(file, file.LocalPath);
        }
    }

    private void WriteFile(CakeFileEntry fileEntry, string path)
    {
        fileEntry.DataOffset = (ulong)_cakeStream.Position;

        // TODO: compression, encryption (?).
        using var fs = File.OpenRead(path);
        fs.CopyTo(_cakeStream);
        _cakeStream.Align(0x04, grow: true);
    }

    private uint GetFullHeaderSize()
    {
        uint tocSize = GetHeaderAndSectionInfoSize();
        foreach (var dirLookupEntry in _dirLookup)
            tocSize += dirLookupEntry.Value.GetSize(VersionMajor, VersionMinor);
        tocSize = Utils.AlignValue(tocSize, 0x04);

        foreach (var fileLookupEntry in _fileLookup)
            tocSize += fileLookupEntry.Value.GetSize(VersionMajor, VersionMinor);
        tocSize = Utils.AlignValue(tocSize, 0x04);

        foreach (var fileEntry in _files)
            tocSize += fileEntry.GetSize(VersionMajor, VersionMinor);
        tocSize = Utils.AlignValue(tocSize, 0x04);

        foreach (var dirEntry in _dirs)
            tocSize += dirEntry.GetSize(VersionMajor, VersionMinor);
        tocSize = Utils.AlignValue(tocSize, 0x04);

        tocSize += (uint)_stringTable.Length;
        // alignment for string table to data does not count towards size.

        return tocSize;
    }

    public uint GetHeaderAndSectionInfoSize()
    {
        if (IsAtLeastVersion(9))
            return 0x5Cu;
        else
            return 0x58u;
    }

    private void WriteString(BinaryStream bs, string str)
    {
        if (IsAtLeastVersion(8))
        {
            if (EncryptHeader)
                throw new NotImplementedException();
            else
            {
                bs.WriteString(str, StringCoding.ByteCharCount);
                bs.WriteByte(0);
            }
        }
        else
        {
            if (EncryptHeader)
                throw new NotImplementedException();
            else
                bs.WriteString(str, StringCoding.ZeroTerminated);
        }
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
}
