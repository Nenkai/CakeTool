using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CakeTool.Hashing;

using Syroot.BinaryData;

namespace CakeTool.GameFiles.Textures;

public class TextureDatabase
{
    public uint Version { get; set; }
    public SortedDictionary<ulong, TextureMeta> TextureInfos = [];

    /// <summary>
    /// 'T_DB'
    /// </summary>
    public const uint MAGIC = 0x42445F54;

    public void Read(Stream stream)
    {
        var bs = new BinaryStream(stream, ByteConverter.Little);
        if (bs.ReadUInt32() != MAGIC) // T_DB
            throw new InvalidDataException("Could not read texture database - file is not a texture database.");

        Version = bs.ReadUInt32();
        uint numTextureInfos = bs.ReadUInt32();
        uint structSize = bs.ReadUInt32();

        long basePos = bs.BaseStream.Position;
        for (int i = 0; i < numTextureInfos; i++)
        {
            bs.Position = basePos + i * structSize;
            
            ulong hash = bs.ReadUInt64();

            var textureInfo = new TextureMeta();
            textureInfo.Read(bs);
            TextureInfos.Add(hash, textureInfo);
        }
    }

    public static TextureDatabase Open(string fileName)
    {
        using var fs = File.OpenRead(fileName);

        var tdb = new TextureDatabase();
        tdb.Read(fs);
        return tdb;
    }

    public bool TryGetTexture(string name, out TextureMeta textureInfo)
    {
        ulong hash = FNV1A64.FNV64StringI(name.Replace('\\', '/'));
        return TextureInfos.TryGetValue(hash, out textureInfo!);
    }
}