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

using Syroot.BinaryData;

namespace CakeTool;

/// <summary>
/// For .mpb symbol/map files
/// </summary>
public class MapBinary
{
    public record Symbol(long Offset, string Name);
    public List<Symbol> Symbols { get; set; } = [];

    public static MapBinary Open(string path)
    {
        var bin = new MapBinary();

        using var fs = File.OpenRead(path);
        using var bs = new BinaryStream(fs);

        uint signature = bs.ReadUInt32();
        uint version = bs.ReadUInt32();
        uint numSymbols = bs.ReadUInt32();
        uint stringTableSize = bs.ReadUInt32();

        List<(uint VirtOffset, uint NameOffset)> locations = [];

        for (int i = 0; i < numSymbols; i++)
        {
            uint virtOffset = bs.ReadUInt32();
            uint nameOffset = bs.ReadUInt32();

            if (version >= 4)
            {
                ushort nameLength = bs.ReadUInt16();
            }

            locations.Add((virtOffset, nameOffset));
        }

        long strTableOffset = bs.Position;
        for (int i = 0; i < numSymbols; i++)
        {
            bs.Position = strTableOffset + locations[i].NameOffset;
            string str = bs.ReadString(StringCoding.ZeroTerminated);
            bin.Symbols.Add(new Symbol(0x140001000 + locations[i].VirtOffset, str));
        }

        return bin;
    }

    public void WriteList(string path)
    {
        using var sw = new StreamWriter(path);
        foreach (var symbol in Symbols)
        {
            sw.WriteLine($"0x{symbol.Offset:X16}  {symbol.Name}");
        }
    }
}
