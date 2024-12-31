using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool.Hashing;

public class FNV1A64
{
    /// <summary>
    /// Hashes a path (note: case insensitive).
    /// </summary>
    /// <param name="path"></param>
    /// <returns></returns>
    public static ulong HashPath(string path)
    {
        const ulong fnv64Offset = 14695981039346656037;
        const ulong fnv64Prime = 0x100000001b3;
        ulong hash = fnv64Offset;

        for (var i = 0; i < path.Length; i++)
        {
            hash = hash ^ char.ToLower(path[i]);
            hash *= fnv64Prime;
        }

        return hash;
    }
}
