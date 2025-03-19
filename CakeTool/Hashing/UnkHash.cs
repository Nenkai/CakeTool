using System;
using System.Collections.Generic;
using System.IO.Hashing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace CakeTool.Hashing;

public class UnkHash
{
    // Is this murmur?
    // TODO: Find out what hash algorithm this actually is.

    public static void Hash(Span<byte> input, Span<byte> output, ulong key)
    {
        Vector128<ulong> h1 = Vector128.Create([key, 0x9E3779B97F4A7C15]);
        Vector128<ulong> h2 = Vector128<ulong>.Zero;

        Vector128<uint> consts = Vector128.Create<uint>([0x114253D5, 0, 0x2745937F, 0]); // 0x4cf5ad432745937f

        Span<Vector128<ulong>> blocks = MemoryMarshal.Cast<byte, Vector128<ulong>>(input);
        for (int i = 0; i < blocks.Length; i++)
        {
            h1 ^= blocks[i];
            h1 ^= h2;

            h2 = Multiply(h1, consts); // PMULUDQ
            h1 = h2;

            h1 = ShiftRightLogical(h1, 33); // PSRLQ
        }

        var hashVec = h1 + h2;
        var outputLongs = MemoryMarshal.Cast<byte, ulong>(output);
        outputLongs[0] = hashVec[0];
        outputLongs[1] = hashVec[1];
    }

    public static Vector128<ulong> Multiply(Vector128<ulong> a, Vector128<uint> b) // Equivalent to PMULUDQ
    {
        ulong aLo = a[0] & 0xFFFFFFFF;
        ulong aHi = (a[1] >> 64) & 0xFFFFFFFF;
        ulong bLo = b[0] & 0xFFFFFFFF;
        ulong bHi = b[2] & 0xFFFFFFFF;

        ulong lo = aLo * bLo;
        ulong hi = aHi * bHi;

        return Vector128.Create([lo, hi]);
    }

    private static Vector128<ulong> ShiftRightLogical(Vector128<ulong> vector, int shiftAmount)
    {
        ulong lo = vector.GetElement(0) >> shiftAmount;
        ulong hi = vector.GetElement(1) >> shiftAmount;
        return Vector128.Create([lo, hi]);
    }
}