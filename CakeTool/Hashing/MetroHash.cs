using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace CakeTool.Hashing;

public class MetroHash
{
    public static void Metrohash128crc_1(Span<byte> key, ulong len, uint seed, Span<byte> outData)
    {
        ulong k0 = 0xC83A91E1;
        ulong k1 = 0x8648DBDB;
        ulong k2 = 0x7BDEC03B;
        ulong k3 = 0x2F5870A5;

        Span<byte> ptr = key;
        Span<byte> end = ptr.Slice((int)len);

        ulong[] v = new ulong[4];
    
        v[0] = ((seed - k0) * k3) + len;
        v[1] = ((seed + k1) * k2) + len;
        
        if (len >= 32)
        {        
            v[2] = ((seed + k0) * k2) + len;
            v[3] = ((seed - k1) * k3) + len;
    
            do
            {
                v[0] ^= BitOperations.Crc32C((uint)v[0], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[1] ^= BitOperations.Crc32C((uint)v[1], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[2] ^= BitOperations.Crc32C((uint)v[2], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[3] ^= BitOperations.Crc32C((uint)v[3], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
            }
            while (ptr.Length >= 32);
    
            v[2] ^= BitOperations.RotateRight(((v[0] + v[3]) * k0) + v[1], 34) * k1;
            v[3] ^= BitOperations.RotateRight(((v[1] + v[2]) * k1) + v[0], 37) * k0;
            v[0] ^= BitOperations.RotateRight(((v[0] + v[2]) * k0) + v[3], 34) * k1;
            v[1] ^= BitOperations.RotateRight(((v[1] + v[3]) * k1) + v[2], 37) * k0;
        }
        
        if (ptr.Length >= 16)
        {
            v[0] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[0] = BitOperations.RotateRight(v[0], 34) * k3;
            v[1] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[1] = BitOperations.RotateRight(v[1], 34) * k3;
            v[0] ^= BitOperations.RotateRight((v[0] * k2) + v[1], 30) * k1;
            v[1] ^= BitOperations.RotateRight((v[1] * k3) + v[0], 30) * k0;
        }
        
        if (ptr.Length >= 8)
        {
            v[0] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[0] = BitOperations.RotateRight(v[0], 36) * k3;
            v[0] ^= BitOperations.RotateRight((v[0] * k2) + v[1], 23) * k1;
        }
        
        // No idea if the implementation is wrong by whoever wrote it first, but crc32 instruction is receiving a 64bit input, while the data is 32
        // same for the rest
        // hence the ulong cast
        if (ptr.Length >= 4)
        {
            v[1] ^= BitOperations.Crc32C((uint)v[0], (ulong)BinaryPrimitives.ReadUInt32LittleEndian(ptr)); ptr = ptr[4..];
            v[1] ^= BitOperations.RotateRight((v[1] * k3) + v[0], 19) * k0;
        }
        
        if (ptr.Length >= 2)
        {
            v[0] ^= BitOperations.Crc32C((uint)v[1], (ulong)BinaryPrimitives.ReadUInt16LittleEndian(ptr)); ptr = ptr[2..];
            v[0] ^= BitOperations.RotateRight((v[0] * k2) + v[1], 13) * k1;
        }
        
        if (ptr.Length >= 1)
        {
            v[1] ^= BitOperations.Crc32C((uint)v[0], (ulong)ptr[0]);
            v[1] ^= BitOperations.RotateRight((v[1] * k3) + v[0], 17) * k0;
        }
        
        v[0] += BitOperations.RotateRight((v[0] * k0) + v[1], 11);
        v[1] += BitOperations.RotateRight((v[1] * k1) + v[0], 26);
        v[0] += BitOperations.RotateRight((v[0] * k0) + v[1], 11);
        v[1] += BitOperations.RotateRight((v[1] * k1) + v[0], 26);

        // memcpy(out, v, 16);
        MemoryMarshal.Cast<ulong, byte>(v.AsSpan(0, 2)).CopyTo(outData);
    }

    public static void Metrohash128crc_2(Span<byte> key, ulong len, ulong seed, Span<byte> outData)
    {
        const ulong k0 = 0xEE783E2F;
        const ulong k1 = 0xAD07C493;
        const ulong k2 = 0x797A90BB;
        const ulong k3 = 0x2E4B2E1B;

        Span<byte> ptr = key;
        Span<byte> end = ptr.Slice((int)len);

        ulong[] v = new ulong[4];

        v[0] = (seed - k0) * k3 + len;
        v[1] = (seed + k1) * k2 + len;

        if (len >= 32)
        {
            v[2] = (seed + k0) * k2 + len;
            v[3] = (seed - k1) * k3 + len;

            do
            {
                v[0] ^= BitOperations.Crc32C((uint)v[0], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[1] ^= BitOperations.Crc32C((uint)v[1], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[2] ^= BitOperations.Crc32C((uint)v[2], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[3] ^= BitOperations.Crc32C((uint)v[3], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
            }
            while (ptr.Length >= 32);

            v[2] ^= BitOperations.RotateRight((v[0] + v[3]) * k0 + v[1], 12) * k1;
            v[3] ^= BitOperations.RotateRight((v[1] + v[2]) * k1 + v[0], 19) * k0;
            v[0] ^= BitOperations.RotateRight((v[0] + v[2]) * k0 + v[3], 12) * k1;
            v[1] ^= BitOperations.RotateRight((v[1] + v[3]) * k1 + v[2], 19) * k0;
        }

        if (ptr.Length >= 16)
        {
            v[0] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[0] = BitOperations.RotateRight(v[0], 41) * k3;
            v[1] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[1] = BitOperations.RotateRight(v[1], 41) * k3;
            v[0] ^= BitOperations.RotateRight(v[0] * k2 + v[1], 10) * k1;
            v[1] ^= BitOperations.RotateRight(v[1] * k3 + v[0], 10) * k0;
        }

        if (ptr.Length >= 8)
        {
            v[0] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[0] = BitOperations.RotateRight(v[0], 34) * k3;
            v[0] ^= BitOperations.RotateRight(v[0] * k2 + v[1], 22) * k1;
        }

        if (ptr.Length >= 4)
        {
            v[1] ^= BitOperations.Crc32C((uint)v[0], BinaryPrimitives.ReadUInt32LittleEndian(ptr)); ptr = ptr[4..];
            v[1] ^= BitOperations.RotateRight(v[1] * k3 + v[0], 14) * k0;
        }

        if (ptr.Length >= 2)
        {
            v[0] ^= BitOperations.Crc32C((uint)v[1], BinaryPrimitives.ReadUInt16LittleEndian(ptr)); ptr = ptr[2..];
            v[0] ^= BitOperations.RotateRight(v[0] * k2 + v[1], 15) * k1;
        }

        if (ptr.Length >= 1)
        {
            v[1] ^= BitOperations.Crc32C((uint)v[0], ptr[0]);
            v[1] ^= BitOperations.RotateRight(v[1] * k3 + v[0], 18) * k0;
        }

        v[0] += BitOperations.RotateRight(v[0] * k0 + v[1], 15);
        v[1] += BitOperations.RotateRight(v[1] * k1 + v[0], 27);
        v[0] += BitOperations.RotateRight(v[0] * k0 + v[1], 15);
        v[1] += BitOperations.RotateRight(v[1] * k1 + v[0], 27);

        // memcpy(out, v, 16);
        MemoryMarshal.Cast<ulong, byte>(v.AsSpan(0, 2)).CopyTo(outData);
    }

    // This one has different constants, it is based on crc_1 variant
    public static void MetroHashUnkCustomV9_1(Span<byte> key, uint len, uint seed, Span<byte> outHash)
    {
        // Some weird metrohash variant, the constants are unknown.
        Span<ulong> ulongs = MemoryMarshal.Cast<byte, ulong>(key);

        const ulong k0 = 0x63516654;
        const ulong k1 = 0x68576D5A;
        const ulong k2 = 0x482B4D62;
        const ulong k3 = 0x51655468;

        Span<byte> ptr = key;
        Span<byte> end = ptr.Slice((int)len);

        ulong[] v = new ulong[4];

        v[0] = ((seed - k0) * k3) + len;
        v[1] = ((seed + k1) * k2) + len;

        if (len >= 32)
        {
            v[2] = ((seed + k0) * k2) + len;
            v[3] = ((seed - k1) * k3) + len;

            do
            {
                v[0] ^= BitOperations.Crc32C((uint)v[0], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[1] ^= BitOperations.Crc32C((uint)v[1], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[2] ^= BitOperations.Crc32C((uint)v[2], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
                v[3] ^= BitOperations.Crc32C((uint)v[3], BinaryPrimitives.ReadUInt64LittleEndian(ptr)); ptr = ptr[8..];
            }
            while (ptr.Length >= 32);

            v[2] ^= BitOperations.RotateRight(((v[0] + v[3]) * k0) + v[1], 34) * k1;
            v[3] ^= BitOperations.RotateRight(((v[1] + v[2]) * k1) + v[0], 37) * k0;
            v[0] ^= BitOperations.RotateRight(((v[0] + v[2]) * k0) + v[3], 34) * k1;
            v[1] ^= BitOperations.RotateRight(((v[1] + v[3]) * k1) + v[2], 37) * k0;
        }

        if (ptr.Length >= 16)
        {
            v[0] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[0] = BitOperations.RotateRight(v[0], 34) * k3;
            v[1] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[1] = BitOperations.RotateRight(v[1], 34) * k3;
            v[0] ^= BitOperations.RotateRight((v[0] * k2) + v[1], 30) * k1;
            v[1] ^= BitOperations.RotateRight((v[1] * k3) + v[0], 30) * k0;
        }

        if (ptr.Length >= 8)
        {
            v[0] += BinaryPrimitives.ReadUInt64LittleEndian(ptr) * k2; ptr = ptr[8..]; v[0] = BitOperations.RotateRight(v[0], 36) * k3;
            v[0] ^= BitOperations.RotateRight((v[0] * k2) + v[1], 23) * k1;
        }

        // No idea if the implementation is wrong by whoever wrote it first, but crc32 instruction is receiving a 64bit input, while the data is 32
        // same for the rest
        // hence the ulong cast
        if (ptr.Length >= 4)
        {
            v[1] ^= BitOperations.Crc32C((uint)v[0], (ulong)BinaryPrimitives.ReadUInt32LittleEndian(ptr)); ptr = ptr[4..];
            v[1] ^= BitOperations.RotateRight((v[1] * k3) + v[0], 19) * k0;
        }

        if (ptr.Length >= 2)
        {
            v[0] ^= BitOperations.Crc32C((uint)v[1], (ulong)BinaryPrimitives.ReadUInt16LittleEndian(ptr)); ptr = ptr[2..];
            v[0] ^= BitOperations.RotateRight((v[0] * k2) + v[1], 13) * k1;
        }

        if (ptr.Length >= 1)
        {
            v[1] ^= BitOperations.Crc32C((uint)v[0], (ulong)ptr[0]);
            v[1] ^= BitOperations.RotateRight((v[1] * k3) + v[0], 17) * k0;
        }

        v[0] += BitOperations.RotateRight((v[0] * k0) + v[1], 11);
        v[1] += BitOperations.RotateRight((v[1] * k1) + v[0], 26);
        v[0] += BitOperations.RotateRight((v[0] * k0) + v[1], 11);
        v[1] += BitOperations.RotateRight((v[1] * k1) + v[0], 26);

        // memcpy(out, v, 16);
        MemoryMarshal.Cast<ulong, byte>(v.AsSpan(0, 2)).CopyTo(outHash);
    }
}
