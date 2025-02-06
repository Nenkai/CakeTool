using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.Compression;
using Syroot.BinaryData;
using System.Diagnostics;
using System.Data;
using System.Xml.Linq;

namespace CakeTool.GameFiles;

public class AnimProjectBin
{
    public List<(ulong, object)> Args = []; // Or constants?
    public List<EventDef> EventDefs = [];

    public void Read(Stream stream)
    {
        BinaryStream binaryFileStream = new BinaryStream(stream, ByteConverter.Little);
        uint version = AnimUtils.ReadHeader(binaryFileStream, "ver_"u8); // 6?
        uint sizeCompressed = AnimUtils.ReadHeader(binaryFileStream, "sizc"u8);
        uint sizeUncompressed = AnimUtils.ReadHeader(binaryFileStream, "sizu"u8);

        var zStream = new DeflateStream(binaryFileStream, CompressionMode.Decompress);
        binaryFileStream.Position += 2; // Skip zlib magic

        byte[] decompressed = new byte[sizeUncompressed];
        zStream.ReadExactly(decompressed);

        using MemoryStream blobStream = new MemoryStream(decompressed);
        using BinaryStream blobBinaryStream = new BinaryStream(blobStream, ByteConverter.Little);
        uint type = AnimUtils.ReadHeader(blobBinaryStream, "type"u8); // 1?
        uint numArgs = AnimUtils.ReadHeader(blobBinaryStream, "args"u8);

        for (int i = 0; i < numArgs; i++)
        {
            ulong hash = blobBinaryStream.ReadUInt64();
            byte argType = blobBinaryStream.Read1Byte();

            switch (argType)
            {
                case 1: // Bool
                    {
                        bool value = blobBinaryStream.ReadBoolean();
                        Args.Add((hash, value));
                    }
                    break;
                case 2: // Int32
                    {
                        int value = blobBinaryStream.ReadInt32();
                        Args.Add((hash, value));
                    }
                    break;
                case 3: // Float
                    {
                        float value = blobBinaryStream.ReadSingle();
                        Args.Add((hash, value));
                    }
                    break;
                case 4: // String
                    {
                        string value = AnimUtils.ReadString(blobBinaryStream);
                        Args.Add((hash, value));
                    }
                    break;
                case 5: // Int64
                    {
                        long value = blobBinaryStream.ReadInt64();
                        Args.Add((hash, value));
                    }
                    break;
                default:
                    throw new NotSupportedException();
            }
        }

        if (AnimUtils.ReadHeader(blobBinaryStream, "stmr"u8) != 0) // AnimStateMirrorDef
        {
            // Unsure
            uint mirrorArguments = blobBinaryStream.ReadUInt32();
            for (int i = 0; i < mirrorArguments; i++)
            {
                blobBinaryStream.ReadUInt64();
                blobBinaryStream.ReadUInt64();
            }

            uint mirrorArguments2 = blobBinaryStream.ReadUInt32();
            for (int i = 0; i < mirrorArguments2; i++)
            {
                blobBinaryStream.ReadUInt64();
                blobBinaryStream.ReadUInt64();
            }

            uint mirrorArguments3 = blobBinaryStream.ReadUInt32();
            for (int i = 0; i < mirrorArguments3; i++)
            {
                blobBinaryStream.ReadUInt32();
                blobBinaryStream.ReadByte();
            }
        }
        else
            blobBinaryStream.Position -= 4;

        uint numEventDefs = AnimUtils.ReadHeader(blobBinaryStream, "adef"u8);
        if (numEventDefs != 0)
        {
            LoadXMLNodes(blobBinaryStream, numEventDefs);
        }
    }

    private void LoadXMLNodes(BinaryStream bs, uint numEventDefs)
    {
        for (int i = 0; i < numEventDefs; i++)
        {
            uint numStateNodes = AnimUtils.ReadHeader(bs, "stat"u8); // State

            var eventDef = new EventDef();
            EventDefs.Add(eventDef);

            for (int j = 0; j < numStateNodes; j++)
            {
                var stateNode = new AnimStateNode();
                stateNode.Read(bs);
                eventDef.StateNodes.Add(stateNode);
            }

            uint numGroupNodes = AnimUtils.ReadHeader(bs, "grp_"u8); // Group
            for (int j = 0; j < numGroupNodes; j++)
            {
                var groupNode = new AnimGroupNode();
                groupNode.Read(bs);
                eventDef.GroupNodes.Add(groupNode);
            }
        }
    }
}

public class AnimUtils
{
    public static uint ReadHeader(BinaryStream bs, ReadOnlySpan<byte> str)
    {
        Span<byte> sig = stackalloc byte[4];
        bs.ReadExactly(sig);

        sig.Reverse();

        if (!sig.SequenceEqual(str))
            return 0;

        uint value = bs.ReadUInt32();
        return value;
    }

    public static string ReadString(BinaryStream bs)
    {
        uint strLen = bs.ReadUInt32();
        string value = bs.ReadString(StringCoding.ZeroTerminated);
        Debug.Assert(strLen - 1 == Encoding.UTF8.GetByteCount(value));
        return value;
    }
}

public class EventDef
{
    public List<AnimStateNode> StateNodes = [];
    public List<AnimGroupNode> GroupNodes = [];
}

public class AnimGroupNode
{
    public List<string> Desc { get; set; } = [];
    public List<ulong> Members { get; set; } = [];
    public List<uint> Selectors { get; set; } = [];

    public void Read(BinaryStream bs)
    {
        uint numDesc = AnimUtils.ReadHeader(bs, "desc"u8);
        for (int i = 0; i < numDesc; i++)
        {
            string str = AnimUtils.ReadString(bs);
            Desc.Add(str);
        }

        uint numMembers = AnimUtils.ReadHeader(bs, "memb"u8);
        for (int i = 0; i < numMembers; i++)
        {
            ulong val = bs.ReadUInt64();
            Members.Add(val);
        }

        uint numSelectors = AnimUtils.ReadHeader(bs, "sels"u8);
        for (int i = 0; i < numSelectors; i++)
        {
            uint val = bs.ReadUInt32();
            Selectors.Add(val);
        }
    }
}

public class AnimNode
{
    public float CropEnd { get; set; }
    public float StartTime { get; set; }
    public bool IsMirrored { get; set; }
    public string DebugName { get; set; }
    public uint Variable { get; set; }
    public float PlaybackRate { get; set; }
    public float CropStart { get; set; }
    public string Uri { get; set; }
    public ulong Tag { get; set; }
}

public class AnimTransition
{
    public int FadeOutFrames { get; set; }
    public bool field_0xF4BC48C2 { get; set; }
    public int FadeInFrames { get; set; }
    public int StartAtFrame { get; set; }
    public string BlendAlignmentBone { get; set; }
    public bool SyncStateEnds { get; set; }
    public ulong FromState { get; set; }
    public bool IsSynchronized { get; set; }
}

public class AnimStateNode
{
    public bool ExclusiveRootRotation_Out { get; set; }
    public bool IsLooping { get; set; }
    public bool OnDemand { get; set; }
    public bool ExclusiveRootRotation_In { get; set; }
    public bool ExclusiveRootMotion_In { get; set; }
    public bool SyncWithFullBodyLayer { get; set; }
    public bool ExclusiveRootMotion_Out { get; set; }
    public string DebugName { get; set; }

    public AnimTransition Transition { get; set; }
    public List<AnimTransition> TransitionOverrides { get; set; } = [];

    public void Read(BinaryStream bs)
    {
        uint keyValueCount = AnimUtils.ReadHeader(bs, "kv__"u8);

        for (int j = 0; j < keyValueCount; j++)
        {
            // 'Tag'

            uint key = bs.ReadUInt32();

            switch (key)
            {
                case 0xC49DC060: // ExclusiveRootRotation_Out -> CRC32C("exclusiverootrotation_out")
                    ExclusiveRootRotation_Out = bs.ReadBoolean(); break;
                case 0xEBA4D0A6: // IsLooping -> CRC32C("islooping")
                    IsLooping = bs.ReadBoolean(); break;
                case 0xEF1E655D: // OnDemand -> CRC32C("ondemand")
                    OnDemand = bs.ReadBoolean(); break;
                case 0xBFC6C046: // ExclusiveRootRotation_In -> CRC32C("exclusiverootrotation_in")
                    ExclusiveRootRotation_In = bs.ReadBoolean(); break;
                case 0xE93FAA8: // ExclusiveRootMotion_In -> CRC32C("exclusiverootmotion_in")
                    ExclusiveRootMotion_In = bs.ReadBoolean(); break;
                case 0x2B5F244D: // SyncWithFullBodyLayer -> CRC32C("syncwithfullbodylayer")
                    SyncWithFullBodyLayer = bs.ReadBoolean(); break;
                case 0x8B648267: // ExclusiveRootMotion_Out -> CRC32C("exclusiverootmotion_out")
                    ExclusiveRootMotion_Out = bs.ReadBoolean(); break;
                case 0x8E0B4BDF: // DebugName -> CRC32C("debugname")
                    DebugName = AnimUtils.ReadString(bs); break;
                default:
                    throw new NotSupportedException();
            }
        }

        uint sync = AnimUtils.ReadHeader(bs, "sync"u8); // SynchroAnimations
        for (int i = 0; i < sync; i++)
        {
            bs.ReadUInt64();
            bs.ReadUInt64();
            bs.ReadBoolean();
        }

        ulong @ref = bs.ReadUInt64(); // Overlay / Ref?
        uint numDTTs = AnimUtils.ReadHeader(bs, "dtt_"u8); // DefaultTransitionTiming
        Debug.Assert(numDTTs == 1);

        Transition = ProcessTransitionNode(bs);
        uint numTransitionOverrides = AnimUtils.ReadHeader(bs, "tovr"u8); // TransitionOverrides
        for (int i = 0; i < numTransitionOverrides; i++)
        {
            AnimTransition transitionOvr = ProcessTransitionNode(bs);
            TransitionOverrides.Add(transitionOvr);
        }

        uint nodeType = AnimUtils.ReadHeader(bs, "node"u8); // Nodes / AnimationNode
        switch (nodeType)
        {
            case 1:
                {
                    ReadAnimNode(bs);
                }
                break;
            case 2:
                {
                    bs.ReadInt32(); // Type?
                }
                break;
            default:
                throw new NotSupportedException("Not yet supported.");
        }

        uint numDesc = AnimUtils.ReadHeader(bs, "desc"u8); // Descriptors
        for (int i = 0; i < numDesc; i++)
        {
            string str = AnimUtils.ReadString(bs);
        }

        uint numEventTriggers = AnimUtils.ReadHeader(bs, "evnt"u8); // 'Events' 
        for (int i = 0; i < numEventTriggers; i++)
        {
            // 'Event'

            // Unknown:
            // - DbId
            // - Triggering
            // - WindowOpenTag
            // - Payload

            ulong hash = bs.ReadUInt64();
            uint unk_ = bs.ReadUInt32();
            bool unkFlag = bs.ReadBoolean();
            if (!unkFlag)
            {
                uint unk3 = bs.ReadUInt32();
                ulong unk4 = bs.ReadUInt64();
            }

            var numTriggers = AnimUtils.ReadHeader(bs, "trig"u8); // 'Trigger'
            for (int j = 0; j < numTriggers; j++)
            {
                ulong @ref_ = bs.ReadUInt64(); // 'Ref'
                float frame = bs.ReadSingle(); // 'Frame'
            }

            var numArgs = AnimUtils.ReadHeader(bs, "args"u8); // 'Arg'
            for (int j = 0; j < numArgs; j++)
            {
                ushort id = bs.ReadUInt16(); // 'Id'
            }
        }
    }

    private AnimTransition ProcessTransitionNode(BinaryStream bs)
    {
        var transition = new AnimTransition();

        uint numKeyValues = AnimUtils.ReadHeader(bs, "kv__"u8);
        for (int i = 0; i < numKeyValues; i++)
        {
            uint key = bs.ReadUInt32();
            switch (key)
            {
                case 0xED804665: // FadeOutFrames -> CRC32("fadeoutframes")
                    transition.FadeOutFrames = bs.ReadInt32(); break;
                case 0xF4BC48C2:
                    transition.field_0xF4BC48C2 = bs.ReadBoolean(); break;
                case 0xFE8AE38A: // FadeInFrames -> CRC32C("fadeinframes")
                    transition.FadeInFrames = bs.ReadInt32(); break;
                case 0xDADA2544: // StartAtFrame -> CRC32C("startatframe")
                    transition.StartAtFrame = bs.ReadInt32(); break;
                case 0x11D9945: // BlendAlignmentBone -> CRC32C("blendalignmentbone")
                    transition.BlendAlignmentBone = AnimUtils.ReadString(bs); break;
                case 0x813DE48: // SyncStateEnds -> CRC32C("syncstateends")
                    transition.SyncStateEnds = bs.ReadBoolean(); break;
                case 0x33DEED73: // FromState -> CRC32C("fromstate")
                    transition.FromState = bs.ReadUInt64(); break;
                case 0x3A823F0C: // IsSynchronized -> CRC32C("issynchronized")
                    transition.IsSynchronized = bs.ReadBoolean(); break;
                default:
                    throw new NotSupportedException();
            }
        }

        return transition;
    }

    private AnimNode ReadAnimNode(BinaryStream bs)
    {
        AnimNode node = new AnimNode();

        bool useConstants = bs.ReadBoolean();
        uint numKeyValues = AnimUtils.ReadHeader(bs, "kv__"u8);
        for (int i = 0; i < numKeyValues; i++)
        {
            uint key = bs.ReadUInt32();
            switch (key)
            {
                case 0xCF0D984C: // CropEnd -> CRC32C("cropend")
                    node.CropEnd = bs.ReadSingle(); break;
                case 0xE39D3DA5: // StartTime -> CRC32C("starttime")
                    node.StartTime = bs.ReadSingle(); break;
                case 0xF43A2E0A: // IsMirrored -> CRC32C("ismirrored")
                    node.IsMirrored = bs.ReadBoolean(); break;
                case 0xFDF783BE: // DebugName -> CRC32C("debugname")
                    node.DebugName = AnimUtils.ReadString(bs); break;
                case 0xC748D578: // Variable, real name unknown (prop maybe?)
                    node.Variable = bs.ReadUInt32(); break;
                case 0x42CB2C8: // PlaybackRate -> CRC32C("playbackrate")
                    {
                        if (useConstants)
                        {
                            ulong variableHash = bs.ReadUInt64();
                        }
                        else
                            node.PlaybackRate = bs.ReadSingle();
                    }
                    break;
                case 0x6F1A9819: // CropStart -> CRC32C("cropstart")
                    node.CropStart = bs.ReadSingle(); break;
                case 0x8C103F9E: // Uri -> CRC32C("uri");
                    node.Uri = AnimUtils.ReadString(bs); break;
                case 0x8E0B4BDF: // Tag -> CRC32C("tag");
                    node.Tag = bs.ReadUInt64(); break;
                default:
                    throw new InvalidDataException();
            }
        }

        return node;
    }
}
