using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

// SysCore::FilesysDirHeader
public struct FilesysDirHeader
{
    public uint Signature;
    public ushort Version;
    public ushort Flags;
}
