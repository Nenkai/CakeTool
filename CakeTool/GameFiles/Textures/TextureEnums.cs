using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool.GameFiles.Textures;

// WEngine::GEBaseFmt
public enum GEBaseFmt : uint
{
    Invalid = 0,
    BC1 = 1,            
    BC4 = 2,            
    BC2 = 3,            
    BC3 = 4,            
    BC5 = 5,            
    BC6H = 6,          
    BC7 = 7,          
    R8 = 8,       
    A8 = 9,                                         
    R8_G8 = 10,      
    R16 = 11,         
    R8_G8_B8_A8 = 12,
    R16_G16 = 13,     
    R32 = 14,         
    R10_G10_B10_A2 = 15,
    R11_G11_B10 = 16,  
    B8_G8_R8_A8 = 17,
    R16_G16_B16_A16 = 18,
    R32_G32 = 20,  
    R32_G32_B32 = 21, 
    R32_G32_B32_A32 = 22,
    D16 = 23,        
    D32 = 24,         
    R32_S8 = 25,
}

// WEngine::GEType
public enum GEType : uint
{
    Invalid = 0,
    Float = 1,
    UNorm = 2,
    SNorm = 3,
    UInt = 4,
    SInt = 5,
    UF16 = 6,
    SF16 = 7,
}
