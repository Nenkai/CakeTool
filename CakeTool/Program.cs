using Syroot.BinaryData;
using System.Text;

namespace CakeTool;

public class Program
{
    static void Main(string[] args)
    {
        var file = new CakeRegistryFile();
        file.Open(args[0]);
    } 
}
