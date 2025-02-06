using System.Buffers.Binary;

namespace BetterPrint;

static class Consts
{
    public class PeParts
    {
        public const string DosHeader = "dos_header";
    }

    public static List<(string name, int value)> CharacteristicsFlag =
    [
        ("IMAGE_FILE_RELOCS_STRIPPED", 0x0001), // Shall be zero 
        ("IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002), // Shall be one 
        ("IMAGE_FILE_32BIT_MACHINE", 0x0100), // Shall be one if and only if COMIMAGE_FLAGS_32BITREQUIRED is one (25.3.3.1) 
        ("IMAGE_FILE_DLL", 0x2000), // The image file is a dynamic-link library (DLL).  
    ];

    public static List<string> ParseFlags(byte[] flags, List<(string name, int value)> definedFlags)
    {
        var flagsIntValue = BinaryPrimitives.ReadUInt16LittleEndian(flags);
        Console.WriteLine("HALO" + flagsIntValue);
        return definedFlags
            .Where(x => (x.value & flagsIntValue) != 0)
            .Select(x => x.name)
            .ToList();
    }
}