using System.Buffers.Binary;

namespace BetterPrint;

static class Consts
{
    public class PeParts
    {
        public const string DosHeader = "dos_header";
    }

    public static List<(string name, uint value)> PeFileHeaderCharacteristics =
    [
        ("IMAGE_FILE_RELOCS_STRIPPED", 0x0001), // Shall be zero 
        ("IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002), // Shall be one 
        ("IMAGE_FILE_32BIT_MACHINE", 0x0100), // Shall be one if and only if COMIMAGE_FLAGS_32BITREQUIRED is one (25.3.3.1) 
        ("IMAGE_FILE_DLL", 0x2000), // The image file is a dynamic-link library (DLL).  
    ];

    public static List<(string name, uint value)> SectionHeaderCharacteristics =
    [
        ("IMAGE_SCN_CNT_CODE", 0x00000020), // Section contains code.
        ("IMAGE_SCN_CNT_INITIALIZED_DATA", 0x00000040), // Section contains initialized data.
        ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x00000080), // Section contains uninitialized data.
        ("IMAGE_SCN_MEM_EXECUTE", 0x20000000), // Section can be executed as code.
        ("IMAGE_SCN_MEM_READ", 0x40000000), // Section can be read.
        ("IMAGE_SCN_MEM_WRITE", 0x80000000), // Section can be written to.
    ];

    public static List<string> ParseFlags(byte[] flags, List<(string name, uint value)> definedFlags)
    {
        var flagsIntValue = BinaryPrimitives.ReadUInt16LittleEndian(flags);
        return definedFlags
            .Where(x => (x.value & flagsIntValue) != 0)
            .Select(x => x.name)
            .ToList();
    }
}