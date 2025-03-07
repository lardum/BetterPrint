namespace BetterPrint;

// https://learn.microsoft.com/pl-pl/dotnet/api/system.reflection.emit.opcodes?view=net-9.0
// https://github.com/dotnet/runtime/blob/1d1bf92fcf43aa6981804dc53c5174445069c9e4/src/libraries/System.Private.CoreLib/src/System/Reflection/Emit/OpCodes.cs
// https://en.wikipedia.org/wiki/List_of_CIL_instructions
public class VirtualMachine
{
    private byte[] _code = [];

    public VirtualMachine(Dictionary<string, Dictionary<string, IlRecord>> il)
    {
        var codeSection = il["sections"][".text"];
        var rawDataPointer = codeSection.Children!["pointer_to_raw_data"].IntValue;
        var rawDataSize = codeSection.Children!["size_of_raw_data"].IntValue;
        Console.WriteLine($"Raw data pointer: {rawDataPointer}, and its size {rawDataSize}");
        // var codeBytes = parser.FileBytes.Skip(rawDataPointer).Take(rawDataSize).ToArray();
    }

    public void Execute(byte[] code)
    {
        var a = 0xFE18;
        Console.WriteLine("Code: " + string.Join(" ", code.Take(10).Select(x => x.ToString("X2"))));

        _code = code;
        var cursor = 0;

        while (cursor < 10) //_code.Length)
        {
            var opcode = GetNext();
            Console.WriteLine(opcode.ToString("X2"));

            switch (opcode)
            {
                case 0xC8:
                    Console.WriteLine("Bagno");
                    break;
                case 0x26:
                    Console.WriteLine("pop");
                    break;
                default:
                    Console.WriteLine($"Unknown opcode {opcode:X}");
                    break;
            }
        }

        return;

        byte GetNext()
        {
            var res = _code.Skip(cursor).Take(1).First();
            cursor++;
            return res;
        }
    }
}