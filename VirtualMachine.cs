namespace BetterPrint;

// https://learn.microsoft.com/pl-pl/dotnet/api/system.reflection.emit.opcodes?view=net-9.0
// https://github.com/dotnet/runtime/blob/1d1bf92fcf43aa6981804dc53c5174445069c9e4/src/libraries/System.Private.CoreLib/src/System/Reflection/Emit/OpCodes.cs
// https://en.wikipedia.org/wiki/List_of_CIL_instructions
public class VirtualMachine
{
    private byte[] _bytecode = [];
    private Stack<int> _stack = new Stack<int>();

    // public VirtualMachine(Dictionary<string, Dictionary<string, MetadataRecord>> il)
    // {
    //     var codeSection = il["sections"][".text"];
    //     var rawDataPointer = codeSection.Children!["pointer_to_raw_data"].IntValue;
    //     var rawDataSize = codeSection.Children!["size_of_raw_data"].IntValue;
    //     // Console.WriteLine($"Raw data pointer: {rawDataPointer}, and its size {rawDataSize}");
    //     // var codeBytes = parser.FileBytes.Skip(rawDataPointer).Take(rawDataSize).ToArray();
    // }

    public void Execute(byte[] code)
    {
        // For hello world:
        // 00-72-01-00-00-70-28-0D-00-00-0A-00-2A
        // 00 -> nop
        // 72 -> ldstr (read string) 
        // take next 4 bytes 01-00-00-70
        // 28 -> Ldc_I4 (Pushes a supplied value of type int32)
        // 0D-00-00-0A
        // 00 -> nop
        // 2A -> ret (return) 

        Console.WriteLine($"Len: {code.Length} | " + BitConverter.ToString(code));

        _bytecode = code;
        var cursor = 0;

        return;
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
            var res = _bytecode.Skip(cursor).Take(1).First();
            cursor++;
            return res;
        }
    }
}