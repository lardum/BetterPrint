namespace BetterPrint;

// https://learn.microsoft.com/pl-pl/dotnet/api/system.reflection.emit.opcodes?view=net-9.0
// https://en.wikipedia.org/wiki/List_of_CIL_instructions
public class Executor
{
    private byte[] _code = [];

    public Executor(Dictionary<string, Dictionary<string, IlRecord>> il)
    {
        var codeSection = il["sections"][".text"];
        var rawDataPointer = codeSection.Children!["pointer_to_raw_data"].IntValue;
        var rawDataSize = codeSection.Children!["size_of_raw_data"].IntValue;
        // var codeBytes = parser.FileBytes.Skip(rawDataPointer).Take(rawDataSize).ToArray();
    }

    public void Execute(byte[] code)
    {
        Console.WriteLine("Code: " + string.Join("", code.Select(x => x.ToString("X"))));

        _code = code;
        var cursor = 0;

        while (cursor < _code.Length)
        {
            var opcode = GetNext();
            opcode = GetNext();
            Console.WriteLine(opcode.ToString("X"));
            Console.WriteLine(opcode.ToString());

            switch (opcode)
            {
                case 0xC8:
                    Console.WriteLine("Bagno");
                    break;
                case 0x26:
                    Console.WriteLine("pop");
                    break;
            }

            break;
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