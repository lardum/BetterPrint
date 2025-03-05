namespace BetterPrint;

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
        _code = code;
        var cursor = 0;

        while (cursor < _code.Length)
        {
            var opcode = GetNext();
            Console.WriteLine(opcode.ToString("X"));

            switch (opcode)
            {
                case 0xC8:
                    Console.WriteLine("Bagno");
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