namespace BetterPrint;

public class Executor
{
    private readonly byte[] _code = [];

    public Executor(Dictionary<string, Dictionary<string, IlRecord>> il)
    {
        var codeSection = il["sections"][".text"];
        var rawDataPointer = codeSection.Children!["pointer_to_raw_data"].IntValue;
        var rawDataSize = codeSection.Children!["size_of_raw_data"].IntValue;
        // var codeBytes = parser.FileBytes.Skip(rawDataPointer).Take(rawDataSize).ToArray();
    }

    public void Execute()
    {
        var cursor = 0;

        while (cursor < _code.Length)
        {
        }


        return;

        byte GetNextByteLocal()
        {
            var res = _code.Skip(cursor).Take(1).First();
            cursor++;
            return res;
        }
    }
}