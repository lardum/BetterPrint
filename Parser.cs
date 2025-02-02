using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BetterPrint;

public class Parser(string path)
{
    private readonly int _len = path.Length;
    private readonly byte[] _fileBytes = File.ReadAllBytes(path);
    private int _cursor = 0;

    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    // https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
    // II.25.2.1 MS-DOS header
    public void Parse()
    {
        var parsedIl = new Dictionary<string, IlRecord>();
        parsedIl.Add(Consts.PeParts.DosHeader, new IlRecord(TokenType.ByteText, _cursor, GetNext(128)));

        var lfanewOffset = BinaryPrimitives.ReadInt32LittleEndian(_fileBytes.Skip(60).Take(4).ToArray());
        if (lfanewOffset != 128) throw new Exception("Wrong offset");

        parsedIl.Add("pe_file_header", new IlRecord(TokenType.ByteText, _cursor, GetNext(4)));
        parsedIl.Add("machine", new IlRecord(TokenType.Bytes, _cursor, GetNext(2)));
        parsedIl.Add("number_of_sections", new IlRecord(TokenType.Short, _cursor, GetNext(2)));

        // Console.WriteLine(JsonSerializer.Serialize(parsedIl, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine(parsedIl["number_of_sections"].GetValue());
    }

    private byte[] GetNext(int len = 1)
    {
        var bts = _fileBytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }

    private short ReadInt16(byte[] bytes) => BinaryPrimitives.ReadInt16BigEndian(bytes);
}

static class Consts
{
    public class PeParts
    {
        public const string DosHeader = "dos_header";
    }
}

record IlRecord(TokenType Type, int Index, byte[] Value)
{
    public string ValueAsciiString() => Encoding.ASCII.GetString(Value);
    public string ValueHexString() => string.Join(" ", Value.Select(x => x.ToString("X")));
    public string ValueBitString() => string.Join(" ", Value.Select(x => x.ToString("B")));

    public string GetValue()
    {
        if (Type == TokenType.Short)
        {
            return BinaryPrimitives.ReadInt16LittleEndian(Value).ToString();
        }

        return ValueAsciiString();
    }
}

internal enum TokenType
{
    Bytes,
    ByteText,
    Short,
}