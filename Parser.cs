using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BetterPrint;

public class Parser(string path)
{
    private readonly byte[] _fileBytes = File.ReadAllBytes(path);
    private int _cursor;

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
        parsedIl.Add("time_date_stamp", new IlRecord(TokenType.DateTime, _cursor, GetNext(4)));
        parsedIl.Add("pointer_to_symbol_table", new IlRecord(TokenType.Int, _cursor, GetNext(4)));
        parsedIl.Add("number_of_symbols", new IlRecord(TokenType.Int, _cursor, GetNext(4)));
        parsedIl.Add("optional_header_size", new IlRecord(TokenType.Short, _cursor, GetNext(2)));
        parsedIl.Add("characteristics", new IlRecord(TokenType.Binary, _cursor, GetNext(2)));

        Console.WriteLine(parsedIl["time_date_stamp"].GetValue());
        Console.WriteLine(parsedIl["optional_header_size"].GetValue());
        Console.WriteLine(parsedIl["characteristics"].GetValue());
    }

    private byte[] GetNext(int len = 1)
    {
        var bts = _fileBytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }
}

internal record IlRecord(TokenType Type, int Index, byte[] Value)
{
    private string ValueAsciiString() => Encoding.ASCII.GetString(Value);
    private string ValueBitString() => string.Join(" ", Value.Select(x => x.ToString("B")));
    public string ValueHexString() => string.Join(" ", Value.Select(x => x.ToString("X")));

    public string GetValue()
    {
        switch (Type)
        {
            case TokenType.Binary:
                return ValueBitString();
            case TokenType.Short:
                return BinaryPrimitives.ReadInt16LittleEndian(Value).ToString();
            case TokenType.Int:
                return BinaryPrimitives.ReadInt32LittleEndian(Value).ToString();
            case TokenType.DateTime:
            {
                var intValue = BinaryPrimitives.ReadInt32BigEndian(Value); // WHY HERE IS BIG ENDIAN???
                var dateTimeValue = new DateTime(1970, 1, 1).AddSeconds(intValue);
                return dateTimeValue.ToString("u");
            }
            case TokenType.Bytes:
            case TokenType.ByteText:
            default:
                return ValueAsciiString();
        }
    }
}

internal enum TokenType
{
    Binary,
    Bytes,
    ByteText,
    Int,
    Short,
    DateTime,
}