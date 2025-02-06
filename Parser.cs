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
        var il = new Dictionary<string, Dictionary<string, IlRecord>>();
        il.Add(Consts.PeParts.DosHeader, ParseDosHeader());
        il.Add("pe_file_header", ParsePeFileHeader());
        PrintDebug(il);
    }

    private Dictionary<string, IlRecord> ParseDosHeader()
    {
        return new Dictionary<string, IlRecord>
        {
            { Consts.PeParts.DosHeader, new IlRecord(TokenType.ByteText, _cursor, GetNext(128)) }
        };
    }

    private Dictionary<string, IlRecord> ParsePeFileHeader()
    {
        var peFileHeader = new Dictionary<string, IlRecord>();

        var lfanewOffset = BinaryPrimitives.ReadUInt32LittleEndian(_fileBytes.Skip(60).Take(4).ToArray());
        if (lfanewOffset != 128) Console.WriteLine($"Wrong offset {lfanewOffset}");

        peFileHeader.Add("pe_singature", new IlRecord(TokenType.ByteText, _cursor, GetNext(4)));
        peFileHeader.Add("machine", new IlRecord(TokenType.Bytes, _cursor, GetNext(2)));
        peFileHeader.Add("number_of_sections", new IlRecord(TokenType.Short, _cursor, GetNext(2)));
        peFileHeader.Add("time_date_stamp", new IlRecord(TokenType.DateTime, _cursor, GetNext(4)));
        peFileHeader.Add("pointer_to_symbol_table", new IlRecord(TokenType.Int, _cursor, GetNext(4)));
        peFileHeader.Add("number_of_symbols", new IlRecord(TokenType.Int, _cursor, GetNext(4)));
        peFileHeader.Add("optional_header_size", new IlRecord(TokenType.Short, _cursor, GetNext(2)));
        peFileHeader.Add("characteristics", new IlRecord(TokenType.Binary, _cursor, GetNext(2)));

        return peFileHeader;
    }

    private byte[] GetNext(int len = 1)
    {
        var bts = _fileBytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }

    private void PrintDebug(Dictionary<string, Dictionary<string, IlRecord>> parsedIl)
    {
        Console.WriteLine(string.Join(", ",
            Consts.ParseFlags(parsedIl["pe_file_header"]["characteristics"].Value, Consts.CharacteristicsFlag)));
        Console.WriteLine(JsonSerializer.Serialize(parsedIl));
    }
}

internal record IlRecord(TokenType Type, int Index, byte[] Value)
{
    private string ValueAsciiString() => Encoding.ASCII.GetString(Value);
    private string ValueBitString() => string.Join(" ", Value.Reverse().Select(x => x.ToString("B")));
    public string ValueHexString() => BitConverter.ToString(Value.Reverse().ToArray());

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
                var uintValue = BinaryPrimitives.ReadUInt32LittleEndian(Value);
                var dateTimeValue = DateTimeOffset.FromUnixTimeSeconds(uintValue).UtcDateTime;
                return dateTimeValue.ToString("u"); // Calc is not working but the bytes are correct
            case TokenType.Bytes:
            case TokenType.ByteText:
                return ValueAsciiString();
            default:
                return ValueHexString();
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