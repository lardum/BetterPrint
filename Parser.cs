using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BetterPrint;

// https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
public class Parser(string path)
{
    private readonly byte[] _fileBytes = File.ReadAllBytes(path);
    private int _cursor;

    public void Parse()
    {
        var il = new Dictionary<string, Dictionary<string, IlRecord>>();
        il.Add(Consts.PeParts.DosHeader, ParseDosHeader());
        il.Add("pe_file_header", ParsePeFileHeader());
        il.Add("optional_header", ParseOptionalHeader());
        il.Add("sections", ParseSectionHeaders(il["pe_file_header"]["number_of_sections"]));

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

        peFileHeader.Add("pe_signature", new IlRecord(TokenType.ByteText, _cursor, GetNext(4)));
        peFileHeader.Add("machine", new IlRecord(TokenType.Bytes, _cursor, GetNext(2)));
        peFileHeader.Add("number_of_sections", new IlRecord(TokenType.Short, _cursor, GetNext(2)));
        peFileHeader.Add("time_date_stamp", new IlRecord(TokenType.DateTime, _cursor, GetNext(4)));
        peFileHeader.Add("pointer_to_symbol_table", new IlRecord(TokenType.Int, _cursor, GetNext(4)));
        peFileHeader.Add("number_of_symbols", new IlRecord(TokenType.Int, _cursor, GetNext(4)));
        peFileHeader.Add("optional_header_size", new IlRecord(TokenType.Short, _cursor, GetNext(2)));
        peFileHeader.Add("characteristics", new IlRecord(TokenType.Binary, _cursor, GetNext(2)));

        return peFileHeader;
    }

    private Dictionary<string, IlRecord> ParseOptionalHeader()
    {
        var optionalHeader = new Dictionary<string, IlRecord>
        {
            { "magic", new IlRecord(TokenType.Bytes, _cursor, GetNext(2)) },
            { "major_linker_version", new IlRecord(TokenType.Byte, _cursor, GetNext()) }, // Should be 6 but is 48?
            { "minor_linker_version", new IlRecord(TokenType.Byte, _cursor, GetNext()) },
            { "size_of_code", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "size_of_initialized_data", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "size_of_uninitialized_data", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "entry_point_rva", new IlRecord(TokenType.Bytes, _cursor, GetNext(4)) },
            { "base_of_code", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "base_of_data", new IlRecord(TokenType.Int, _cursor, GetNext(4)) }
        };

        return optionalHeader;
    }

    // To verify
    private Dictionary<string, IlRecord> ParseSectionHeaders(IlRecord numberOfSectionsRecord)
    {
        var sectionHeaders = new Dictionary<string, IlRecord>();
        int numSections = int.Parse(numberOfSectionsRecord.GetReadableValue());

        for (int i = 0; i < numSections; i++)
        {
            string sectionName = Encoding.ASCII.GetString(GetNext(8)).Trim('\0');
            sectionHeaders.Add(sectionName, new IlRecord(TokenType.ByteText, _cursor, GetNext(40)));
        }

        return sectionHeaders;
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
        Console.WriteLine(JsonSerializer.Serialize(parsedIl, new JsonSerializerOptions { WriteIndented = true }));
    }
}

internal record IlRecord(TokenType Type, int Index, byte[] Value)
{
    private string ValueAsciiString() => Encoding.ASCII.GetString(Value);
    private string ValueBitString() => string.Join(" ", Value.Reverse().Select(x => x.ToString("B")));
    public string ValueHexString() => BitConverter.ToString(Value.Reverse().ToArray());

    public string GetReadableValue()
    {
        return Type switch
        {
            TokenType.Binary => ValueBitString(),
            TokenType.Byte => Value[0].ToString(),
            TokenType.Short => BinaryPrimitives.ReadInt16LittleEndian(Value).ToString(),
            TokenType.Int => BinaryPrimitives.ReadInt32LittleEndian(Value).ToString(),
            TokenType.DateTime => DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(Value)).UtcDateTime.ToString("u"),
            TokenType.ByteText => ValueAsciiString(),
            TokenType.Bytes => ValueHexString(),
            _ => ValueHexString(),
        };
    }
}

internal enum TokenType
{
    Binary,
    Byte,
    Bytes,
    ByteText,
    Int,
    Short,
    DateTime,
}