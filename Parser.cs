using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BetterPrint;

// https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
// https://www.cybb0rg.com/2024/07/20/pe-headers-and-sections-explained/
public class Parser(string path)
{
    public readonly byte[] FileBytes = File.ReadAllBytes(path);
    private int _cursor;
    private const bool Debug = true;

    public Dictionary<string, Dictionary<string, IlRecord>> Parse()
    {
        var il = new Dictionary<string, Dictionary<string, IlRecord>>();
        il.Add(Consts.PeParts.DosHeader, ParseDosHeader());
        il.Add("pe_file_header", ParsePeFileHeader());
        il.Add("optional_header", ParseOptionalHeader());
        il.Add("sections", ParseSectionHeaders(il["pe_file_header"]["number_of_sections"]));
        il.Add("cli_header", ParseCliHeader());

        if (Debug)
        {
            PrintDebug(il);
        }

        var codeSection = il["sections"][".text"];
        var rawDataPointer = codeSection.Children!["pointer_to_raw_data"].IntValue;
        var rawDataSize = codeSection.Children!["size_of_raw_data"].IntValue;
        var codeBytes = FileBytes.Skip(rawDataPointer).Take(rawDataSize).ToArray();

        return il;
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

        var lfanewOffset = BinaryPrimitives.ReadUInt32LittleEndian(FileBytes.Skip(60).Take(4).ToArray());
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
            { "base_of_data", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "nt_fields", new IlRecord(TokenType.Bytes, _cursor, GetNext(68)) },
            // II.25.2.3.3 Pe header data directories
            { "export_table", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "import_table", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "resource_table", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "exception_table", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "certificate_table", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "base_relocation_table", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "debug", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "copyright", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "global_ptr", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "tls_table", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "load_config_table", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "bound_import", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "iat", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "delay_import_descriptor", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "cli_header", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "reserved", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
        };

        var a = optionalHeader["cli_header"];
        return optionalHeader;
    }

    private Dictionary<string, IlRecord> ParseSectionHeaders(IlRecord numberOfSectionsRecord)
    {
        var localCursor = 0;
        var sectionHeaders = new Dictionary<string, IlRecord>();
        var numSections = numberOfSectionsRecord.ShortValue;

        byte[] sectionBytes;
        for (var i = 0; i < numSections; i++)
        {
            localCursor = 0;
            var index = _cursor;
            sectionBytes = GetNext(40);
            var nameBytes = GetNextLocal(8);
            var sectionName = Encoding.ASCII.GetString(sectionBytes[..8]).Trim('\0');

            var sectionDetails = new Dictionary<string, IlRecord>
            {
                { "name", new IlRecord(TokenType.ByteText, index + localCursor - 8, nameBytes) },
                { "virtual_size", new IlRecord(TokenType.Int, index + localCursor, GetNextLocal(4)) },
                { "virtual_address", new IlRecord(TokenType.Int, index + localCursor, GetNextLocal(4)) },
                { "size_of_raw_data", new IlRecord(TokenType.Int, index + localCursor, GetNextLocal(4)) },
                { "pointer_to_raw_data", new IlRecord(TokenType.Int, index + localCursor, GetNextLocal(4)) },
                { "pointer_to_relocations", new IlRecord(TokenType.Int, index + localCursor, GetNextLocal(4)) },
                { "pointer_to_linenumbers", new IlRecord(TokenType.Int, index + localCursor, GetNextLocal(4)) },
                { "number_of_relocations", new IlRecord(TokenType.Short, index + localCursor, GetNextLocal(2)) },
                { "number_of_linenumbers", new IlRecord(TokenType.Short, index + localCursor, GetNextLocal(2)) },
                { "characteristics", new IlRecord(TokenType.Binary, index + localCursor, GetNextLocal(4)) }
            };

            if (Debug)
            {
                var characteristics = sectionDetails["characteristics"];
                var flags = Consts.ParseFlags(characteristics.Value, Consts.SectionHeaderCharacteristics);
                Console.WriteLine(string.Join(", ", flags));
            }

            sectionHeaders.Add(sectionName, new IlRecord(TokenType.Bytes, _cursor, sectionBytes, sectionDetails));
        }

        return sectionHeaders;

        byte[] GetNextLocal(int len = 1)
        {
            var bts = sectionBytes.Skip(localCursor).Take(len).ToArray();
            localCursor += len;
            return bts;
        }
    }

    private Dictionary<string, IlRecord> ParseCliHeader()
    {
        var cliHeader = new Dictionary<string, IlRecord>
        {
            { "size_of_header", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
        };

        var a = cliHeader["size_of_header"];

        return cliHeader;
    }

    private byte[] GetNext(int len = 1)
    {
        var bts = FileBytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }

    private void PrintDebug(Dictionary<string, Dictionary<string, IlRecord>> parsedIl)
    {
        Console.WriteLine(string.Join(", ",
            Consts.ParseFlags(parsedIl["pe_file_header"]["characteristics"].Value, Consts.PeFileHeaderCharacteristics)));
        Console.WriteLine(JsonSerializer.Serialize(parsedIl, new JsonSerializerOptions { WriteIndented = true }));
    }
}

public record IlRecord(TokenType Type, int Index, byte[] Value, Dictionary<string, IlRecord>? Children = null)
{
    private string ValueAsciiString() => Encoding.ASCII.GetString(Value);
    private string ValueBitString() => string.Join(" ", Value.Reverse().Select(x => x.ToString("B")));
    public string ValueHexString() => BitConverter.ToString(Value.Reverse().ToArray());

    public string StringValue
        => Type switch
        {
            TokenType.Binary => ValueBitString(),
            TokenType.Byte => Value[0].ToString(),
            TokenType.Short => BinaryPrimitives.ReadInt16LittleEndian(Value).ToString(),
            TokenType.Int => BinaryPrimitives.ReadInt32LittleEndian(Value).ToString(),
            TokenType.Long => BinaryPrimitives.ReadInt64LittleEndian(Value).ToString(),
            TokenType.DateTime => DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(Value)).UtcDateTime.ToString("u"),
            TokenType.ByteText => ValueAsciiString(),
            TokenType.Bytes => ValueHexString(),
            _ => ValueHexString(),
        };

    public short ShortValue => Type == TokenType.Short ? BinaryPrimitives.ReadInt16LittleEndian(Value) : (short)0;
    public int IntValue => Type == TokenType.Int ? BinaryPrimitives.ReadInt32LittleEndian(Value) : 0;
    public long LongValue => Type == TokenType.Long ? BinaryPrimitives.ReadInt64LittleEndian(Value) : 0;
}

public enum TokenType
{
    Binary,
    Byte,
    Bytes,
    ByteText,
    Short,
    Int,
    Long,
    DateTime,
}