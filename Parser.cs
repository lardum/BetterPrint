using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BetterPrint;

// https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
public class Parser(string path)
{
    public readonly byte[] FileBytes = File.ReadAllBytes(path);
    private int _cursor;
    private readonly bool _debug = false;
    private readonly Dictionary<string, Dictionary<string, IlRecord>> _il = new();

    public Dictionary<string, Dictionary<string, IlRecord>> Parse()
    {
        _il.Add(Consts.PeParts.DosHeader, ParseDosHeader());
        _il.Add("pe_file_header", ParsePeFileHeader());
        _il.Add("optional_header", ParseOptionalHeader());
        _il.Add("sections", ParseSectionHeaders(_il["pe_file_header"]["number_of_sections"]));
        _il.Add("cli_header", ParseCliHeader());
        _il.Add("metadata_root", ParseMetadataRoot());

        if (_debug)
        {
            PrintDebug(_il);
        }

        var codeSection = _il["sections"][".text"];
        var rawDataPointer = codeSection.Children!["pointer_to_raw_data"].IntValue;
        var rawDataSize = codeSection.Children!["size_of_raw_data"].IntValue;
        var codeBytes = FileBytes.Skip(rawDataPointer).Take(rawDataSize).ToArray();

        return _il;
    }

    /// <summary>
    /// Where is this logic in the docks?
    /// </summary>
    /// <param name="rva"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    private int RvaToFileOffset(int rva)
    {
        foreach (var section in _il["sections"])
        {
            var virtualAddress = section.Value.Children!["virtual_address"].IntValue;
            if (rva >= virtualAddress && rva < virtualAddress + virtualAddress)
            {
                return section.Value.Children["pointer_to_raw_data"].IntValue + (rva - virtualAddress);
            }
        }

        throw new InvalidOperationException($"Could not convert RVA 0x{rva:X8} to file offset");
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
        var peHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(FileBytes.Skip(60).Take(4).ToArray());

        // Verify PE signature "PE\0\0"
        if (FileBytes[peHeaderOffset] != 'P' || FileBytes[peHeaderOffset + 1] != 'E' ||
            FileBytes[peHeaderOffset + 2] != 0 || FileBytes[peHeaderOffset + 3] != 0)
        {
            throw new InvalidOperationException("Invalid PE signature");
        }

        var peFileHeader = new Dictionary<string, IlRecord>
        {
            { "pe_signature", new IlRecord(TokenType.ByteText, _cursor, GetNext(4)) },
            { "machine", new IlRecord(TokenType.Bytes, _cursor, GetNext(2)) },
            { "number_of_sections", new IlRecord(TokenType.Short, _cursor, GetNext(2)) },
            { "time_date_stamp", new IlRecord(TokenType.DateTime, _cursor, GetNext(4)) },
            { "pointer_to_symbol_table", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "number_of_symbols", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "optional_header_size", new IlRecord(TokenType.Short, _cursor, GetNext(2)) },
            { "characteristics", new IlRecord(TokenType.Binary, _cursor, GetNext(2)) }
        };

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
            { "nt_fields", new IlRecord(TokenType.Bytes, _cursor, GetNext(68)) }, // II.25.2.3.3 Pe header data directories
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
            { "clr_runtime_header_rva", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "clr_runtime_header_size", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "reserved", new IlRecord(TokenType.Long, _cursor, GetNext(8)) }
        };

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

            if (_debug)
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
        var clrHeaderRva = _il["optional_header"]["clr_runtime_header_rva"].IntValue;
        var clrHeaderOffset = RvaToFileOffset(clrHeaderRva);
        _cursor = clrHeaderOffset;

        var cliHeader = new Dictionary<string, IlRecord>
        {
            { "size_of_header", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "major_runtime_version", new IlRecord(TokenType.Short, _cursor, GetNext(2)) },
            { "minor_runtime_version", new IlRecord(TokenType.Short, _cursor, GetNext(2)) },
            { "metadata_rva", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "metadata_size", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "flags", new IlRecord(TokenType.Bytes, _cursor, GetNext(4)) },
            { "entry_point_token", new IlRecord(TokenType.Bytes, _cursor, GetNext(4)) },
            { "resources_rva", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "resources_size", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "strong_name_signature_rva", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "strong_name_signature_size", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "code_manager_table_rva", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "code_manager_table_size", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "export_address_table_jumps_rva", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "export_address_table_jumps_size", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "managed_native_header_rva", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "managed_native_header_size", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
        };

        return cliHeader;
    }

    private Dictionary<string, IlRecord> ParseMetadataRoot()
    {
        var metadataRootRva = _il["cli_header"]["metadata_rva"].IntValue;
        var metadataOffset = RvaToFileOffset(metadataRootRva);

        _cursor = metadataOffset;

        var metadataRoot = new Dictionary<string, IlRecord>()
        {
            { "signature", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "major_version", new IlRecord(TokenType.Short, _cursor, GetNext(2)) },
            { "minor_version", new IlRecord(TokenType.Short, _cursor, GetNext(2)) },
            { "reserved", new IlRecord(TokenType.Bytes, _cursor, GetNext(4)) },
            { "version_length", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
        };

        // Read version string (null-terminated)
        var versionOffset = metadataOffset + 16;
        var versionEndOffset = versionOffset;
        while (FileBytes[versionEndOffset] != 0 && versionEndOffset < FileBytes.Length)
        {
            versionEndOffset++;
        }

        var version = Encoding.ASCII.GetString(FileBytes, versionOffset, versionEndOffset - versionOffset);

        if (_debug)
        {
            Console.WriteLine($"CLR version {version}");
        }

        var versionBytes = FileBytes.Skip(versionOffset).Take(versionEndOffset - versionOffset).ToArray();

        metadataRoot.Add("version_string", new IlRecord(TokenType.ByteText, versionOffset, versionBytes));

        return metadataRoot;
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