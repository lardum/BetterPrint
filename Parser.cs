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
    private readonly Dictionary<string, Dictionary<string, IlRecord>> _metadata = new();

    public Dictionary<string, Dictionary<string, IlRecord>> Parse()
    {
        _metadata.Add(Consts.PeParts.DosHeader, ParseDosHeader());
        _metadata.Add("pe_file_header", ParsePeFileHeader());
        _metadata.Add("optional_header", ParseOptionalHeader());
        _metadata.Add("sections", ParseSectionHeaders(_metadata["pe_file_header"]["number_of_sections"]));
        _metadata.Add("cli_header", ParseCliHeader());
        _metadata.Add("metadata_root", ParseMetadataRoot());

        if (_debug)
        {
            PrintDebug(_metadata);
        }

        var codeSection = _metadata["sections"][".text"];
        var rawDataPointer = codeSection.Children!["pointer_to_raw_data"].IntValue;
        var rawDataSize = codeSection.Children!["size_of_raw_data"].IntValue;
        var codeBytes = FileBytes.Skip(rawDataPointer).Take(rawDataSize).ToArray();

        return _metadata;
    }

    /// <summary>
    /// Where is this logic in the docks?
    /// </summary>
    /// <param name="rva"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    private int RvaToFileOffset(int rva)
    {
        foreach (var section in _metadata["sections"])
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
        var clrHeaderRva = _metadata["optional_header"]["clr_runtime_header_rva"].IntValue;
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

    // I.24.2.1 Metadata root 
    private Dictionary<string, IlRecord> ParseMetadataRoot()
    {
        var metadataRootRva = _metadata["cli_header"]["metadata_rva"].IntValue;
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

        var versionBytes = FileBytes.Skip(versionOffset).Take(versionEndOffset - versionOffset).ToArray();

        metadataRoot.Add("version_string", new IlRecord(TokenType.ByteText, versionOffset, versionBytes));

        // Align to 4-byte boundary
        var offset = versionOffset + versionBytes.Length;
        offset = (offset + 3) & ~3;
        _cursor = offset;

        metadataRoot.Add("flags", new IlRecord(TokenType.Bytes, _cursor, GetNext(2)));
        metadataRoot.Add("number_of_streams", new IlRecord(TokenType.Short, _cursor, GetNext(2)));

        if (_debug)
        {
            Console.WriteLine($"CLR version {version}, Metadata streams: {metadataRoot["number_of_streams"].IntValue}");
        }

        ParseMetadataStreamHeaders(metadataRoot, metadataRoot["number_of_streams"].ShortValue);

        return metadataRoot;
    }

    private void ParseMetadataStreamHeaders(Dictionary<string, IlRecord> metadataRoot, int numberOfStreams)
    {
        for (var i = 0; i < numberOfStreams; i++)
        {
            var streamOffsetBytes = GetNext(4);
            var streamSizeBytes = GetNext(4);

            // Read stream name (null-terminated)
            var nameOffset = _cursor;
            var nameEndOffset = nameOffset;
            while (FileBytes[nameEndOffset] != 0 && nameEndOffset < FileBytes.Length)
            {
                nameEndOffset++;
            }

            var nameBytes = GetNext(nameEndOffset - nameOffset);
            var streamName = Encoding.ASCII.GetString(nameBytes);
            var index = _cursor - nameBytes.Length - 8;

            var fileOffset = RvaToFileOffset(_metadata["cli_header"]["metadata_rva"].IntValue + BinaryPrimitives.ReadInt32LittleEndian(streamOffsetBytes));
            metadataRoot
                .Add($"{streamName}", new IlRecord(TokenType.Bytes, index, FileBytes.Skip(index).Take(8 + nameBytes.Length).ToArray(),
                    new Dictionary<string, IlRecord>
                    {
                        { "offset", new IlRecord(TokenType.Int, index, streamOffsetBytes) },
                        { "size", new IlRecord(TokenType.Int, index + 4, streamSizeBytes) },
                        { "name", new IlRecord(TokenType.ByteText, index + 4, nameBytes) },
                        { "file_offset", new IlRecord(TokenType.Int, index + 4, BitConverter.GetBytes(fileOffset)) }
                    }));

            // Move to next stream header (align to 4-byte boundary)
            var offset = nameEndOffset + 1;
            _cursor = (offset + 3) & ~3;
        }

        var tableStream = metadataRoot.FirstOrDefault(x => x.Key is "#~" or "#-").Value;

        if (tableStream is not null)
        {
            ParseTablesHeader(metadataRoot, tableStream);
        }
    }

    private void ParseTablesHeader(Dictionary<string, IlRecord> metadataRoot, IlRecord tableStream)
    {
        var fileOffset = tableStream.Children!["file_offset"].IntValue;
        _cursor = fileOffset;

        var children = new Dictionary<string, IlRecord>
        {
            { "reserved", new IlRecord(TokenType.Int, _cursor, GetNext(4)) },
            { "major_version", new IlRecord(TokenType.Byte, _cursor, GetNext()) },
            { "minor_version", new IlRecord(TokenType.Byte, _cursor, GetNext()) },
            { "heap_of_set_sizes", new IlRecord(TokenType.Byte, _cursor, GetNext()) },
            { "reserved_2", new IlRecord(TokenType.Byte, _cursor, GetNext()) },
            { "mask_valid", new IlRecord(TokenType.Long, _cursor, GetNext(8)) },
            { "mask_sorted", new IlRecord(TokenType.Long, _cursor, GetNext(8)) }
        };

        // Parse table row counts (for each bit set in validTables)
        var validTables = (ulong)children["mask_valid"].LongValue;
        var rowCounts = new uint[64];
        for (var i = 0; i < 64; i++)
        {
            if ((validTables & (1UL << i)) != 0)
            {
                rowCounts[i] = BitConverter.ToUInt32(GetNext(4));
            }
        }

        // Calculate string index size (if strings heap is large)
        int heapSizes = children["heap_of_set_sizes"].Value.First();
        var largeStrings = (heapSizes & 0x01) != 0;
        var largeGUID = (heapSizes & 0x02) != 0;
        var largeBlob = (heapSizes & 0x04) != 0;

        // For TypeDef table (0x02), we need the row count
        if ((validTables & (1UL << 0x02)) != 0 && rowCounts[0x02] > 0)
        {
            // Find the relevant heap streams
            var stringsStream = metadataRoot.First(x => x.Key == "#Strings").Value;
            var blobStream = metadataRoot.First(x => x.Key == "#Blob").Value;

            // Parse TypeDef table
            // its parsing streams, we dont want to do it yet
            // ParseTypeDefTable(_cursor, rowCounts, largeStrings, largeGUID, largeBlob, stringsStream, blobStream, metadataRoot);
        }
        else
        {
            Console.WriteLine("No TypeDef entries in the metadata");
        }

        metadataRoot.Add("tables_header", new IlRecord(TokenType.Bytes, 0, [], children));
        
        Console.WriteLine("------------------");
        Console.WriteLine(JsonSerializer.Serialize(metadataRoot, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("------------------");
    }

    private void ParseTypeDefTable(int tablesOffset, uint[] rowCounts, bool largeStrings, bool largeGUID, bool largeBlob,
        IlRecord stringsStream, IlRecord blobStream, Dictionary<string, IlRecord> metadataRoot)
    {
        // Console.WriteLine("------------------");
        // Console.WriteLine(JsonSerializer.Serialize(metadataRoot, new JsonSerializerOptions { WriteIndented = true }));
        // Console.WriteLine("------------------");

        // Calculate offsets of different tables
        var typeDefOffset = tablesOffset;

        // Need to account for rows in tables that come before TypeDef
        for (var i = 0; i < 0x02; i++)
        {
            if ((rowCounts[i] > 0))
            {
                // Need to calculate table size and add it
                // This is complex and depends on the specific table
                // For simplicity, just adding placeholder
                typeDefOffset += (int)(rowCounts[i] * 16); // Approximate
            }
        }

        if (_debug)
        {
            Console.WriteLine($"TypeDef Table Offset: 0x{typeDefOffset:X8}, Rows: {rowCounts[0x02]}");
        }

        // TypeDef table column sizes depend on various factors
        int stringsIndexSize = largeStrings ? 4 : 2;
        int blobIndexSize = largeBlob ? 4 : 2;
        int tableIndexSize = 2; // Depends on max rows, simplified here

        int typeDefRowSize = 4 + stringsIndexSize + stringsIndexSize + tableIndexSize + tableIndexSize + tableIndexSize;

        for (int i = 0; i < rowCounts[0x02]; i++)
        {
            int rowOffset = typeDefOffset + (i * typeDefRowSize);

            uint flags = BitConverter.ToUInt32(FileBytes, rowOffset);

            // Read name from strings heap
            int nameIndex = largeStrings
                ? BitConverter.ToInt32(FileBytes, rowOffset + 4)
                : BitConverter.ToUInt16(FileBytes, rowOffset + 4);

            // Read namespace from strings heap
            int namespaceIndex = largeStrings
                ? BitConverter.ToInt32(FileBytes, rowOffset + 4 + stringsIndexSize)
                : BitConverter.ToUInt16(FileBytes, rowOffset + 4 + stringsIndexSize);

            string name = ReadStringFromHeap(stringsStream, nameIndex);
            string namespaceName = ReadStringFromHeap(stringsStream, namespaceIndex);

            // var typeDef = new TypeDefinition
            // {
            //     Flags = flags,
            //     Name = name,
            //     Namespace = namespaceName,
            //     FullName = string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}.{name}"
            // };

            // TypeDefinitions.Add(typeDef);
        }
    }

    private string ReadStringFromHeap(IlRecord stringsStream, int index)
    {
        if (stringsStream == null || index <= 0)
        {
            return string.Empty;
        }

        var stringOffset = stringsStream.Children["file_offset"].IntValue + index;

        // Find end of string (null-terminated)
        int endOffset = stringOffset;
        while (endOffset < FileBytes.Length && FileBytes[endOffset] != 0)
        {
            endOffset++;
        }

        return Encoding.UTF8.GetString(FileBytes, stringOffset, endOffset - stringOffset);
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
    public string HexValue => BitConverter.ToString(Value.Reverse().ToArray());
}

public enum TokenType
{
    Binary,
    Byte,
    Bytes,
    ByteText,
    Short,
    Int, // DWord
    Long, // QWord
    DateTime,
}