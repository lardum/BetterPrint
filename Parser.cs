using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BetterPrint;

// https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
// https://github.com/mono/mono/blob/0f53e9e151d92944cacab3e24ac359410c606df6/tools/pedump/pedump.c#L49
public class Parser(string path)
{
    public readonly byte[] FileBytes = File.ReadAllBytes(path);
    private int _cursor;
    private readonly bool _debug = false;
    private readonly Dictionary<string, Dictionary<string, MetadataRecord>> _metadata = new();

    private MetadataModule Module = null!;
    private List<TypeRef> TyperefTable = [];
    private List<TypeDef> TypeDefTable = [];
    private List<MethodDef> MethodDefTable = [];
    private List<Param> ParamTable = [];

    public Dictionary<string, Dictionary<string, MetadataRecord>> Parse()
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

        // var tables = new
        // {
        //     Module,
        //     TyperefTable,
        //     TypeDefTable,
        //     MethodDefTable,
        //     ParamTable
        // };
        // Console.WriteLine(JsonSerializer.Serialize(tables, new JsonSerializerOptions { WriteIndented = true }));

        var codeSection = _metadata["sections"][".text"];

        var virtualAddress = codeSection.Children!["virtual_address"].IntValue;
        var pointerToRawData = codeSection.Children!["pointer_to_raw_data"].IntValue;

        var vm = new VirtualMachine();

        File.WriteAllText("./bytes.txt", BitConverter.ToString(FileBytes));

        foreach (var mdt in MethodDefTable)
        {
            var fileOffset = mdt.Rva.IntValue - virtualAddress + pointerToRawData;
            var firstByte = FileBytes[fileOffset];
            var isTinyHeader = (firstByte & 0x3) == 0x2;
            var isFatHeader = (firstByte & 0x3) == 0x3;

            var codeSize = 0;
            if (isTinyHeader)
            {
                codeSize = (firstByte >> 2); // Upper 6 bits store size
            }

            var codeOffset = fileOffset + 1;

            if (isFatHeader)
            {
                codeSize = BinaryPrimitives.ReadInt32LittleEndian(FileBytes.AsSpan(codeOffset + 4));
            }

            var methodEnd = codeOffset + codeSize;

            vm.Execute(FileBytes.Skip(codeOffset).Take(methodEnd - codeOffset).ToArray());

            break;
        }

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

    private Dictionary<string, MetadataRecord> ParseDosHeader()
    {
        return new Dictionary<string, MetadataRecord>
        {
            { Consts.PeParts.DosHeader, new MetadataRecord(MetadataType.ByteText, _cursor, GetNext(128)) }
        };
    }

    private Dictionary<string, MetadataRecord> ParsePeFileHeader()
    {
        var peHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(FileBytes.Skip(60).Take(4).ToArray());

        // Verify PE signature "PE\0\0"
        if (FileBytes[peHeaderOffset] != 'P' || FileBytes[peHeaderOffset + 1] != 'E' ||
            FileBytes[peHeaderOffset + 2] != 0 || FileBytes[peHeaderOffset + 3] != 0)
        {
            throw new InvalidOperationException("Invalid PE signature");
        }

        var peFileHeader = new Dictionary<string, MetadataRecord>
        {
            { "pe_signature", new MetadataRecord(MetadataType.ByteText, _cursor, GetNext(4)) },
            { "machine", new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(2)) },
            { "number_of_sections", new MetadataRecord(MetadataType.Short, _cursor, GetNext(2)) },
            { "time_date_stamp", new MetadataRecord(MetadataType.DateTime, _cursor, GetNext(4)) },
            { "pointer_to_symbol_table", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "number_of_symbols", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "optional_header_size", new MetadataRecord(MetadataType.Short, _cursor, GetNext(2)) },
            { "characteristics", new MetadataRecord(MetadataType.Binary, _cursor, GetNext(2)) }
        };

        return peFileHeader;
    }

    private Dictionary<string, MetadataRecord> ParseOptionalHeader()
    {
        var optionalHeader = new Dictionary<string, MetadataRecord>
        {
            { "magic", new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(2)) },
            { "major_linker_version", new MetadataRecord(MetadataType.Byte, _cursor, GetNext()) }, // Should be 6 but is 48?
            { "minor_linker_version", new MetadataRecord(MetadataType.Byte, _cursor, GetNext()) },
            { "size_of_code", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "size_of_initialized_data", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "size_of_uninitialized_data", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "entry_point_rva", new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(4)) },
            { "base_of_code", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "base_of_data", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "nt_fields", new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(68)) }, // II.25.2.3.3 Pe header data directories
            { "export_table", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "import_table", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "resource_table", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "exception_table", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "certificate_table", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "base_relocation_table", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "debug", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "copyright", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "global_ptr", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "tls_table", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "load_config_table", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "bound_import", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "iat", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "delay_import_descriptor", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "clr_runtime_header_rva", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "clr_runtime_header_size", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "reserved", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) }
        };

        return optionalHeader;
    }

    private Dictionary<string, MetadataRecord> ParseSectionHeaders(MetadataRecord numberOfSectionsRecord)
    {
        var localCursor = 0;
        var sectionHeaders = new Dictionary<string, MetadataRecord>();
        var numSections = numberOfSectionsRecord.ShortValue;

        byte[] sectionBytes;
        for (var i = 0; i < numSections; i++)
        {
            localCursor = 0;
            var index = _cursor;
            sectionBytes = GetNext(40);
            var nameBytes = GetNextLocal(8);
            var sectionName = Encoding.ASCII.GetString(sectionBytes[..8]).Trim('\0');

            var sectionDetails = new Dictionary<string, MetadataRecord>
            {
                { "name", new MetadataRecord(MetadataType.ByteText, index + localCursor - 8, nameBytes) },
                { "virtual_size", new MetadataRecord(MetadataType.Int, index + localCursor, GetNextLocal(4)) },
                { "virtual_address", new MetadataRecord(MetadataType.Int, index + localCursor, GetNextLocal(4)) },
                { "size_of_raw_data", new MetadataRecord(MetadataType.Int, index + localCursor, GetNextLocal(4)) },
                { "pointer_to_raw_data", new MetadataRecord(MetadataType.Int, index + localCursor, GetNextLocal(4)) },
                { "pointer_to_relocations", new MetadataRecord(MetadataType.Int, index + localCursor, GetNextLocal(4)) },
                { "pointer_to_linenumbers", new MetadataRecord(MetadataType.Int, index + localCursor, GetNextLocal(4)) },
                { "number_of_relocations", new MetadataRecord(MetadataType.Short, index + localCursor, GetNextLocal(2)) },
                { "number_of_linenumbers", new MetadataRecord(MetadataType.Short, index + localCursor, GetNextLocal(2)) },
                { "characteristics", new MetadataRecord(MetadataType.Binary, index + localCursor, GetNextLocal(4)) }
            };

            if (_debug)
            {
                var characteristics = sectionDetails["characteristics"];
                var flags = Consts.ParseFlags(characteristics.Value, Consts.SectionHeaderCharacteristics);
                Console.WriteLine(string.Join(", ", flags));
            }

            sectionHeaders.Add(sectionName, new MetadataRecord(MetadataType.Bytes, _cursor, sectionBytes, sectionDetails));
        }

        return sectionHeaders;

        byte[] GetNextLocal(int len = 1)
        {
            var bts = sectionBytes.Skip(localCursor).Take(len).ToArray();
            localCursor += len;
            return bts;
        }
    }

    private Dictionary<string, MetadataRecord> ParseCliHeader()
    {
        var clrHeaderRva = _metadata["optional_header"]["clr_runtime_header_rva"].IntValue;
        var clrHeaderOffset = RvaToFileOffset(clrHeaderRva);
        _cursor = clrHeaderOffset;

        var cliHeader = new Dictionary<string, MetadataRecord>
        {
            { "size_of_header", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "major_runtime_version", new MetadataRecord(MetadataType.Short, _cursor, GetNext(2)) },
            { "minor_runtime_version", new MetadataRecord(MetadataType.Short, _cursor, GetNext(2)) },
            { "metadata_rva", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "metadata_size", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "flags", new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(4)) },
            { "entry_point_token", new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(4)) },
            { "resources_rva", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "resources_size", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "strong_name_signature_rva", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "strong_name_signature_size", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "code_manager_table_rva", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "code_manager_table_size", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "export_address_table_jumps_rva", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "export_address_table_jumps_size", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "managed_native_header_rva", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "managed_native_header_size", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
        };

        return cliHeader;
    }

    // I.24.2.1 Metadata root 
    private Dictionary<string, MetadataRecord> ParseMetadataRoot()
    {
        var metadataRootRva = _metadata["cli_header"]["metadata_rva"].IntValue;
        var metadataOffset = RvaToFileOffset(metadataRootRva);

        _cursor = metadataOffset;

        var metadataRoot = new Dictionary<string, MetadataRecord>()
        {
            { "signature", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "major_version", new MetadataRecord(MetadataType.Short, _cursor, GetNext(2)) },
            { "minor_version", new MetadataRecord(MetadataType.Short, _cursor, GetNext(2)) },
            { "reserved", new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(4)) },
            { "version_length", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
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

        metadataRoot.Add("version_string", new MetadataRecord(MetadataType.ByteText, versionOffset, versionBytes));

        // Align to 4-byte boundary
        var offset = versionOffset + versionBytes.Length;
        offset = (offset + 3) & ~3;
        _cursor = offset;

        metadataRoot.Add("flags", new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(2)));
        metadataRoot.Add("number_of_streams", new MetadataRecord(MetadataType.Short, _cursor, GetNext(2)));

        if (_debug)
        {
            Console.WriteLine($"CLR version {version}, Metadata streams: {metadataRoot["number_of_streams"].IntValue}");
        }

        ParseMetadataStreamHeaders(metadataRoot, metadataRoot["number_of_streams"].ShortValue);

        return metadataRoot;
    }

    private void ParseMetadataStreamHeaders(Dictionary<string, MetadataRecord> metadataRoot, int numberOfStreams)
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

            var fileOffset =
                RvaToFileOffset(_metadata["cli_header"]["metadata_rva"].IntValue + BinaryPrimitives.ReadInt32LittleEndian(streamOffsetBytes));
            metadataRoot
                .Add($"{streamName}", new MetadataRecord(MetadataType.Bytes, index, FileBytes.Skip(index).Take(8 + nameBytes.Length).ToArray(),
                    new Dictionary<string, MetadataRecord>
                    {
                        { "offset", new MetadataRecord(MetadataType.Int, index, streamOffsetBytes) },
                        { "size", new MetadataRecord(MetadataType.Int, index + 4, streamSizeBytes) },
                        { "name", new MetadataRecord(MetadataType.ByteText, index + 4, nameBytes) },
                        { "file_offset", new MetadataRecord(MetadataType.Int, index + 4, BitConverter.GetBytes(fileOffset)) }
                    }));

            // Move to next stream header (align to 4-byte boundary)
            var offset = nameEndOffset + 1;
            _cursor = (offset + 3) & ~3;
        }

        var tableStream = metadataRoot.FirstOrDefault(x => x.Key is "#~" or "#-").Value;

        if (tableStream is not null)
        {
            ParseTablesHeader(tableStream);
        }
    }

    private void ParseTablesHeader(MetadataRecord tableStream)
    {
        // II.24.2.6 #~ stream
        var fileOffset = tableStream.Children!["file_offset"].IntValue;
        _cursor = fileOffset;

        var children = new Dictionary<string, MetadataRecord>
        {
            { "reserved", new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)) },
            { "major_version", new MetadataRecord(MetadataType.Byte, _cursor, GetNext()) },
            { "minor_version", new MetadataRecord(MetadataType.Byte, _cursor, GetNext()) },
            { "heap_of_set_sizes", new MetadataRecord(MetadataType.Byte, _cursor, GetNext()) },
            { "reserved_2", new MetadataRecord(MetadataType.Byte, _cursor, GetNext()) },
            { "mask_valid", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) },
            { "mask_sorted", new MetadataRecord(MetadataType.Long, _cursor, GetNext(8)) }
        };

        // Parse table row counts (for each bit set in validTables)

        // The number of 1s in the Valid bitvector determines how many values exist in Rows.
        // For hello word Valid value is: 0 0 0 1001 0 0 10101 1000111 as ValueBitString
        // Console.WriteLine(children["mask_valid"].ValueBitString());
        // Read the Valid field (64-bit number).
        // Check which bits are set (1) to know which tables exist.
        // Read the Rows array to get the row count for each existing table.

        // Store this information in a dictionary {table_name: row_count}.
        var validTables = (ulong)children["mask_valid"].LongValue;
        var rowCounts = new uint[64];
        for (var i = 0; i < 64; i++)
        {
            if ((validTables & (1UL << i)) != 0)
            {
                rowCounts[i] = BitConverter.ToUInt32(GetNext(4));
            }
        }

        // II.22.30 Module : 0x00 
        var stringHeapSize = GetHeapIndexSize("String");
        var guidHeapSize = GetHeapIndexSize("GUID");
        Module = new MetadataModule
        (
            new MetadataRecord(MetadataType.Short, _cursor, GetNext(2)),
            new MetadataRecord(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize)),
            new MetadataRecord(guidHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(guidHeapSize)),
            new MetadataRecord(guidHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(guidHeapSize)),
            new MetadataRecord(guidHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(guidHeapSize))
        );

        // II.22.38 TypeRef : 0x01
        var typeRefRowCount = rowCounts[0x01];
        var tableIndexSize1A = GetTableIndexSize(0x1A);
        for (var i = 0; i < typeRefRowCount; i++)
        {
            // page 275, ResolutionScope: 2 bits to encode tag, index 26 (0x1A)_
            var resolutionScope =
                new MetadataRecord(tableIndexSize1A == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(tableIndexSize1A));
            var typeName = new MetadataRecord(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize));
            var typeNamespace = new MetadataRecord(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize));

            TyperefTable.Add(new TypeRef(resolutionScope, typeName, typeNamespace));
        }

        // II.22.37 TypeDef : 0x02
        var typeDefRowCount = rowCounts[0x02]; // Get number of TypeDefs
        var typeDefExtendsSize = GetTableIndexSize(0x01); // TypeRef Table size (for Extends column)
        var fieldTableIndexSize = GetTableIndexSize(0x04); // Field Table index size
        var methodTableIndexSize = GetTableIndexSize(0x06); // MethodDef Table index size
        for (var i = 0; i < typeDefRowCount; i++)
        {
            var flags = new MetadataRecord(MetadataType.Int, _cursor, GetNext(4)); // 4-byte Flags
            var typeName = new MetadataRecord(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize));
            var typeNamespace = new MetadataRecord(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize));
            var extends = new MetadataRecord(typeDefExtendsSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(typeDefExtendsSize));
            var fieldList = new MetadataRecord(fieldTableIndexSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor,
                GetNext(fieldTableIndexSize));
            // var methodList = new MetadataRecord(methodTableIndexSize == 2 ? TokenType.Short : TokenType.Int, _cursor, GetNext(methodTableIndexSize));

            // IDK
            TypeDefTable.Add(new TypeDef(flags, typeName, typeNamespace, extends, fieldList, null!));
        }

        var blobHeapSize = GetHeapIndexSize("Blob");
        // II.22.26 MethodDef : 0x06
        var methodDefRowCount = rowCounts[0x06]; // Number of methods

        for (var i = 0; i < methodDefRowCount; i++)
        {
            var rva = new MetadataRecord(MetadataType.Int, _cursor, GetNext(4));
            var implFlags = new MetadataRecord(MetadataType.Short, _cursor, GetNext(2));
            var flags = new MetadataRecord(MetadataType.Short, _cursor, GetNext(2));
            var name = new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(stringHeapSize));
            var signature = new MetadataRecord(blobHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(blobHeapSize));
            // TODO: FIX 
            var paramList = new MetadataRecord(
                MetadataType.Short, //GetTableIndexSize(0x08) == 2 ? TokenType.Short : TokenType.Int,
                _cursor,
                GetNext(2) //GetTableIndexSize(0x08))
            );

            MethodDefTable.Add(new MethodDef(rva, implFlags, flags, name, signature, paramList));
        }

        // II.22.33 Param : 0x08
        var paramRowCount = rowCounts[0x08];
        for (var i = 0; i < paramRowCount; i++)
        {
            var flags = new MetadataRecord(MetadataType.Short, _cursor, GetNext(2));
            var sequence = new MetadataRecord(MetadataType.Bytes, _cursor, GetNext(2));
            var name = new MetadataRecord(MetadataType.Short, _cursor, GetNext(stringHeapSize));
            ParamTable.Add(new Param(flags, sequence, name));
        }

        return;

        // The HeapSizes field is a bitvector that encodes the width of indexes into the various heaps. If bit 0 is
        // set, indexes into the “#String” heap are 4 bytes wide; if bit 1 is set, indexes into the “#GUID” heap are
        // 4 bytes wide; if bit 2 is set, indexes into the “#Blob” heap are 4 bytes wide. Conversely, if the
        // HeapSize bit for a particular heap is not set, indexes into that heap are 2 bytes wide
        int GetHeapIndexSize(string heapType)
        {
            var heapSize = children["heap_of_set_sizes"].IntValue;

            return heapType switch
            {
                "String" => (heapSize & 0x01) != 0 ? 4 : 2,
                "GUID" => (heapSize & 0x02) != 0 ? 4 : 2,
                "Blob" => (heapSize & 0x04) != 0 ? 4 : 2,
                _ => throw new ArgumentException("Invalid heap type")
            };
        }

        int GetTableIndexSize(int tableId)
        {
            var maskValid = children["mask_valid"].LongValue;
            return ((maskValid & (1L << tableId)) != 0) ? 4 : 2;
        }
    }

    private byte[] GetNext(int len = 1)
    {
        var bts = FileBytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }

    private void PrintDebug(Dictionary<string, Dictionary<string, MetadataRecord>> parsedIl)
    {
        Console.WriteLine(string.Join(", ",
            Consts.ParseFlags(parsedIl["pe_file_header"]["characteristics"].Value, Consts.PeFileHeaderCharacteristics)));
        Console.WriteLine(JsonSerializer.Serialize(parsedIl, new JsonSerializerOptions { WriteIndented = true }));
    }
}

public record MetadataRecord(MetadataType Type, int Index, byte[] Value, Dictionary<string, MetadataRecord>? Children = null)
{
    public string ValueAsciiString() => Encoding.ASCII.GetString(Value);
    public string ValueBitString() => string.Join(" ", Value.Reverse().Select(x => x.ToString("B")));
    public string ValueHexString() => BitConverter.ToString(Value.Reverse().ToArray());

    public string StringValue
        => Type switch
        {
            MetadataType.Binary => ValueBitString(),
            MetadataType.Byte => Value[0].ToString(),
            MetadataType.Short => BinaryPrimitives.ReadInt16LittleEndian(Value).ToString(),
            MetadataType.Int => BinaryPrimitives.ReadInt32LittleEndian(Value).ToString(),
            MetadataType.Long => BinaryPrimitives.ReadInt64LittleEndian(Value).ToString(),
            MetadataType.DateTime => DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(Value)).UtcDateTime.ToString("u"),
            MetadataType.ByteText => ValueAsciiString(),
            MetadataType.Bytes => ValueHexString(),
            _ => ValueHexString(),
        };

    public short ShortValue => Type == MetadataType.Short ? BinaryPrimitives.ReadInt16LittleEndian(Value) : (short)0;
    public int IntValue => Type == MetadataType.Int ? BinaryPrimitives.ReadInt32LittleEndian(Value) : 0;
    public long LongValue => Type == MetadataType.Long ? BinaryPrimitives.ReadInt64LittleEndian(Value) : 0;
    public string HexValue => BitConverter.ToString(Value.Reverse().ToArray());
}

public enum MetadataType
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