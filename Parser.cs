using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BetterPrint;

// https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
// https://github.com/mono/mono/blob/0f53e9e151d92944cacab3e24ac359410c606df6/tools/pedump/pedump.c#L49
public class Parser(string path)
{
    private int _cursor;
    private readonly bool _debug = false;
    private readonly Dictionary<string, Dictionary<string, Metadata>> _metadata = new();

    public readonly byte[] FileBytes = File.ReadAllBytes(path);
    public DosHeader DosHeader = null!;
    public PeFileHeader PeFileHeader = null!;
    public PeOptionalHeader PeOptionalHeader = null!;
    public List<SectionHeader> SectionHeaders = [];
    public CliHeader CliHeader = null!;
    public MetadataRoot MetadataRoot = null!;

    public MetadataModule Module = null!;
    public List<TypeRef> TyperefTable = [];
    public List<TypeDef> TypeDefTable = [];
    public List<MethodDef> MethodDefTable = [];
    public List<Param> ParamTable = [];

    public Dictionary<string, Dictionary<string, Metadata>> Parse()
    {
        ParseDosHeader();
        ParsePeFileHeader();
        ParseOptionalHeader();
        ParseSectionHeaders(PeFileHeader.NumberOfSections);
        ParseCliHeader();
        ParseMetadataRoot();

        var strings = MetadataRoot.StreamHeaders.First(x => x.Name.StringValue == "#Strings");
        var stringsOffset = strings.FileOffset.IntValue;
        var stringsSize = strings.Size.IntValue;
        var stringsBytes = FileBytes.Skip(stringsOffset).Take(stringsSize).ToArray();

        var metadata = new
        {
            DosHeader,
            Module,
            TyperefTable,
            TypeDefTable,
            MethodDefTable,
            ParamTable
        };
        // Console.WriteLine(JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }));

        var codeSection = SectionHeaders.First(x => x.Name.StringValue.Trim('\0') == ".text");

        var virtualAddress = codeSection.VirtualAddress.IntValue;
        var pointerToRawData = codeSection.PointerToRawData.IntValue;

        var vm = new VirtualMachine(stringsBytes);

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
        foreach (var section in SectionHeaders)
        {
            var virtualAddress = section.VirtualAddress.IntValue;
            if (rva >= virtualAddress && rva < virtualAddress + virtualAddress)
            {
                return section.PointerToRawData.IntValue + (rva - virtualAddress);
            }
        }

        throw new InvalidOperationException($"Could not convert RVA 0x{rva:X8} to file offset");
    }

    private void ParseDosHeader()
    {
        DosHeader = new DosHeader(new Metadata(MetadataType.ByteText, _cursor, GetNext(128)));
        var peHeaderOffset = DosHeader.GetLfanew();

        // Verify PE signature "PE\0\0"
        if (FileBytes[peHeaderOffset] != 'P' || FileBytes[peHeaderOffset + 1] != 'E' ||
            FileBytes[peHeaderOffset + 2] != 0 || FileBytes[peHeaderOffset + 3] != 0)
        {
            throw new InvalidOperationException("Invalid PE signature");
        }
    }

    private void ParsePeFileHeader()
    {
        PeFileHeader = new PeFileHeader(
            new Metadata(MetadataType.ByteText, _cursor, GetNext(4)),
            new Metadata(MetadataType.Bytes, _cursor, GetNext(2)),
            new Metadata(MetadataType.Short, _cursor, GetNext(2)),
            new Metadata(MetadataType.DateTime, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Short, _cursor, GetNext(2)),
            new Metadata(MetadataType.Binary, _cursor, GetNext(2))
        );
    }

    private void ParseOptionalHeader()
    {
        PeOptionalHeader = new PeOptionalHeader(
            new Metadata(MetadataType.Bytes, _cursor, GetNext(2)),
            new Metadata(MetadataType.Byte, _cursor, GetNext()),
            new Metadata(MetadataType.Byte, _cursor, GetNext()),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Bytes, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            // II.25.2.3.2 PE header Windows NT-specific fields
            new Metadata(MetadataType.Bytes, _cursor, GetNext(68)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8))
        );
    }

    private void ParseSectionHeaders(Metadata numberOfSections)
    {
        int localCursor;
        var numSections = numberOfSections.ShortValue;

        byte[] sectionBytes;
        for (var i = 0; i < numSections; i++)
        {
            localCursor = 0;
            var index = _cursor;
            sectionBytes = GetNext(40);
            var nameBytes = GetNextLocal(8);

            var sectionDetails = new SectionHeader(
                new Metadata(MetadataType.ByteText, index + localCursor - 8, nameBytes),
                new Metadata(MetadataType.Int, index + localCursor, GetNextLocal(4)),
                new Metadata(MetadataType.Int, index + localCursor, GetNextLocal(4)),
                new Metadata(MetadataType.Int, index + localCursor, GetNextLocal(4)),
                new Metadata(MetadataType.Int, index + localCursor, GetNextLocal(4)),
                new Metadata(MetadataType.Int, index + localCursor, GetNextLocal(4)),
                new Metadata(MetadataType.Int, index + localCursor, GetNextLocal(4)),
                new Metadata(MetadataType.Short, index + localCursor, GetNextLocal(2)),
                new Metadata(MetadataType.Short, index + localCursor, GetNextLocal(2)),
                new Metadata(MetadataType.Binary, index + localCursor, GetNextLocal(4))
            );

            SectionHeaders.Add(sectionDetails);

            if (_debug)
            {
                var flags = Consts.ParseFlags(sectionDetails.Characteristics.Value, Consts.SectionHeaderCharacteristics);
                Console.WriteLine(string.Join(", ", flags));
            }
        }

        return;

        byte[] GetNextLocal(int len = 1)
        {
            var bts = sectionBytes.Skip(localCursor).Take(len).ToArray();
            localCursor += len;
            return bts;
        }
    }

    private void ParseCliHeader()
    {
        var clrHeaderRva = PeOptionalHeader.ClrRuntimeHeaderRva.IntValue;
        var clrHeaderOffset = RvaToFileOffset(clrHeaderRva);
        _cursor = clrHeaderOffset;

        CliHeader = new CliHeader(
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Short, _cursor, GetNext(2)),
            new Metadata(MetadataType.Short, _cursor, GetNext(2)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Bytes, _cursor, GetNext(4)),
            new Metadata(MetadataType.Bytes, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4))
        );
    }

    // I.24.2.1 Metadata root 
    private void ParseMetadataRoot()
    {
        var metadataRootRva = CliHeader.MetadataRva.IntValue;
        var metadataOffset = RvaToFileOffset(metadataRootRva);

        _cursor = metadataOffset;

        MetadataRoot = new MetadataRoot(
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Short, _cursor, GetNext(2)),
            new Metadata(MetadataType.Short, _cursor, GetNext(2)),
            new Metadata(MetadataType.Bytes, _cursor, GetNext(4)),
            new Metadata(MetadataType.Int, _cursor, GetNext(4))
        );

        // Read version string (null-terminated)
        var versionOffset = metadataOffset + 16;
        var versionEndOffset = versionOffset;
        while (FileBytes[versionEndOffset] != 0 && versionEndOffset < FileBytes.Length)
        {
            versionEndOffset++;
        }

        var version = Encoding.ASCII.GetString(FileBytes, versionOffset, versionEndOffset - versionOffset);

        var versionBytes = FileBytes.Skip(versionOffset).Take(versionEndOffset - versionOffset).ToArray();

        MetadataRoot.VersionString = new Metadata(MetadataType.ByteText, versionOffset, versionBytes);

        // Align to 4-byte boundary
        var offset = versionOffset + versionBytes.Length;
        offset = (offset + 3) & ~3;
        _cursor = offset;

        MetadataRoot.Flags = new Metadata(MetadataType.Bytes, _cursor, GetNext(2));
        MetadataRoot.NumberOfStreams = new Metadata(MetadataType.Short, _cursor, GetNext(2));

        if (_debug)
        {
            Console.WriteLine($"CLR version {version}, Metadata streams: {MetadataRoot.NumberOfStreams.IntValue}");
        }

        ParseMetadataStreamHeaders(MetadataRoot);
    }

    private void ParseMetadataStreamHeaders(MetadataRoot metadataRoot)
    {
        for (var i = 0; i < metadataRoot.NumberOfStreams.ShortValue; i++)
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
            var index = _cursor - nameBytes.Length - 8;
            var fileOffset = RvaToFileOffset(CliHeader.MetadataRva.IntValue + BinaryPrimitives.ReadInt32LittleEndian(streamOffsetBytes));

            MetadataRoot.StreamHeaders.Add(new StreamHeader(
                new Metadata(MetadataType.Int, index, streamOffsetBytes),
                new Metadata(MetadataType.Int, index + 4, streamSizeBytes),
                new Metadata(MetadataType.ByteText, index + 8, nameBytes),
                new Metadata(MetadataType.Int, 0, BitConverter.GetBytes(fileOffset))
            ));

            // Move to next stream header (align to 4-byte boundary)
            var offset = nameEndOffset + 1;
            _cursor = (offset + 3) & ~3;
        }

        var newTableStream = MetadataRoot.StreamHeaders.FirstOrDefault(x => x.Name.StringValue == "#~");

        if (newTableStream is not null)
        {
            ParseTablesHeader(newTableStream);
        }
    }

    private void ParseTablesHeader(StreamHeader tableStreamHeader)
    {
        // II.24.2.6 #~ stream
        var fileOffset = tableStreamHeader.FileOffset.IntValue;
        _cursor = fileOffset;

        var stream = new Stream(
            new Metadata(MetadataType.Int, _cursor, GetNext(4)),
            new Metadata(MetadataType.Byte, _cursor, GetNext()),
            new Metadata(MetadataType.Byte, _cursor, GetNext()),
            new Metadata(MetadataType.Byte, _cursor, GetNext()),
            new Metadata(MetadataType.Byte, _cursor, GetNext()),
            new Metadata(MetadataType.Long, _cursor, GetNext(8)),
            new Metadata(MetadataType.Long, _cursor, GetNext(8))
        );

        // Parse table row counts (for each bit set in validTables)

        // The number of 1s in the Valid bitvector determines how many values exist in Rows.
        // For hello word Valid value is: 0 0 0 1001 0 0 10101 1000111 as ValueBitString
        // Console.WriteLine(children["mask_valid"].ValueBitString());
        // Read the Valid field (64-bit number).
        // Check which bits are set (1) to know which tables exist.
        // Read the Rows array to get the row count for each existing table.

        // Store this information in a dictionary {table_name: row_count}.
        var validTables = (ulong)stream.MaskValid.LongValue;
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
            new Metadata(MetadataType.Short, _cursor, GetNext(2)),
            new Metadata(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize)),
            new Metadata(guidHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(guidHeapSize)),
            new Metadata(guidHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(guidHeapSize)),
            new Metadata(guidHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(guidHeapSize))
        );

        // II.22.38 TypeRef : 0x01
        var typeRefRowCount = rowCounts[0x01];
        var tableIndexSize1A = GetTableIndexSize(0x1A);
        for (var i = 0; i < typeRefRowCount; i++)
        {
            // page 275, ResolutionScope: 2 bits to encode tag, index 26 (0x1A)_
            var resolutionScope =
                new Metadata(tableIndexSize1A == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(tableIndexSize1A));
            var typeName = new Metadata(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize));
            var typeNamespace = new Metadata(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize));

            TyperefTable.Add(new TypeRef(resolutionScope, typeName, typeNamespace));
        }

        // II.22.37 TypeDef : 0x02
        var typeDefRowCount = rowCounts[0x02]; // Get number of TypeDefs
        var typeDefExtendsSize = GetTableIndexSize(0x01); // TypeRef Table size (for Extends column)
        var fieldTableIndexSize = GetTableIndexSize(0x04); // Field Table index size
        var methodTableIndexSize = GetTableIndexSize(0x06); // MethodDef Table index size
        for (var i = 0; i < typeDefRowCount; i++)
        {
            var flags = new Metadata(MetadataType.Int, _cursor, GetNext(4)); // 4-byte Flags
            var typeName = new Metadata(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize));
            var typeNamespace = new Metadata(stringHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(stringHeapSize));
            var extends = new Metadata(typeDefExtendsSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(typeDefExtendsSize));
            var fieldList = new Metadata(fieldTableIndexSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor,
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
            var rva = new Metadata(MetadataType.Int, _cursor, GetNext(4));
            var implFlags = new Metadata(MetadataType.Short, _cursor, GetNext(2));
            var flags = new Metadata(MetadataType.Short, _cursor, GetNext(2));
            var name = new Metadata(MetadataType.Bytes, _cursor, GetNext(stringHeapSize));
            var signature = new Metadata(blobHeapSize == 2 ? MetadataType.Short : MetadataType.Int, _cursor, GetNext(blobHeapSize));
            // TODO: FIX 
            var paramList = new Metadata(
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
            var flags = new Metadata(MetadataType.Short, _cursor, GetNext(2));
            var sequence = new Metadata(MetadataType.Bytes, _cursor, GetNext(2));
            var name = new Metadata(MetadataType.Short, _cursor, GetNext(stringHeapSize));
            ParamTable.Add(new Param(flags, sequence, name));
        }

        return;

        // The HeapSizes field is a bitvector that encodes the width of indexes into the various heaps. If bit 0 is
        // set, indexes into the “#String” heap are 4 bytes wide; if bit 1 is set, indexes into the “#GUID” heap are
        // 4 bytes wide; if bit 2 is set, indexes into the “#Blob” heap are 4 bytes wide. Conversely, if the
        // HeapSize bit for a particular heap is not set, indexes into that heap are 2 bytes wide
        int GetHeapIndexSize(string heapType)
        {
            var heapSize = stream.HeapOfSetSizes.IntValue;

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
            var maskValid = stream.MaskValid.LongValue;
            return ((maskValid & (1L << tableId)) != 0) ? 4 : 2;
        }
    }

    private byte[] GetNext(int len = 1)
    {
        var bts = FileBytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }
}

public record Metadata(MetadataType Type, int Index, byte[] Value, Dictionary<string, Metadata>? Children = null)
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