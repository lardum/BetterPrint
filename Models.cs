using System.Buffers.Binary;

namespace BetterPrint;

/// <summary>
/// II.25.2.1 MS-DOS header
/// </summary>
public class DosHeader(Metadata rawBytes)
{
    public Metadata RawBytes { get; } = rawBytes;

    public uint GetLfanew()
        => BinaryPrimitives.ReadUInt32LittleEndian(RawBytes.Value.Skip(60).Take(4).ToArray());
}

/// <summary>
/// II.25.2.2 PE file header
/// </summary>
public record PeFileHeader(
    Metadata PeSignature,
    Metadata Machine,
    Metadata NumberOfSections,
    Metadata TimeDateStamp,
    Metadata PointerToSymbolTable,
    Metadata NumberOfSymbols,
    Metadata OptionalHeaderSize,
    Metadata Characteristics
);

/// <summary>
/// II.25.2.3 PE optional header
/// </summary>
public record PeOptionalHeader(
    Metadata Magic,
    Metadata MajorLinkerVersion,
    Metadata MinorLinkerVersion,
    Metadata SizeOfCode,
    Metadata SizeOfInitializedData,
    Metadata SizeofUnInitializedData,
    Metadata EntryPointRva,
    Metadata BaseOfCode,
    Metadata BaseOfData,
    Metadata NtFields, // II.25.2.3.2 PE header Windows NT-specific fields
    Metadata ExportTable,
    Metadata ImportTable,
    Metadata ResourceTable,
    Metadata ExceptionTable,
    Metadata CertificateTable,
    Metadata BaseRelocationTable,
    Metadata Debug,
    Metadata Copyright,
    Metadata GlobalPtr,
    Metadata TlsTable,
    Metadata LoadConfigTable,
    Metadata BoundImport,
    Metadata Iat,
    Metadata DelayImportDescriptor,
    Metadata ClrRuntimeHeaderRva,
    Metadata ClrRuntimeHeaderSize,
    Metadata Reserved
);

/// <summary>
/// II.25.3 Section headers
/// </summary>
public record SectionHeader(
    Metadata Name,
    Metadata VirtualSize,
    Metadata VirtualAddress,
    Metadata SizeOfRawData,
    Metadata PointerToRawData,
    Metadata PointerToRelocations,
    Metadata PointerToLineNumbers,
    Metadata NumberOfRelocations,
    Metadata NumberOfLineNumbers,
    Metadata Characteristics
);

/// <summary>
/// II.25.3.3 CLI header
/// </summary>
public record CliHeader(
    Metadata SizeOfHeader,
    Metadata MajorRuntimeVersion,
    Metadata MinorRuntimeVersion,
    Metadata MetadataRva,
    Metadata MetadataSize,
    Metadata Flags,
    Metadata EntryPointToken,
    Metadata ResourcesRva,
    Metadata ResourcesSize,
    Metadata StrongNameSignatureRva,
    Metadata StrongNameSignatureSize,
    Metadata CodeManagerTableRva,
    Metadata CodeManagerTableSize,
    Metadata ExportAddressTableJumpsRva,
    Metadata ExportAddressTableJumpsSize,
    Metadata ManagedNativeHeaderRva,
    Metadata ManagedNativeHeaderSize
);

public class MetadataRoot(
    Metadata Signature,
    Metadata MajorVersion,
    Metadata MinorVersion,
    Metadata Reserved,
    Metadata VisionLength
)
{
    public Metadata Flags { get; set; } = null!;
    public Metadata NumberOfStreams { get; set; } = null!;
    public Metadata VersionString { get; set; } = null!;
    public List<StreamHeader> StreamHeaders { get; set; } = [];
}

public record StreamHeader(
    Metadata Offset,
    Metadata Size,
    Metadata Name,
    Metadata FileOffset
);

public record Stream(
    Metadata Reserved,
    Metadata MajorVersion,
    Metadata MinorVersion,
    Metadata HeapOfSetSizes,
    Metadata Reserved2,
    Metadata MaskValid,
    Metadata MaskSorted
);

/// <summary>
/// II.22.30 Module : 0x00
/// </summary>
public class MetadataModule(Metadata generation, Metadata name, Metadata mvid, Metadata encId, Metadata encBaseId)
{
    /// <summary>
    /// Generation (a 2-byte value, reserved, shall be zero)
    /// </summary>
    public Metadata Generation { get; } = generation;

    /// <summary>
    /// Name (an index into the String heap)
    /// </summary>
    public Metadata Name { get; } = name;

    /// <summary>
    /// Mvid (an index into the Guid heap; simply a Guid used to distinguish between two
    /// versions of the same module)
    /// </summary>
    public Metadata Mvid { get; } = mvid;

    /// <summary>
    /// EncId (an index into the Guid heap; reserved, shall be zero)
    /// </summary>
    public Metadata EncId { get; } = encId;

    /// <summary>
    /// EncBaseId (an index into the Guid heap; reserved, shall be zero)
    /// </summary>
    public Metadata EncBaseId { get; } = encBaseId;

    /// <summary>
    /// 1. The Module table shall contain one and only one row [ERROR]
    /// 2. Name shall index a non-empty string. This string should match exactly any
    /// corresponding ModuleRef.Name string that resolves to this module. [ERROR]
    /// 3. Mvid shall index a non-null GUID in the Guid heap [ERROR]
    /// </summary>
    // public bool Valid()
    // {
    //     return true;
    // }
}

/// <summary>
/// II.22.38 TypeRef : 0x01
/// </summary>
public class TypeRef(Metadata resolutionScope, Metadata typeName, Metadata typeNamespace)
{
    /// <summary>
    /// ResolutionScope (an index into a Module, ModuleRef, AssemblyRef or TypeRef table,
    /// or null; more precisely, a ResolutionScope (§II.24.2.6) coded index)
    /// </summary>
    public Metadata ResolutionScope { get; } = resolutionScope;

    /// <summary>
    /// TypeName (an index into the String heap)
    /// </summary>
    public Metadata TypeName { get; } = typeName;

    /// <summary>
    /// TypeNamespace (an index into the String heap
    /// </summary>
    public Metadata TypeNamespace { get; } = typeNamespace;
}

/// <summary>
/// II.22.37 TypeDef : 0x02
/// The first row of the TypeDef table represents the pseudo class that acts as parent for functions
/// and variables defined at module scope.
/// </summary>
public class TypeDef(
    Metadata flags,
    Metadata typeName,
    Metadata typeNamespace,
    Metadata extends,
    Metadata fieldList,
    Metadata methodList)
{
    /// <summary>
    /// Flags (a 4-byte bitmask of type TypeAttributes, §II.23.1.15)
    /// </summary>
    public Metadata Flags { get; } = flags;

    /// <summary>
    /// TypeName (an index into the String heap)
    /// </summary>
    public Metadata TypeName { get; } = typeName;

    /// <summary>
    /// TypeNamespace (an index into the String heap)
    /// </summary>
    public Metadata TypeNamespace { get; } = typeNamespace;

    /// <summary>
    /// Extends (an index into the TypeDef, TypeRef, or TypeSpec table; more precisely, a
    /// TypeDefOrRef (§II.24.2.6) coded index)
    /// </summary>
    public Metadata Extends { get; } = extends;

    /// <summary>
    /// FieldList (an index into the Field table; it marks the first of a contiguous run of
    /// Fields owned by this Type). The run continues to the smaller of:
    /// - the last row of the Field table
    /// - the next run of Fields, found by inspecting the FieldList of the next row
    ///   in this TypeDef table
    /// </summary>
    public Metadata FieldList { get; } = fieldList;

    /// <summary>
    /// MethodList (an index into the MethodDef table; it marks the first of a continguous
    /// run of Methods owned by this Type). The run continues to the smaller of:
    /// - the last row of the MethodDef table
    /// - the next run of Methods, found by inspecting the MethodList of the next
    ///   row in this TypeDef table
    /// </summary>
    public Metadata MethodList { get; } = methodList;
}

/// <summary>
/// II.22.26 MethodDef : 0x06
/// </summary>
public class MethodDef(
    Metadata rva,
    Metadata implFlags,
    Metadata flags,
    Metadata name,
    Metadata signature,
    Metadata paramList)
{
    /// <summary>
    /// RVA (a 4-byte constant)
    /// </summary>
    public Metadata Rva { get; init; } = rva;

    /// <summary>
    /// ImplFlags (a 2-byte bitmask of type MethodImplAttributes, §II.23.1.10)
    /// </summary>
    public Metadata ImplFlags { get; init; } = implFlags;

    /// <summary>
    /// Flags (a 2-byte bitmask of type MethodAttributes, §II.23.1.10)
    /// </summary>
    /// <returns></returns>
    public Metadata Flags { get; init; } = flags;

    /// <summary>
    /// Name (an index into the String heap)
    /// </summary>
    public Metadata Name { get; init; } = name;

    /// <summary>
    /// Signature (an index into the Blob heap)
    /// </summary>
    /// <returns></returns>
    public Metadata Signature { get; init; } = signature;

    public Metadata ParamList { get; } = paramList;
}

/// <summary>
/// II.22.33 Param : 0x08
/// </summary>
public class Param(Metadata flags, Metadata sequence, Metadata name)
{
    /// <summary>
    /// Flags (a 2-byte bitmask of type ParamAttributes, §II.23.1.13)
    /// </summary>
    public Metadata Flags { get; } = flags;

    /// <summary>
    /// Sequence (a 2-byte constant)
    /// </summary>
    public Metadata Sequence { get; } = sequence;

    /// <summary>
    /// Name (an index into the String heap)
    /// </summary>
    public Metadata Name { get; } = name;
}