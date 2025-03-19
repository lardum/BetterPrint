namespace BetterPrint;

/// <summary>
/// II.22.30 Module : 0x00
/// </summary>
public class MetadataModule(MetadataRecord generation, MetadataRecord name, MetadataRecord mvid, MetadataRecord encId, MetadataRecord encBaseId)
{
    /// <summary>
    /// Generation (a 2-byte value, reserved, shall be zero)
    /// </summary>
    public MetadataRecord Generation { get; init; } = generation;

    /// <summary>
    /// Name (an index into the String heap)
    /// </summary>
    public MetadataRecord Name { get; init; } = name;

    /// <summary>
    /// Mvid (an index into the Guid heap; simply a Guid used to distinguish between two
    /// versions of the same module)
    /// </summary>
    public MetadataRecord Mvid { get; init; } = mvid;

    /// <summary>
    /// EncId (an index into the Guid heap; reserved, shall be zero)
    /// </summary>
    public MetadataRecord EncId { get; init; } = encId;

    /// <summary>
    /// EncBaseId (an index into the Guid heap; reserved, shall be zero)
    /// </summary>
    public MetadataRecord EncBaseId { get; init; } = encBaseId;

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
public class TypeRef(MetadataRecord resolutionScope, MetadataRecord typeName, MetadataRecord typeNamespace)
{
    /// <summary>
    /// ResolutionScope (an index into a Module, ModuleRef, AssemblyRef or TypeRef table,
    /// or null; more precisely, a ResolutionScope (§II.24.2.6) coded index)
    /// </summary>
    public MetadataRecord ResolutionScope { get; } = resolutionScope;

    /// <summary>
    /// TypeName (an index into the String heap)
    /// </summary>
    public MetadataRecord TypeName { get; } = typeName;

    /// <summary>
    /// TypeNamespace (an index into the String heap
    /// </summary>
    public MetadataRecord TypeNamespace { get; } = typeNamespace;
}

/// <summary>
/// II.22.37 TypeDef : 0x02
/// The first row of the TypeDef table represents the pseudo class that acts as parent for functions
/// and variables defined at module scope.
/// </summary>
public class TypeDef(
    MetadataRecord flags,
    MetadataRecord typeName,
    MetadataRecord typeNamespace,
    MetadataRecord extends,
    MetadataRecord fieldList,
    MetadataRecord methodList)
{
    /// <summary>
    /// Flags (a 4-byte bitmask of type TypeAttributes, §II.23.1.15)
    /// </summary>
    public MetadataRecord Flags { get; } = flags;

    /// <summary>
    /// TypeName (an index into the String heap)
    /// </summary>
    public MetadataRecord TypeName { get; } = typeName;

    /// <summary>
    /// TypeNamespace (an index into the String heap)
    /// </summary>
    public MetadataRecord TypeNamespace { get; } = typeNamespace;

    /// <summary>
    /// Extends (an index into the TypeDef, TypeRef, or TypeSpec table; more precisely, a
    /// TypeDefOrRef (§II.24.2.6) coded index)
    /// </summary>
    public MetadataRecord Extends { get; } = extends;

    /// <summary>
    /// FieldList (an index into the Field table; it marks the first of a contiguous run of
    /// Fields owned by this Type). The run continues to the smaller of:
    /// - the last row of the Field table
    /// - the next run of Fields, found by inspecting the FieldList of the next row
    ///   in this TypeDef table
    /// </summary>
    public MetadataRecord FieldList { get; } = fieldList;

    /// <summary>
    /// MethodList (an index into the MethodDef table; it marks the first of a continguous
    /// run of Methods owned by this Type). The run continues to the smaller of:
    /// - the last row of the MethodDef table
    /// - the next run of Methods, found by inspecting the MethodList of the next
    ///   row in this TypeDef table
    /// </summary>
    public MetadataRecord MethodList { get; } = methodList;
}

/// <summary>
/// II.22.26 MethodDef : 0x06
/// </summary>
public class MethodDef(
    MetadataRecord rva,
    MetadataRecord implFlags,
    MetadataRecord flags,
    MetadataRecord name,
    MetadataRecord signature,
    MetadataRecord paramList)
{
    /// <summary>
    /// RVA (a 4-byte constant)
    /// </summary>
    public MetadataRecord Rva { get; init; } = rva;

    /// <summary>
    /// ImplFlags (a 2-byte bitmask of type MethodImplAttributes, §II.23.1.10)
    /// </summary>
    public MetadataRecord ImplFlags { get; init; } = implFlags;

    /// <summary>
    /// Flags (a 2-byte bitmask of type MethodAttributes, §II.23.1.10)
    /// </summary>
    /// <returns></returns>
    public MetadataRecord Flags { get; init; } = flags;

    /// <summary>
    /// Name (an index into the String heap)
    /// </summary>
    public MetadataRecord Name { get; init; } = name;

    /// <summary>
    /// Signature (an index into the Blob heap)
    /// </summary>
    /// <returns></returns>
    public MetadataRecord Signature { get; init; } = signature;

    public MetadataRecord ParamList { get; } = paramList;
}

/// <summary>
/// II.22.33 Param : 0x08
/// </summary>
public class Param(MetadataRecord flags, MetadataRecord sequence, MetadataRecord name)
{
    /// <summary>
    /// Flags (a 2-byte bitmask of type ParamAttributes, §II.23.1.13)
    /// </summary>
    public MetadataRecord Flags { get; } = flags;

    /// <summary>
    /// Sequence (a 2-byte constant)
    /// </summary>
    public MetadataRecord Sequence { get; } = sequence;

    /// <summary>
    /// Name (an index into the String heap)
    /// </summary>
    public MetadataRecord Name { get; } = name;
}