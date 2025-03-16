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
    public MetadataRecord ResolutionScope { get; } = resolutionScope;
    public MetadataRecord TypeName { get; } = typeName;
    public MetadataRecord TypeNamespace { get; } = typeNamespace;
}

/// <summary>
/// II.22.26 MethodDef : 0x06
/// </summary>
public class MethodDef(MetadataRecord rva, MetadataRecord implFlags, MetadataRecord flags, MetadataRecord name, MetadataRecord signature)
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
}