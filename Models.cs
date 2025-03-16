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