namespace BetterPrint;

/// <summary>
/// II.22.30 Module : 0x00
/// </summary>
public class MetadataModule
{
    /// <summary>
    /// Generation (a 2-byte value, reserved, shall be zero)
    /// </summary>
    public MetadataRecord Generation { get; set; }

    /// <summary>
    /// Name (an index into the String heap)
    /// </summary>
    public MetadataRecord Name { get; set; }

    /// <summary>
    /// Mvid (an index into the Guid heap; simply a Guid used to distinguish between two
    /// versions of the same module)
    /// </summary>
    public MetadataRecord Mvid { get; set; }

    /// <summary>
    /// EncId (an index into the Guid heap; reserved, shall be zero)
    /// </summary>
    public MetadataRecord EncId { get; set; }

    /// <summary>
    /// EncBaseId (an index into the Guid heap; reserved, shall be zero)
    /// </summary>
    public MetadataRecord EncBaseId { get; set; }
}