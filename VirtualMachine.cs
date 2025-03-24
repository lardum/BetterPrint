using System.Buffers.Binary;
using System.Text;

namespace BetterPrint;

// https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes?view=net-9.0
// https://github.com/dotnet/runtime/blob/1d1bf92fcf43aa6981804dc53c5174445069c9e4/src/libraries/System.Private.CoreLib/src/System/Reflection/Emit/OpCodes.cs
// https://en.wikipedia.org/wiki/List_of_CIL_instructions
public class VirtualMachine
{
    private readonly PeFile _peFile;
    private readonly byte[] _bytecode;
    private readonly byte[] _strings;
    private readonly int _stringsOffset;

    public VirtualMachine(PeFile peFile)
    {
        _peFile = peFile;
        _bytecode = peFile.FileBytes;

        var strings = _peFile.MetadataRoot.StreamHeaders.First(x => x.Name.StringValue == "#Strings");
        _stringsOffset = strings.FileOffset.IntValue;
        var stringsSize = strings.Size.IntValue;
        _strings = _bytecode.Skip(_stringsOffset).Take(stringsSize).ToArray();
    }

    public void Run()
    {
        var codeSection = _peFile.SectionHeaders.First(x => x.Name.StringValue.Trim('\0') == ".text");

        var virtualAddress = codeSection.VirtualAddress.IntValue;
        var pointerToRawData = codeSection.PointerToRawData.IntValue;

        foreach (var mdt in _peFile.MethodDefTable)
        {
            var fileOffset = mdt.Rva.IntValue - virtualAddress + pointerToRawData;
            var firstByte = _bytecode[fileOffset];
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
                codeSize = BinaryPrimitives.ReadInt32LittleEndian(_bytecode.AsSpan(codeOffset + 4));
            }

            var methodEnd = codeOffset + codeSize;

            SecureStrings(_bytecode.Skip(codeOffset).Take(methodEnd - codeOffset).ToArray());
        }
    }

    private void SecureStrings(byte[] code)
    {
        // For hello world:
        // 00-72-01-00-00-70-28-0D-00-00-0A-00-2A
        // 00 -> nop
        // 72 -> ldstr (read string) 
        // take next 4 bytes 01-00-00-70
        // 28 -> call
        // 0D-00-00-0A
        // 00 -> nop
        // 2A -> ret (return) 

        Console.WriteLine($"Len: {code.Length} | " + BitConverter.ToString(code));

        var cursor = 0;

        while (cursor < code.Length)
        {
            var opcode = GetNext();

            switch (opcode)
            {
                case 0x00:
                    break;
                case 0x72:
                    var table = BinaryPrimitives.ReadUInt32LittleEndian(code.Skip(cursor).Take(4).ToArray());
                    var tableIndex = (int)(table & 0x00FFFFFF);
                    var tableType = GetTokenType((int)(table >> 24)); // strings
                    var stringValue = GetStringValue(tableIndex);
                    Console.WriteLine($"ldstr, {table} and string value: {stringValue} which is now secured");
                    cursor += 4;
                    break;
                default:
                    // Console.WriteLine($"Unknown opcode {opcode:X2}");
                    break;
            }
        }

        return;

        byte GetNext()
        {
            var res = code.Skip(cursor).Take(1).First();
            cursor++;
            return res;
        }
    }

    private string GetStringValue(int index)
    {
        List<int> stringStarts = [];
        var currentStart = 0;
        var len = _strings.Length;

        while (currentStart < len)
        {
            if (_strings[currentStart] == 0)
            {
                stringStarts.Add(currentStart);
            }

            currentStart++;
        }

        var startIndex = stringStarts[index] + 1;
        var endIndex = stringStarts[index + 1];

        if (startIndex >= len || endIndex > len || startIndex > endIndex)
        {
            return string.Empty;
        }

        // idk the hello world string is in blob not in #string heap
        SecureStringBytes(startIndex + _stringsOffset, endIndex + _stringsOffset);

        return Encoding.UTF8.GetString(_strings, startIndex, endIndex - startIndex);
    }

    private void SecureStringBytes(int startIndex, int endIndex)
    {
        for (var i = startIndex + 2; i < endIndex; i++)
        {
            var b = _peFile.FileBytes[i];
            if (b != 0)
            {
                _peFile.FileBytes[i] = 0x41; // A
            }
        }
    }

    private TokenType GetTokenType(int token) => (TokenType)(token & 0xff000000);
}

public enum TokenType : uint
{
    Module = 0x00000000,
    TypeRef = 0x01000000,
    TypeDef = 0x02000000,
    Field = 0x04000000,
    Method = 0x06000000,
    Param = 0x08000000,
    InterfaceImpl = 0x09000000,
    MemberRef = 0x0a000000,
    CustomAttribute = 0x0c000000,
    Permission = 0x0e000000,
    Signature = 0x11000000,
    Event = 0x14000000,
    Property = 0x17000000,
    ModuleRef = 0x1a000000,
    TypeSpec = 0x1b000000,
    Assembly = 0x20000000,
    AssemblyRef = 0x23000000,
    File = 0x26000000,
    ExportedType = 0x27000000,
    ManifestResource = 0x28000000,
    GenericParam = 0x2a000000,
    MethodSpec = 0x2b000000,
    GenericParamConstraint = 0x2c000000,

    Document = 0x30000000,
    MethodDebugInformation = 0x31000000,
    LocalScope = 0x32000000,
    LocalVariable = 0x33000000,
    LocalConstant = 0x34000000,
    ImportScope = 0x35000000,
    StateMachineMethod = 0x36000000,
    CustomDebugInformation = 0x37000000,

    String = 0x70000000,
}