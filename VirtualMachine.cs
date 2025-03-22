using System.Buffers.Binary;

namespace BetterPrint;

// https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes?view=net-9.0
// https://github.com/dotnet/runtime/blob/1d1bf92fcf43aa6981804dc53c5174445069c9e4/src/libraries/System.Private.CoreLib/src/System/Reflection/Emit/OpCodes.cs
// https://en.wikipedia.org/wiki/List_of_CIL_instructions
public class VirtualMachine
{
    private byte[] _bytecode = [];

    public void Execute(byte[] code)
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

        _bytecode = code;
        var cursor = 0;

        while (cursor < _bytecode.Length)
        {
            var opcode = GetNext();

            switch (opcode)
            {
                case 0x00:
                    break;
                case 0x72:
                    var table = BinaryPrimitives.ReadUInt32LittleEndian(_bytecode.Skip(cursor).Take(4).ToArray());
                    var tableIndex = (int)(table & 0x00FFFFFF);
                    var tableType = GetTokenType((int)(table >> 24));
                    Console.WriteLine($"ldstr, {table}");
                    break;
                default:
                    Console.WriteLine($"Unknown opcode {opcode:X2}");
                    break;
            }
        }

        return;

        byte GetNext()
        {
            var res = _bytecode.Skip(cursor).Take(1).First();
            cursor++;
            return res;
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