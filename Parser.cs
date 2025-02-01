using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BetterPrint;

public class Parser(string path)
{
    private readonly int _len = path.Length;
    private readonly byte[] _fileBytes = File.ReadAllBytes(path);
    private int _cursor = 0;

    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    // https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
    // II.25.2.1 MS-DOS header
    public void Parse()
    {
        var parsedIl = new Dictionary<string, IlRecord>();
        parsedIl.Add(Consts.PeParts.DosHeader, new IlRecord(TokenType.ByteText, GetNext(128), _cursor - 128, _cursor));
        parsedIl.Add("file_header", new IlRecord(TokenType.ByteText, GetNext(2), _cursor - 2, _cursor));

        Console.WriteLine(string.Join(" ", _fileBytes.Skip(128).Take(10).Select(x => x.ToString("X"))));

        // var a = _fileBytes.Skip(60).Take(4).ToArray();
        var lfanewOffset = BinaryPrimitives.ReadInt32LittleEndian(_fileBytes.Skip(60).Take(4).ToArray());
        var a = _fileBytes.Skip(lfanewOffset).Take(4).ToArray();

        // Console.WriteLine("Offset " + lfanewOffset);
        // Console.WriteLine(string.Join(" ", _fileBytes.Skip(128 + lfanewOffset).Take(2).Select(x => x.ToString())));
        // Console.WriteLine(ReadInt16(_fileBytes.Skip(128).Take(2).ToArray()));
        //
        // Console.WriteLine(parsedIl["file_header"].ValueAsciiString());
        // Console.WriteLine(parsedIl["file_header"].ValueHexString());
        // Console.WriteLine(parsedIl["file_header"].ValueBitString());
    }

    private byte[] GetNext(int len = 1)
    {
        var bts = _fileBytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }

    private short ReadInt16(byte[] bytes) => BinaryPrimitives.ReadInt16BigEndian(bytes);
}

static class Consts
{
    public class PeParts
    {
        public const string DosHeader = "dos_header";
    }
}

record IlRecord(TokenType Type, byte[] Value, int S, int E)
{
    public string ValueAsciiString() => Encoding.ASCII.GetString(Value);
    public string ValueHexString() => string.Join(" ", Value.Select(x => x.ToString("X")));
    public string ValueBitString() => string.Join(" ", Value.Select(x => x.ToString("B")));
}

internal enum TokenType
{
    ByteText
}