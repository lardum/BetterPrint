using System.Text;

namespace BetterPrint;

public class Parser(string path)
{
    private readonly int _len = path.Length;
    private readonly byte[] _fileBytes = File.ReadAllBytes(path);
    private int _cursor = 0;

    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    // https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
    public void Parse()
    {
        var parsedIl = new Dictionary<string, IlRecord>();
        var dosHeader = GetNext(2);

        parsedIl.Add(ProjectConsts.PeParts.DosHeader, new IlRecord(TokenType.ByteText, dosHeader, _cursor - 2, _cursor));

        Console.WriteLine(parsedIl[ProjectConsts.PeParts.DosHeader]);
    }

    private byte[] GetNext(int len = 0)
    {
        var bts = _fileBytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }
}

static class ProjectConsts
{
    public class PeParts
    {
        public const string DosHeader = "dos_header";
    }
}

record IlRecord(TokenType Type, byte[] Value, int S, int E)
{
    public override string ToString()
    {
        if (Type == TokenType.ByteText)
        {
            return Encoding.ASCII.GetString(Value);
        }

        return base.ToString() ?? string.Empty;
    }
}

internal enum TokenType
{
    ByteText
}