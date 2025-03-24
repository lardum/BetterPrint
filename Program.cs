// https://stackoverflow.com/questions/3707295/how-to-programatically-find-the-bytecode-cil-in-a-net-executable-dll

using System.Text;
using BetterPrint;

const string path = @"./HelloWorld.dll";
// ExtractIlBytes.Extract(path);

var parser = new Parser(path);
var peFile = parser.Parse();
var vm = new VirtualMachine(peFile);
vm.Run();

SecureStrings();
return;

Console.WriteLine(BitConverter.ToString(peFile.FileBytes.Skip(1178).Take(100).ToArray()));
File.WriteAllBytes("./ExampleProgram/HelloWorld.dll", peFile.FileBytes);

return;

void SecureStrings()
{
    var strings = peFile.MetadataRoot.StreamHeaders.First(x => x.Name.StringValue == "#Strings");

    var stringsOffset = 1721; // strings.FileOffset.IntValue;
    var stringsSize = 26; // strings.Size.IntValue;

    var newFile = peFile.FileBytes;
    // Console.WriteLine(BitConverter.ToString(newFile.Skip(stringsOffset).Take(stringsSize).ToArray()));
    // Console.WriteLine(Encoding.UTF8.GetString(newFile.Skip(stringsOffset).Take(stringsSize).ToArray()));
    // return;

    for (var i = stringsOffset; i < stringsOffset + stringsSize; i++)
    {
        // var b = newFile[i];
        // if (b != 0)
        {
            newFile[i] = 0x41; // A
            // that causes No string associated with token.
        }
    }

    // Console.WriteLine(BitConverter.ToString(newFile));
    File.WriteAllBytes("./ExampleProgram/HelloWorld.dll", newFile);
}