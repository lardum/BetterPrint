// https://stackoverflow.com/questions/3707295/how-to-programatically-find-the-bytecode-cil-in-a-net-executable-dll

using BetterPrint;

const string path = @"./HelloWorld.dll";
// ExtractIlBytes.Extract(path);

var parser = new Parser(path);
var peFile = parser.Parse();
var vm = new VirtualMachine(peFile);
vm.Run();

SecureUsHeapStrings();
return;

void SecureUsHeapStrings()
{
    var strings = peFile.MetadataRoot.StreamHeaders.First(x => x.Name.StringValue == "#US");
    var stringsOffset = strings.FileOffset.IntValue;
    var stringsSize = strings.Size.IntValue;

    var newFile = peFile.FileBytes;

    for (var i = stringsOffset + 2; i < stringsOffset + stringsSize; i++)
    {
        newFile[i] = 0x41; // A
    }

    File.WriteAllBytes("./ExampleProgram/HelloWorld.dll", newFile);
}