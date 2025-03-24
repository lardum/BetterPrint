// https://stackoverflow.com/questions/3707295/how-to-programatically-find-the-bytecode-cil-in-a-net-executable-dll

using BetterPrint;

const string path = @"./HelloWorld.dll";
// ExtractIlBytes.Extract(path);

var parser = new Parser(path);
var peFile = parser.Parse();
var vm = new VirtualMachine(peFile);
vm.Run();


File.WriteAllBytes("./ExampleProgram/HelloWorld.dll", peFile.FileBytes);