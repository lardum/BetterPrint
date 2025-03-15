// https://stackoverflow.com/questions/3707295/how-to-programatically-find-the-bytecode-cil-in-a-net-executable-dll
using BetterPrint;

const string path = @"D:\code3\test\HelloWorld\bin\Debug\net8.0\HelloWorld.dll";
var parser = new Parser(path);
var il = parser.Parse();

var codeSection = il["sections"][".text"];
var rawDataPointer = codeSection.Children!["pointer_to_raw_data"].IntValue;
var rawDataSize = codeSection.Children!["size_of_raw_data"].IntValue;
var codeBytes = parser.FileBytes.Skip(rawDataPointer).Take(rawDataSize).ToArray();

var executor = new VirtualMachine(il);
// executor.Execute(codeBytes);