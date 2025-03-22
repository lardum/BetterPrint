// https://stackoverflow.com/questions/3707295/how-to-programatically-find-the-bytecode-cil-in-a-net-executable-dll

using BetterPrint;

// const string path = @"D:\code3\test\HelloWorld\bin\Debug\net8.0\HelloWorld.dll";
const string path = @"./HelloWorld.dll";

var parser = new Parser(path);
var metadata = parser.Parse();