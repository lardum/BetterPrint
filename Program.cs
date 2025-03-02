using BetterPrint;

const string path = @"D:\code3\test\HelloWorld\bin\Debug\net8.0\HelloWorld.dll";
var parser = new Parser(path);
var il = parser.Parse();

var executor = new Executor(il);
executor.Execute();