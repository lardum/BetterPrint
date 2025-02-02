using BetterPrint;

const string path = @"D:\code\test\ConsoleAppTest\bin\Debug\net9.0\ConsoleAppTest.dll";
// const string path86 = @"D:\code\test\ConsoleAppTest\bin\x86\Debug\net9.0\ConsoleAppTest.dll";
var p = new Parser(path);
p.Parse();