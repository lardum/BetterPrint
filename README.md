# Secure all user strings for given PE (.dll) file

This project was a personal learning experience focused on PE file parsing and bytecode analysis, within
the context of .NET DLLs.
Its basically useless but it was fun.

### Process:

- parsing PE file according to ECMA-335 specification
- interpreting extracted bytecode to list all strings that are loaded from #US heap
- replacing all bytes in #US heap with letters A to "secure" all strings
- saving new secured .dll

### How to run this thing on Windows:

- run `.\ExampleProgram\HelloWorld.exe` to see the original "Hello World!" output.
- then execute the program `dotnet run`
- run again `.\ExampleProgram\HelloWorld.exe` to see that now the dll have secured strings heap
