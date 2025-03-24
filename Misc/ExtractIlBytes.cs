using Mono.Cecil;
using Mono.Cecil.Cil;

namespace BetterPrint.Misc;

public class ExtractIlBytes
{
    public static void Extract(string assemblyPath)
    {
        string typeName = "YourNamespace.YourClass"; // Fully qualified class name
        string methodName = "Program.Main"; // Method to extract IL from

        // Load the assembly
        var assembly = AssemblyDefinition.ReadAssembly(assemblyPath);

        // Find the target method
        var methods = assembly.MainModule
            .Types.SelectMany(x => x.Methods)
            .ToList();

        foreach (var method in methods)
        {
            // Extract IL bytes
            if (!method.HasBody) continue;
            var ilBytes = method.Body.Instructions.SelectMany(i => i.GetILBytes()).ToArray();
            Console.WriteLine($"Raw IL bytes for {methodName}: Len: {method.Body.CodeSize} | {BitConverter.ToString(ilBytes)}");
        }
    }
}

// Extension method to get raw IL bytes from an instruction
public static class IlHelper
{
    public static byte[] GetILBytes(this Instruction instr)
    {
        using (var ms = new System.IO.MemoryStream())
        {
            using (var writer = new System.IO.BinaryWriter(ms))
            {
                writer.Write(instr.OpCode.Value);
                if (instr.Operand != null)
                {
                    if (instr.Operand is byte b) writer.Write(b);
                    else if (instr.Operand is short s) writer.Write(s);
                    else if (instr.Operand is int i) writer.Write(i);
                    else if (instr.Operand is long l) writer.Write(l);
                    else if (instr.Operand is sbyte sb) writer.Write(sb);
                    else if (instr.Operand is float f) writer.Write(f);
                    else if (instr.Operand is double d) writer.Write(d);
                    // Add more cases as needed
                }
            }

            return ms.ToArray();
        }
    }
}