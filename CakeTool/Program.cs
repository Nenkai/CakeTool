using System.Text;

using CommandLine;

using Microsoft.Extensions.Logging;

using NLog;
using NLog.Extensions.Logging;

namespace CakeTool;

public class Program
{
    private static ILoggerFactory _loggerFactory;
    private static Microsoft.Extensions.Logging.ILogger _logger;

    public const string Version = "0.1.0";

    static void Main(string[] args)
    {
        _loggerFactory = LoggerFactory.Create(builder => builder.AddNLog());
        _logger = _loggerFactory.CreateLogger<Program>();

        Console.WriteLine("-----------------------------------------");
        Console.WriteLine($"- CakeTool {Version} by Nenkai");
        Console.WriteLine("-----------------------------------------");
        Console.WriteLine("- https://github.com/Nenkai");
        Console.WriteLine("- https://twitter.com/Nenkaai");
        Console.WriteLine("-----------------------------------------");
        Console.WriteLine("");

        var p = Parser.Default.ParseArguments<UnpackCakeVerbs, UnpackFileVerbs>(args)
            .WithParsed<UnpackCakeVerbs>(UnpackCake)
            .WithParsed<UnpackFileVerbs>(UnpackFile);
    }

    static void UnpackFile(UnpackFileVerbs verbs)
    {
        if (!File.Exists(verbs.InputFile))
        {
            _logger.LogError("File '{path}' does not exist", verbs.InputFile);
            return;
        }

        if (string.IsNullOrEmpty(verbs.OutputPath))
        {
            string inputFileName = Path.GetFileNameWithoutExtension(verbs.InputFile);
            verbs.OutputPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(verbs.InputFile)), $"{inputFileName}.extracted");
        }

        try
        {
            using var cake = CakeRegistryFile.Open(verbs.InputFile, _loggerFactory);
            if (cake.TypeOrParam == CakeRegistryType.External)
            {
                _logger.LogWarning("Cake is marked as external, there are no files to unpack. Files listed above are present outside the cake archive.");
                return;
            }

            _logger.LogInformation("Starting unpack process.");
            if (cake.ExtractFile(verbs.FileToUnpack, verbs.OutputPath))
                _logger.LogInformation("File extracted successfully.");
            else
                _logger.LogInformation("File was not found in cake archive.");
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Failed to unpack.");
        }
    }

    static void UnpackCake(UnpackCakeVerbs verbs)
    {
        if (!File.Exists(verbs.InputFile))
        {
            _logger.LogError("File '{path}' does not exist", verbs.InputFile);
            return;
        }

        if (string.IsNullOrEmpty(verbs.OutputPath))
        {
            string inputFileName = Path.GetFileNameWithoutExtension(verbs.InputFile);
            verbs.OutputPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(verbs.InputFile)), $"{inputFileName}.extracted");
        }

        try
        {
            using var cake = CakeRegistryFile.Open(verbs.InputFile, _loggerFactory);
            if (cake.TypeOrParam == CakeRegistryType.External)
            {
                _logger.LogWarning("Cake is marked as external, there are no files to unpack. Files listed above are present outside the cake archive.");
                return;
            }

            _logger.LogInformation("Starting unpack process.");
            cake.ExtractAll(verbs.OutputPath);
            _logger.LogInformation("Done.");

        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Failed to unpack.");
        }
    }
}

[Verb("unpack-file", HelpText = "Unpacks a specific file from a cake (.cak) archive.")]
public class UnpackFileVerbs
{
    [Option('i', "input", Required = true, HelpText = "Input .cak file")]
    public string InputFile { get; set; }

    [Option('f', "file", Required = true, HelpText = "File to unpack.")]
    public string FileToUnpack { get; set; }

    [Option('o', "output", HelpText = "Optional. Output directory.")]
    public string OutputPath { get; set; }
}

[Verb("unpack-cak", HelpText = "Unpacks all files from a cake (.cak) archive.")]
public class UnpackCakeVerbs
{
    [Option('i', "input", Required = true, HelpText = "Input .cak file")]
    public string InputFile { get; set; }

    [Option('o', "output", HelpText = "Output directory. Optional, defaults to a folder named the same as the cake (.cak) file.")]
    public string OutputPath { get; set; }
}
