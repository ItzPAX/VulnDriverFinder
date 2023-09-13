using Poushec.UpdateCatalogParser;
using Poushec.UpdateCatalogParser.Models;
using System;
using System.IO;
using System.Net;
using Microsoft.Deployment.Compression.Cab;
using PeNet;
using System.Text.RegularExpressions;

static void WriteColor(string message, ConsoleColor color)
{
    var pieces = Regex.Split(message, @"(\[[^\]]*\])");

    for (int i = 0; i < pieces.Length; i++)
    {
        string piece = pieces[i];

        if (piece.StartsWith("[") && piece.EndsWith("]"))
        {
            Console.ForegroundColor = color;
            piece = piece.Substring(1, piece.Length - 2);
        }

        Console.Write(piece);
        Console.ResetColor();
    }

    Console.WriteLine();
}

string[] sus_imports =
{
    "ZwMapViewOfSection",
    "MmMapIoSpace",
    "MmGetPhysicalAddress",
    "IoCreateDevice",
    "IofCompleteRequest"
};
void ProcessFile(string path)
{
    var filename = path.Split('\\').Last();
    var extension = path.Split('.').Last();
    if (extension != "sys")
        return;

    var header = new PeFile(path);
    if (header.ImageNtHeaders.FileHeader.Machine != PeNet.Header.Pe.MachineType.Amd64)
        return;
    //Console.WriteLine($"Scanning {path}");

    var imports = header.ImportedFunctions;
    var pot_vuln = false;
    List<string> sus_imported = new List<string>();

    foreach (var import in sus_imports)
    {
        foreach (var p_import in imports)
        {
            if (p_import.Name == import)
            {
                pot_vuln = true;
                sus_imported.Add(p_import.Name);
            }
        }
    }

    if (!pot_vuln)
        return;

    // minimum we need is 3 imports {create, complete, mapview}
    if (sus_imported.Count < 4)
        return;

    if (!sus_imported.Contains("IoCreateDevice") && !sus_imported.Contains("IofCompleteRequest"))
        return;

    var file = File.ReadAllBytes(path);
    if (file.Length > 100000)
        return;

    Directory.CreateDirectory(Directory.GetCurrentDirectory() + "\\check_me");

    if (sus_imported.Contains("MmMapIoSpace") && (!sus_imported.Contains("ZwMapViewOfSection") || !sus_imported.Contains("MmGetPhysicalAddress")))
        return;

    WriteColor($"Found potentially vulnerable driver: [{filename}]", ConsoleColor.Green);
    foreach(var sus_imp in sus_imported)
    {
        WriteColor($"    Imports: [{sus_imp}]", ConsoleColor.Red);
    }

    if (!File.Exists(Directory.GetCurrentDirectory() + "\\check_me\\" + header.ImageNtHeaders.FileHeader.TimeDateStamp + "_" + filename))
        File.Copy(path, Directory.GetCurrentDirectory() + "\\check_me\\" + header.ImageNtHeaders.FileHeader.TimeDateStamp + "_" + filename);
}

void ProcessDirectory(string targetDirectory)
{
    // Process the list of files found in the directory.
    string[] fileEntries = Directory.GetFiles(targetDirectory);
    foreach (string fileName in fileEntries)
        ProcessFile(fileName);

    // Recurse into subdirectories of this directory.
    string[] subdirectoryEntries = Directory.GetDirectories(targetDirectory);
    foreach (string subdirectory in subdirectoryEntries)
        ProcessDirectory(subdirectory);
}

var client = new HttpClient();
var catalogClient = new CatalogClient(client, 3);

Directory.CreateDirectory(Directory.GetCurrentDirectory() + "\\downloads");

Console.Write("Input search query: ");
var query = Console.ReadLine();

var results = await catalogClient.SendSearchQueryAsync(query);

Directory.CreateDirectory(Directory.GetCurrentDirectory() + "\\downloads\\" + query);

Console.WriteLine($"Scanning through {results.Count} items");
    int i = 1;

foreach (var item in results)
{
    Console.WriteLine($"[{i}/{results.Count}] Processing {item.Title} ({item.Size})");
    if (item.Classification.Contains("Driver"))
    {
        var path = Directory.GetCurrentDirectory() + "\\downloads\\" + query + "\\" + item.UpdateID;
        if (Directory.Exists(path) || item.SizeInBytes > 20971524)
        {
            i++;
            continue;
        }
        UpdateBase update_details;

        try
        {
            update_details = await catalogClient.GetUpdateDetailsAsync(item);
        }
        catch
        {
            Console.WriteLine("Fucked up");
            i++;
            continue;
        }

        using (var dl_client = new WebClient())
        {
            dl_client.DownloadFile(update_details.DownloadLinks[0], path + ".cab");

            CabInfo cab = new CabInfo(path + ".cab");
            Directory.CreateDirectory(path);
            cab.Unpack(path);
            File.Delete(path + ".cab");
            ProcessDirectory(path);

            //cleanup so we dont have 100000TB of crap
            DirectoryInfo di = new DirectoryInfo(path);
            try
            {
                foreach (FileInfo file in di.GetFiles())
                {
                    file.Delete();
                }
                foreach (DirectoryInfo dir in di.GetDirectories())
                {
                    dir.Delete(true);
                }
            }
            catch { }
        }
    }
    i++;
}

Console.WriteLine("done.");
Console.ReadKey();