using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using McMaster.Extensions.CommandLineUtils;
using YaraSharp;

namespace SilkETW
{
    [SuppressDefaultHelpOption]
    class Silk
    {
        // We are using -> McMaster.Extensions.CommandLineUtils
        // https://github.com/natemcmaster/CommandLineUtils/
        [Option("-h|--help", CommandOptionType.NoValue)]
        public Boolean Help { get; }

        [Option("-s|--silk", CommandOptionType.NoValue)]
        public Boolean Trivia { get; }

        [Option("-t|--type", CommandOptionType.SingleValue)]
        public CollectorType CollectorType { get; }

        [Option("-kk|--kernelkeyword", CommandOptionType.SingleValue)]
        public KernelKeywords KernelKeywords { get; }

        [Option("-ot|--outputtype", CommandOptionType.SingleValue)]
        public OutputType OutputType { get; }

        [Option("-p|--path", CommandOptionType.SingleValue)]
        public String Path { get; set; } = String.Empty;

        [Option("-pn|--providername", CommandOptionType.SingleValue)]
        public String ProviderName { get; } = String.Empty;

        [Option("-l|--level", CommandOptionType.SingleValue)]
        public UserTraceEventLevel UserTraceEventLevel { get; } = UserTraceEventLevel.Informational; // Default to Informational

        [Option("-uk|--userkeyword", CommandOptionType.SingleValue)]
        public String UserKeywords { get; } = "0xffffffffffffffff"; // Default to [ulong]matchAnyKeywords
                                                                    // We need some tricks here because the parser interprets
                                                                    // cmdline hex as a string...

        [Option("-f|--filter", CommandOptionType.SingleValue)]
        public FilterOption FilterOption { get; } = FilterOption.None; // Default to no filter

        [Option("-fv|--filtervalue", CommandOptionType.SingleValue)]
        public String FilterValue { get; } = String.Empty;

        [Option("-y|--yara", CommandOptionType.SingleValue)]
        public String YaraScan { get; } = String.Empty;

        [Option("-yo|--yaraoptions", CommandOptionType.SingleValue)]
        public YaraOptions YaraOptions { get; }


        public static void Main(string[] args)
        {
            SilkUtility.PrintLogo();
            if (ArgumentEscaper.EscapeAndConcatenate(args).Length == 0)
            {
                SilkUtility.PrintHelp();
                return;
            }
            CommandLineApplication.Execute<Silk>(args);
        }

        private void OnExecute()
        {
            // Print custom help
            if (Help)
            {
                SilkUtility.PrintHelp();
                return;
            }

            // Print trivia
            if (Trivia)
            {
                SilkUtility.PrintTrivia();
                return;
            }

            // What type of collector are we creating?
            if (CollectorType == CollectorType.None)
            {
                SilkUtility.ReturnStatusMessage("[!] Select valid collector type (-t|--type)", ConsoleColor.Red);
                return;
            }
            else if (CollectorType == CollectorType.Kernel)
            {
                if (KernelKeywords == KernelKeywords.None)
                {
                    SilkUtility.ReturnStatusMessage("[!] Select valid Kernel keyword (-kk|--kernelkeyword)", ConsoleColor.Red);
                    return;
                }
            }
            else if (CollectorType == CollectorType.User)
            {
                if (String.IsNullOrEmpty(ProviderName))
                {
                    SilkUtility.ReturnStatusMessage("[!] Specify valid provider name (-pn|--providername)", ConsoleColor.Red);
                    return;
                }

                // Check and convert UserKeywords to ulong
                if (String.IsNullOrEmpty(UserKeywords))
                {
                    SilkUtility.ReturnStatusMessage("[!] Specify valid keywords mask (-uk|--userkeyword)", ConsoleColor.Red);
                    return;
                }
                else
                {
                    try
                    {
                        if (UserKeywords.StartsWith("0x"))
                        {
                            SilkUtility.UlongUserKeywords = Convert.ToUInt64(UserKeywords, 16);
                        }
                        else
                        {
                            SilkUtility.UlongUserKeywords = Convert.ToUInt64(UserKeywords);
                        }
                    }
                    catch
                    {
                        SilkUtility.ReturnStatusMessage("[!] Specify valid keywords mask (-uk|--userkeyword)", ConsoleColor.Red);
                        return;
                    }
                }
            }

            // Validate output parameters
            if (OutputType == OutputType.None)
            {
                SilkUtility.ReturnStatusMessage("[!] Select valid output type (-ot|--outputtype)", ConsoleColor.Red);
                return;
            }
            else
            {
                if (OutputType == OutputType.file)
                {
                    if (String.IsNullOrEmpty(Path))
                    {
                        SilkUtility.ReturnStatusMessage("[!] Specify valid output file (-p|--path)", ConsoleColor.Red);
                        return;
                    }
                    else
                    {
                        try
                        {
                            FileAttributes CheckAttrib = File.GetAttributes(Path);
                            if (CheckAttrib.HasFlag(FileAttributes.Directory))
                            {
                                SilkUtility.ReturnStatusMessage("[!] Specify an output filepath not a directory (-p|--path)", ConsoleColor.Red);
                                return;
                            }
                        }
                        catch { }
                        if (!(Directory.Exists(System.IO.Path.GetDirectoryName(Path))))
                        {
                            SilkUtility.ReturnStatusMessage("[!] Invalid path specified (-p|--path)", ConsoleColor.Red);
                            return;
                        }
                        else
                        {
                            if (!(SilkUtility.DirectoryHasPermission(System.IO.Path.GetDirectoryName(Path), System.Security.AccessControl.FileSystemRights.Write)))
                            {
                                SilkUtility.ReturnStatusMessage("[!] No write access to output path (-p|--path)", ConsoleColor.Red);
                                return;
                            }
                        }
                    }
                }
                else if (OutputType == OutputType.url)
                {
                    if (String.IsNullOrEmpty(Path))
                    {
                        SilkUtility.ReturnStatusMessage("[!] Specify valid URL (-p|--path)", ConsoleColor.Red);
                        return;
                    }
                    else
                    {
                        Uri uriResult;
                        bool UrlResult = Uri.TryCreate(Path, UriKind.Absolute, out uriResult) && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
                        if (!UrlResult)
                        {
                            SilkUtility.ReturnStatusMessage("[!] Invalid URL specified (-p|--path)", ConsoleColor.Red);
                            return;
                        }
                    }
                }
                else if (OutputType == OutputType.eventlog)
                {
                    Path = "SilkETW-Log";
                }
            }

            // Validate filter options
            // None, EventName, ProcessID, ProcessName, Opcode
            if (FilterOption != FilterOption.None)
            {
                if (String.IsNullOrEmpty(FilterValue))
                {
                    SilkUtility.ReturnStatusMessage("[!] Specify a valid filter value (-fv|--filtervalue) in conjunction with -f", ConsoleColor.Red);
                    return;
                }
                if (FilterOption == FilterOption.ProcessID)
                {
                    try
                    {
                        SilkUtility.FilterValueObject = Convert.ToUInt32(FilterValue);
                    }
                    catch
                    {
                        SilkUtility.ReturnStatusMessage("[!] Specify a valid ProcessID", ConsoleColor.Red);
                        return;
                    }
                }
                else if (FilterOption == FilterOption.Opcode)
                {
                    try
                    {
                        UInt32 opcode;
                        if (FilterValue.StartsWith("0x"))
                        {
                            opcode = Convert.ToUInt32(FilterValue, 16);
                        }
                        else
                        {
                            opcode = Convert.ToUInt32(FilterValue);
                        }
                        if (opcode > byte.MaxValue)
                        {
                            SilkUtility.ReturnStatusMessage("[!] Opcode outside valid range (0-255)", ConsoleColor.Red);
                            return;
                        }
                        SilkUtility.FilterValueObject = Convert.ToByte(opcode);
                    }
                    catch
                    {
                        SilkUtility.ReturnStatusMessage("[!] Specify a valid Opcode", ConsoleColor.Red);
                        return;
                    }
                }
                else
                {
                    SilkUtility.FilterValueObject = FilterValue;
                }
            }

            // Validate Yara folder path
            if (YaraScan != String.Empty)
            {
                try
                {
                    FileAttributes CheckAttrib = File.GetAttributes(YaraScan);
                    if (!(CheckAttrib.HasFlag(FileAttributes.Directory)))
                    {
                        SilkUtility.ReturnStatusMessage("[!] Specified path is not a folder (-y|--yara)", ConsoleColor.Red);
                        return;
                    } else
                    {
                        List<string> YaraRuleCollection = Directory.GetFiles(YaraScan, "*.yar", SearchOption.AllDirectories).ToList();
                        if (YaraRuleCollection.Count == 0)
                        {
                            SilkUtility.ReturnStatusMessage("[!] Yara folder path does not contain any *.yar files (-y|--yara)", ConsoleColor.Red);
                            return;
                        } else
                        {
                            // We already initialize yara for performace,
                            // new rules can not be added at runtime.
                            SilkUtility.YaraInstance = new YSInstance();
                            SilkUtility.YaraContext = new YSContext();
                            SilkUtility.YaraCompiler = SilkUtility.YaraInstance.CompileFromFiles(YaraRuleCollection,null);
                            SilkUtility.YaraRules = SilkUtility.YaraCompiler.GetRules();
                            YSReport YaraReport = SilkUtility.YaraCompiler.GetErrors();
                        
                            if (!(YaraReport.IsEmpty()))
                            {
                                SilkUtility.ReturnStatusMessage("[!] The following yara errors were detected (-y|--yara)", ConsoleColor.Red);

                                Dictionary<string, List<string>> Errors = YaraReport.Dump();
                                foreach (KeyValuePair<string, List<string>> Error in Errors)
                                {
                                    SilkUtility.ReturnStatusMessage("==> " + Error.Key, ConsoleColor.Yellow);
                                    foreach (String ErrorMsg in Error.Value)
                                    {
                                        SilkUtility.ReturnStatusMessage("    + " + ErrorMsg, ConsoleColor.Yellow);
                                    }
                                }
                                return;
                            }

                        }
                    }
                }
                catch
                {
                    SilkUtility.ReturnStatusMessage("[!] Specify a valid yara rule folder path (-y|--yara)", ConsoleColor.Red);
                    return;
                }

                if (YaraOptions == YaraOptions.None)
                {
                    SilkUtility.ReturnStatusMessage("[!] Specify a valid yara option (-yo|--yaraoptions)", ConsoleColor.Red);
                    return;
                }
            }

            // We passed all collector parameter checks
            SilkUtility.ReturnStatusMessage("[+] Collector parameter validation success..", ConsoleColor.Green);

            // Launch the collector
            if (CollectorType == CollectorType.Kernel)
            {
                ETWCollector.StartTrace(CollectorType, (ulong)KernelKeywords, OutputType, Path, FilterOption, SilkUtility.FilterValueObject, YaraScan, YaraOptions);
            }
            else
            {
                ETWCollector.StartTrace(CollectorType, SilkUtility.UlongUserKeywords, OutputType, Path, FilterOption, SilkUtility.FilterValueObject, YaraScan, YaraOptions, ProviderName, UserTraceEventLevel);
            }
        }
    }
}
