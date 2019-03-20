using System;
using System.IO;
using Microsoft.Diagnostics.Tracing;
using System.Collections;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net;
using YaraSharp;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json.Linq;

namespace SilkETW
{
    // Command line enums
    enum CollectorType
    {
        None = 0,
        Kernel,
        User
    }

    enum OutputType
    {
        None = 0,
        url,
        file
    }

    enum FilterOption
    {
        None = 0,
        EventName,
        ProcessID,
        ProcessName,
        Opcode
    }

    enum YaraOptions
    {
        None = 0,
        All,
        Matches
    }

    enum KernelKeywords
    {
        //
        // Summary:
        //     Turn on PMC (Precise Machine Counter) events. Only Win 8
        PMCProfile = int.MinValue,
        //
        // Summary:
        //     These are the kernel events that are not allowed in containers. Can be subtracted
        //     out.
        NonContainer = -16777248,
        //
        // Summary:
        //     Logs nothing
        None = 0,
        //
        // Summary:
        //     Logs process starts and stops.
        Process = 1,
        //
        // Summary:
        //     Logs threads starts and stops
        Thread = 2,
        //
        // Summary:
        //     Logs native modules loads (LoadLibrary), and unloads
        ImageLoad = 4,
        //
        // Summary:
        //     Logs process performance counters (TODO When?) (Vista+ only) see KernelTraceEventParser.ProcessPerfCtr,
        //     ProcessPerfCtrTraceData
        ProcessCounters = 8,
        //
        // Summary:
        //     log thread context switches (Vista only) (can be > 10K events per second)
        ContextSwitch = 16,
        //
        // Summary:
        //     log defered procedure calls (an Kernel mechanism for having work done asynchronously)
        //     (Vista+ only)
        DeferedProcedureCalls = 32,
        //
        // Summary:
        //     log hardware interrupts. (Vista+ only)
        Interrupt = 64,
        //
        // Summary:
        //     log calls to the OS (Vista+ only) This is VERY volumous (can be > 100K events
        //     per second)
        SystemCall = 128,
        //
        // Summary:
        //     Loads the completion of Physical disk activity.
        DiskIO = 256,
        //
        // Summary:
        //     Logs the mapping of file IDs to actual (kernel) file names.
        DiskFileIO = 512,
        //
        // Summary:
        //     log Disk operations (Vista+ only) Generally not TOO volumous (typically less
        //     than 1K per second) (Stacks associated with this)
        DiskIOInit = 1024,
        //
        // Summary:
        //     Thread Dispatcher (ReadyThread) (Vista+ only) (can be > 10K events per second)
        Dispatcher = 2048,
        //
        // Summary:
        //     Logs all page faults (hard or soft) Can be pretty volumous (> 1K per second)
        Memory = 4096,
        //
        // Summary:
        //     Logs all page faults that must fetch the data from the disk (hard faults)
        MemoryHardFaults = 8192,
        //
        // Summary:
        //     Log Virtual Alloc calls and VirtualFree. (Vista+ Only) Generally not TOO volumous
        //     (typically less than 1K per second)
        VirtualAlloc = 16384,
        //
        // Summary:
        //     Log mapping of files into memmory (Win8 and above Only) Generally low volume.
        VAMap = 32768,
        //
        // Summary:
        //     Logs TCP/IP network send and receive events.
        NetworkTCPIP = 65536,
        //
        // Summary:
        //     Logs activity to the windows registry. Can be pretty volumous (> 1K per second)
        Registry = 131072,
        //
        // Summary:
        //     Logs Advanced Local Procedure call events.
        AdvancedLocalProcedureCalls = 1048576,
        //
        // Summary:
        //     Disk I/O that was split (eg because of mirroring requirements) (Vista+ only)
        SplitIO = 2097152,
        //
        // Summary:
        //     Handle creation and closing (for handle leaks)
        Handle = 4194304,
        //
        // Summary:
        //     Device Driver logging (Vista+ only)
        Driver = 8388608,
        //
        // Summary:
        //     You mostly don't care about these unless you are dealing with OS internals.
        OS = 11534432,
        //
        // Summary:
        //     Sampled based profiling (every msec) (Vista+ only) (expect 1K events per proc
        //     per second)
        Profile = 16777216,
        //
        // Summary:
        //     Good default kernel flags. (TODO more detail)
        Default = 16852751,
        //
        // Summary:
        //     Use this if you care about blocked time.
        ThreadTime = 16854815,
        //
        // Summary:
        //     log file FileOperationEnd (has status code) when they complete (even ones that
        //     do not actually cause Disk I/O). (Vista+ only) Generally not TOO volumous (typically
        //     less than 1K per second) (No stacks associated with these)
        FileIO = 33554432,
        //
        // Summary:
        //     log the start of the File I/O operation as well as the end. (Vista+ only) Generally
        //     not TOO volumous (typically less than 1K per second)
        FileIOInit = 67108864,
        //
        // Summary:
        //     These events are too verbose for normal use, but this give you a quick way of
        //     turing on 'interesting' events This does not include SystemCall because it is
        //     'too verbose'
        Verbose = 117702431,
        //
        // Summary:
        //     All legal kernel events
        All = 129236991,
        //
        // Summary:
        //     Events when queuing and dequeuing from the I/O completion ports.
        IOQueue = 268435456,
        //
        // Summary:
        //     Events when thread priorities change.
        ThreadPriority = 536870912,
        //
        // Summary:
        //     Kernel reference set events (like XPERF ReferenceSet). Fully works only on Win
        //     8.
        ReferenceSet = 1073741824
    }

    enum UserTraceEventLevel
    {
        // Summary:
        //     Always log the event (It also can mean that the provider decides the verbosity)
        Always = 0,
        //
        // Summary:
        //     Events that indicate critical conditions
        Critical = 1,
        //
        // Summary:
        //     Events that indicate error conditions
        Error = 2,
        //
        // Summary:
        //     Events that indicate warning conditions
        Warning = 3,
        //
        // Summary:
        //     Events that indicate information
        Informational = 4,
        //
        // Summary:
        //     Events that verbose information
        Verbose = 5
    }

    // Def basic event struct so we can serialize to JSON
    public struct EventRecordStruct
    {
        public Guid ProviderGuid;
        public List<String> YaraMatch;
        public string ProviderName;
        public string EventName;
        public TraceEventOpcode Opcode;
        public string OpcodeName;
        public DateTime TimeStamp;
        public int ThreadID;
        public int ProcessID;
        public string ProcessName;
        public int PointerSize;
        public int EventDataLength;
        public Hashtable XmlEventData;
    }

    class SilkUtility
    {
        // Global var's
        public static ulong UlongUserKeywords;
        public static String EventParseSessionName;
        public static UInt64 RunningEventCount = 0;
        public static int CursorYPos = 0;
        public static Object FilterValueObject = null;
        public static Boolean ProcessEventData;
        public static Boolean NoYaraRulesFound = false;
        public static YSInstance YaraInstance;
        public static YSContext YaraContext;
        public static YSCompiler YaraCompiler;
        public static YSRules YaraRules;
        public static List<String> YaraRuleMatches = new List<String>();
        public static readonly object ConsoleWriterLock = new object();

        // Print logo
        public static void PrintLogo()
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("\n███████╗██╗██╗   ██╗  ██╗███████╗████████╗██╗    ██╗");
            Console.WriteLine("██╔════╝██║██║   ██║ ██╔╝██╔════╝╚══██╔══╝██║    ██║  ");
            Console.WriteLine("███████╗██║██║   █████╔╝ █████╗     ██║   ██║ █╗ ██║  ");
            Console.WriteLine("╚════██║██║██║   ██╔═██╗ ██╔══╝     ██║   ██║███╗██║  ");
            Console.WriteLine("███████║██║█████╗██║  ██╗███████╗   ██║   ╚███╔███╔╝  ");
            Console.WriteLine("╚══════╝╚═╝╚════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚══╝╚══╝   ");
            Console.ResetColor();
            Console.WriteLine("                  [v0.4 - Ruben Boonen => @FuzzySec]\n");
        }

        // Print trivia ;)
        public static void PrintTrivia()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("|------------------------------------------------------|\n" +
                              "| Taur Urgas sent some soliders out to arrest me. I    |\n" +
                              "| didn't particularly feel like being arrested, so I   |\n" +
                              "| argued with the soldiers a bit. Several of them died |\n" +
                              "| during the argument - those things happen once in a  |\n" +
                              "| while.                                               |\n" +
                              "|                                              ~ Silk  |\n" +
                              "|------------------------------------------------------|");
            Console.ResetColor();
        }

        // Print help
        public static void PrintHelp()
        {
            string HelpText = "\n >--~~--> Args? <--~~--<\n\n" +
                              "-h  (--help)          This help menu\n" +
                              "-s  (--silk)          Trivia about Silk\n" +
                              "-t  (--type)          Specify if we are using a Kernel or User collector\n" +
                              "-kk (--kernelkeyword) Valid keywords: Process, Thread, ImageLoad, ProcessCounters, ContextSwitch,\n" +
                              "                      DeferedProcedureCalls, Interrupt, SystemCall, DiskIO, DiskFileIO, DiskIOInit,\n" +
                              "                      Dispatcher, Memory, MemoryHardFaults, VirtualAlloc, VAMap, NetworkTCPIP, Registry,\n" +
                              "                      AdvancedLocalProcedureCalls, SplitIO, Handle, Driver, OS, Profile, Default,\n" +
                              "                      ThreadTime, FileIO, FileIOInit, Verbose, All, IOQueue, ThreadPriority,\n" +
                              "                      ReferenceSet, PMCProfile, NonContainer\n" +
                              "-uk (--userkeyword)   Define a mask of valid keywords, eg 0x2038 -> JitKeyword|InteropKeyword|\n" +
                              "                      LoaderKeyword|NGenKeyword\n" +
                              "-pn (--providername)  User ETW provider name, eg \"Microsoft-Windows-DotNETRuntime\"\n" +
                              "-l  (--level)         Logging level: Always, Critical, Error, Warning, Informational, Verbose\n" +
                              "-ot (--outputtype)    Output type; either POST to URL or write to file\n" +
                              "-p  (--path)          Either full output file path or URL\n" +
                              "-f  (--filter)        Filter types: None, EventName, ProcessID, ProcessName, Opcode\n" +
                              "-fv (--filtervalue)   Filter type capture value, eg \"svchost\" for ProcessName\n" +
                              "-y  (--yara)          Full path to folder containing Yara rules\n" +
                              "-yo (--yaraoptions)   Either record \"All\" events or only \"Matches\"\n\n" +

                              " >--~~--> Usage? <--~~--<\n";
            Console.WriteLine(HelpText);
            SilkUtility.ReturnStatusMessage("# Use a VirtualAlloc Kernel collector, POST results to Elasticsearch", ConsoleColor.Green);
            Console.WriteLine("SilkETW.exe -t kernel -kk VirtualAlloc -ot url -p https://some.elk:9200/valloc/_doc/\n");
            SilkUtility.ReturnStatusMessage("# Use a Process Kernel collector, filter on PID", ConsoleColor.Green);
            Console.WriteLine("SilkETW.exe -t kernel -kk Process -ot url -p https://some.elk:9200/kproc/_doc/ -f ProcessID -fv 11223\n");
            SilkUtility.ReturnStatusMessage("# Use a .Net User collector, specify mask, filter on EventName, write to file", ConsoleColor.Green);
            Console.WriteLine("SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\\Some\\Path\\out.json -f EventName -fv Method/LoadVerbose\n");
            SilkUtility.ReturnStatusMessage("# Use a DNS User collector, specify log level, write to file", ConsoleColor.Green);
            Console.WriteLine("SilkETW.exe -t user -pn Microsoft-Windows-DNS-Client -l Always -ot file -p C:\\Some\\Path\\out.json\n");
            SilkUtility.ReturnStatusMessage("# Use an LDAP User collector, perform Yara matching, POST matches to Elasticsearch", ConsoleColor.Green);
            Console.WriteLine("SilkETW.exe -t user -pn Microsoft-Windows-Ldap-Client -ot url -p https://some.elk:9200/ldap/_doc/ -y C:\\Some\\Yara\\Rule\\Folder -yo matches");
        }

        // Print status message
        public static void ReturnStatusMessage(String StatusMessage, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(StatusMessage);
            Console.ResetColor();
        }

        // Update event count in-place
        public static void UpdateEventCount(String NewCount)
        {
            lock(ConsoleWriterLock)
            {
                if (SilkUtility.CursorYPos == 0)
                {
                    SilkUtility.CursorYPos = Console.CursorTop - 1;
                    Console.CursorVisible = false;
                }
                int CurrentCursorYPos = Console.CursorTop;
                Console.SetCursorPosition(0, SilkUtility.CursorYPos);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(NewCount);
                Console.ResetColor();
                Console.SetCursorPosition(0, CurrentCursorYPos);
            }
        }

        // Check if user has X access to directory
        public static bool DirectoryHasPermission(string DirectoryPath, FileSystemRights AccessRight)
        {
            var isInRoleWithAccess = false;

            try
            {
                var di = new DirectoryInfo(DirectoryPath);
                var acl = di.GetAccessControl();
                var rules = acl.GetAccessRules(true, true, typeof(NTAccount));
                var currentUser = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(currentUser);
                foreach (AuthorizationRule rule in rules)
                {
                    var fsAccessRule = rule as FileSystemAccessRule;
                    if (fsAccessRule == null)
                        continue;

                    if ((fsAccessRule.FileSystemRights & AccessRight) > 0)
                    {
                        var ntAccount = rule.IdentityReference as NTAccount;
                        if (ntAccount == null)
                            continue;

                        if (principal.IsInRole(ntAccount.Value))
                        {
                            if (fsAccessRule.AccessControlType == AccessControlType.Deny)
                                return false;
                            isInRoleWithAccess = true;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            return isInRoleWithAccess;
        }

        public static int ProcessJSONEventData(String JSONData, OutputType OutputType, String Path, String YaraScan, YaraOptions YaraOptions)
        {
            // Yara options
            if (YaraScan != String.Empty)
            {
                byte[] JSONByteArray = Encoding.ASCII.GetBytes(JSONData);
                List<YSMatches> Matches = SilkUtility.YaraInstance.ScanMemory(JSONByteArray, SilkUtility.YaraRules,null,0);
                SilkUtility.YaraRuleMatches.Clear();
                if (Matches.Count != 0)
                {
                    foreach (YSMatches Match in Matches)
                    {
                        SilkUtility.YaraRuleMatches.Add(Match.Rule.Identifier);
                        lock (ConsoleWriterLock)
                        {
                            SilkUtility.ReturnStatusMessage($"     -> Yara match: {Match.Rule.Identifier}", ConsoleColor.Magenta);
                        }
                    }

                    // Dynamically update the JSON object -> List<String> YaraRuleMatches
                    JObject obj = JObject.Parse(JSONData);
                    ((JArray)obj["YaraMatch"]).Add(SilkUtility.YaraRuleMatches);
                    JSONData = obj.ToString(Newtonsoft.Json.Formatting.None);
                }
            }

            if (YaraOptions == YaraOptions.All || YaraOptions == YaraOptions.None || (YaraScan != String.Empty && SilkUtility.YaraRuleMatches.Count > 0))
            {
                //--[Return Codes]
                // 0 == OK
                // 1 == File write failed
                // 2 == URL POST request failed
                //--

                // Process JSON
                if (OutputType == OutputType.file)
                {
                    try
                    {
                        if (!File.Exists(Path))
                        {
                            File.WriteAllText(Path, (JSONData + Environment.NewLine));
                        }
                        else
                        {
                            File.AppendAllText(Path, (JSONData + Environment.NewLine));
                        }

                        return 0;
                    }
                    catch
                    {
                        return 1;
                    }

                }
                else
                {
                    try
                    {
                        string responseFromServer = string.Empty;
                        HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(Path);
                        webRequest.Timeout = 10000; // 10 second timeout
                        webRequest.Method = "POST";
                        webRequest.ContentType = "application/json";
                        webRequest.Accept = "application/json";
                        using (var streamWriter = new StreamWriter(webRequest.GetRequestStream()))
                        {
                            streamWriter.Write(JSONData);
                            streamWriter.Flush();
                            streamWriter.Close();
                        }
                        var httpResponse = (HttpWebResponse)webRequest.GetResponse();
                        using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
                        {
                            var result = streamReader.ReadToEnd();
                        }

                        return 0;
                    }
                    catch
                    {
                        return 2;
                    }

                }
            } else
            {
                return 0;
            }
        }

        // Ctrl-c callback handler
        private static bool ctrlCExecuted;
        private static ConsoleCancelEventHandler ctrlCHandler;
        public static void SetupCtrlCHandler(Action action)
        {
            ctrlCExecuted = false;
            if (ctrlCHandler != null)
                Console.CancelKeyPress -= ctrlCHandler;

            ctrlCHandler = (object sender, ConsoleCancelEventArgs cancelArgs) =>
            {
                if (!ctrlCExecuted)
                {
                    ctrlCExecuted = true;
                    SilkUtility.ReturnStatusMessage("[>] Stopping trace collector..", ConsoleColor.Yellow);
                    action();
                    cancelArgs.Cancel = true;
                }
            };
            Console.CancelKeyPress += ctrlCHandler;
        }
    }
}
