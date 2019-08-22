using System;
using System.IO;
using Microsoft.Diagnostics.Tracing;
using System.Collections;
using System.Security.AccessControl;
using System.Security.Principal;
using YaraSharp;
using System.Collections.Generic;
using System.Threading;

namespace SilkService
{
    // Enums
    public enum CollectorType
    {
        None = 0,
        Kernel,
        User
    }

    public enum OutputType
    {
        None = 0,
        url,
        file,
        eventlog
    }

    public enum FilterOption
    {
        None = 0,
        EventName,
        ProcessID,
        ProcessName,
        Opcode
    }

    public enum YaraOptions
    {
        None = 0,
        All,
        Matches
    }

    public enum EventIds
    {
        Start = 0,
        StopOk,
        StopError,
        Event
    }

    public enum KernelKeywords
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

    public enum UserTraceEventLevel
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

    // Basic event struct so we can serialize to JSON
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

    // XML collector parameters
    public struct CollectorParameters
    {
        public Guid CollectorGUID;
        public CollectorType CollectorType;
        public KernelKeywords KernelKeywords;
        public OutputType OutputType;
        public String Path;
        public String ProviderName;
        public UserTraceEventLevel UserTraceEventLevel;
        public Object UserKeywords;
        public FilterOption FilterOption;
        public Object FilterValue;
        public String YaraScan;
        public YaraOptions YaraOptions;
        public YSInstance YaraInstance;
        public YSContext YaraContext;
        public YSCompiler YaraCompiler;
        public YSRules YaraRules;
    }

    // Bookkeeper struct for service cleanup
    public struct CollectorInstance
    {
        public Guid CollectorGUID;
        public ETWTraceEventSource EventSource;
        public String EventParseSessionName;
    }

    class SilkUtility
    {
        // Global var's
        public static List<CollectorParameters> SilkServiceParameterSets = new List<CollectorParameters>();
        public static List<Thread> CollectorThreadList = new List<Thread>();
        public static List<CollectorInstance> CollectorTaskList = new List<CollectorInstance>();
        public static ManualResetEvent SignalThreadStarted = new ManualResetEvent(false);

        // Lock service text log
        public static readonly object LockServiceTextLog = new object();

        // Write to service log text file
        public static void WriteToServiceTextLog(String Message)
        {
            lock (LockServiceTextLog)
            {
                String Path = AppDomain.CurrentDomain.BaseDirectory + "\\Logs";
                if (!Directory.Exists(Path))
                {
                    Directory.CreateDirectory(Path);
                }
                String FilePath = AppDomain.CurrentDomain.BaseDirectory + "\\Logs\\ServiceLog_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";
                if (!File.Exists(FilePath))
                {
                    using (StreamWriter sw = File.CreateText(FilePath))
                    {
                        sw.WriteLine(Message);
                    }
                }
                else
                {
                    using (StreamWriter sw = File.AppendText(FilePath))
                    {
                        sw.WriteLine(Message);
                    }
                }
            }
        }

        // Collector log wrapper
        public static void WriteCollectorGuidMessageToServiceTextLog(Guid CollectorId, String Message, Boolean Error)
        {
            if (Error)
            {
                WriteToServiceTextLog("[!] Collector ID: " + CollectorId + "; " + Message);
            }
            else
            {
                WriteToServiceTextLog("[+] Collector ID: " + CollectorId + "; " + Message);
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
    }
}
