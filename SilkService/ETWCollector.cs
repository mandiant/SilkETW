using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using System.Xml;
using System.Collections;
using System.Collections.Generic;
using YaraSharp;
using System.Text;
using Newtonsoft.Json.Linq;
using System.Net;

namespace SilkService
{
    class ETWCollector
    {
        public static void StartTrace(CollectorParameters Collector)
        {
            void RetargetEventSource(String LegacySource)
            {
                // This is a fix for: https://github.com/fireeye/SilkETW/issues/4
                // When both SilkETW and SilkService are used on the same host
                // eventlog logging would fail for one or the other as they had
                // the same source. This function will retarget the source.
                if (EventLog.SourceExists(LegacySource))
                {
                    EventLog.DeleteEventSource(LegacySource);
                }
            }

            Boolean WriteEventLogEntry(String Message, EventLogEntryType Type, EventIds EventId, String Path)
            {
                //--[Event ID's]
                // 0 == Collector start
                // 1 == Collector terminated -> by user
                // 2 == Collector terminated -> by error
                // 3 == Event recorded
                //--

                try
                {
                    // Fix legacy collector source
                    RetargetEventSource("ETW Collector");

                    // Event log properties
                    String Source = "SilkService Collector";

                    // If the source doesn't exist we have to create it first
                    if (!EventLog.SourceExists(Source))
                    {
                        EventLog.CreateEventSource(Source, Path);
                    }

                    // Write event
                    using (EventLog Log = new EventLog(Path))
                    {
                        Log.Source = Source;
                        Log.MaximumKilobytes = 99968; // Max ~100mb size -> needs 64kb increments
                        Log.ModifyOverflowPolicy(OverflowAction.OverwriteAsNeeded, 10); // Always overwrite oldest
                        Log.WriteEntry(Message, Type, (int)EventId);
                    }
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            int ProcessJSONEventData(String JSONData, OutputType OutputType, String Path, String YaraScan, YaraOptions YaraOptions, YSInstance YaraInstance, YSRules YaraRules)
            {
                // Yara matches
                List<String> YaraRuleMatches = new List<String>();

                // Yara options
                if (YaraScan != String.Empty)
                {
                    byte[] JSONByteArray = Encoding.ASCII.GetBytes(JSONData);
                    List<YSMatches> Matches = YaraInstance.ScanMemory(JSONByteArray, YaraRules, null, 0);
                    YaraRuleMatches.Clear();
                    if (Matches.Count != 0)
                    {
                        foreach (YSMatches Match in Matches)
                        {
                            YaraRuleMatches.Add(Match.Rule.Identifier);
                        }

                        // Dynamically update the JSON object -> List<String> YaraRuleMatches
                        JObject obj = JObject.Parse(JSONData);
                        ((JArray)obj["YaraMatch"]).Add(YaraRuleMatches);
                        JSONData = obj.ToString(Newtonsoft.Json.Formatting.None);
                    }
                }

                if (YaraOptions == YaraOptions.All || YaraOptions == YaraOptions.None || (YaraScan != String.Empty && YaraRuleMatches.Count > 0))
                {
                    //--[Return Codes]
                    // 0 == OK
                    // 1 == File write failed
                    // 2 == URL POST request failed
                    // 3 == Eventlog write failed
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
                    else if (OutputType == OutputType.url)
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
                    else
                    {
                        Boolean WriteEvent = WriteEventLogEntry(JSONData, EventLogEntryType.Information, EventIds.Event, Path);

                        if (WriteEvent)
                        {
                            return 0;
                        }
                        else
                        {
                            return 3;
                        }

                    }
                }
                else
                {
                    return 0;
                }
            }

            // Local variables for StartTrace
            String EventParseSessionName;
            Boolean ProcessEventData;

            // Is elevated? While running as a service this should always be true but
            // this is kept for edge-case user-fail.
            if (TraceEventSession.IsElevated() != true)
            {
                SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "The collector must be run elevated", true);
                return;
            }

            // Print status
            SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Starting trace collector", false);

            // We tag event sessions with a unique name
            // While running these are observable with => logman -ets
            if (Collector.CollectorType == CollectorType.Kernel)
            {
                EventParseSessionName = KernelTraceEventParser.KernelSessionName;
            }
            else
            {
                String RandId = Guid.NewGuid().ToString();
                EventParseSessionName = ("SilkServiceUserCollector_" + RandId);
            }

            // Create trace session
            using (var TraceSession = new TraceEventSession(EventParseSessionName))
            {
                // The collector cannot survive process termination (safeguard)
                TraceSession.StopOnDispose = true;

                // Create event source
                using (var EventSource = new ETWTraceEventSource(EventParseSessionName, TraceEventSourceType.Session))
                {
                    // A DynamicTraceEventParser can understand how to read the embedded manifests that occur in the dataStream
                    var EventParser = new DynamicTraceEventParser(EventSource);

                    // Loop events as they arrive
                    EventParser.All += delegate (TraceEvent data)
                    {
                        // It's a bit ugly but ... ¯\_(ツ)_/¯
                        if (Collector.FilterOption != FilterOption.None)
                        {
                            if (Collector.FilterOption == FilterOption.Opcode && (byte)data.Opcode != (byte)Collector.FilterValue)
                            {
                                ProcessEventData = false;
                            }
                            else if (Collector.FilterOption == FilterOption.ProcessID && data.ProcessID != (UInt32)Collector.FilterValue)
                            {
                                ProcessEventData = false;
                            }
                            else if (Collector.FilterOption == FilterOption.ProcessName && data.ProcessName != (String)Collector.FilterValue)
                            {
                                ProcessEventData = false;
                            }
                            else if (Collector.FilterOption == FilterOption.EventName && data.EventName != (String)Collector.FilterValue)
                            {
                                ProcessEventData = false;
                            }
                            else
                            {
                                ProcessEventData = true;
                            }
                        }
                        else
                        {
                            ProcessEventData = true;
                        }

                        // Only process/serialize events if they match our filter
                        if (ProcessEventData)
                        {
                            var eRecord = new EventRecordStruct
                            {
                                ProviderGuid = data.ProviderGuid,
                                YaraMatch = new List<String>(),
                                ProviderName = data.ProviderName,
                                EventName = data.EventName,
                                Opcode = data.Opcode,
                                OpcodeName = data.OpcodeName,
                                TimeStamp = data.TimeStamp,
                                ThreadID = data.ThreadID,
                                ProcessID = data.ProcessID,
                                ProcessName = data.ProcessName,
                                PointerSize = data.PointerSize,
                                EventDataLength = data.EventDataLength
                            };

                            // Populate Proc name if undefined
                            if (String.IsNullOrEmpty(eRecord.ProcessName))
                            {
                                try
                                {
                                    eRecord.ProcessName = Process.GetProcessById(eRecord.ProcessID).ProcessName;
                                }
                                catch
                                {
                                    eRecord.ProcessName = "N/A";
                                }
                            }
                            var EventProperties = new Hashtable();

                            // Try to parse event XML
                            try
                            {
                                StringReader XmlStringContent = new StringReader(data.ToString());
                                XmlTextReader EventElementReader = new XmlTextReader(XmlStringContent);
                                while (EventElementReader.Read())
                                {
                                    for (int AttribIndex = 0; AttribIndex < EventElementReader.AttributeCount; AttribIndex++)
                                    {
                                        EventElementReader.MoveToAttribute(AttribIndex);

                                        // Cap maxlen for eventdata elements to 10k
                                        if (EventElementReader.Value.Length > 10000)
                                        {
                                            String DataValue = EventElementReader.Value.Substring(0, Math.Min(EventElementReader.Value.Length, 10000));
                                            EventProperties.Add(EventElementReader.Name, DataValue);
                                        }
                                        else
                                        {
                                            EventProperties.Add(EventElementReader.Name, EventElementReader.Value);
                                        }
                                    }
                                }
                            }
                            catch
                            {
                                // For debugging (?), never seen this fail
                                EventProperties.Add("XmlEventParsing", "false");
                            }
                            eRecord.XmlEventData = EventProperties;

                            // Serialize to JSON
                            String JSONEventData = Newtonsoft.Json.JsonConvert.SerializeObject(eRecord);
                            int ProcessResult = ProcessJSONEventData(JSONEventData, Collector.OutputType, Collector.Path, Collector.YaraScan, Collector.YaraOptions, Collector.YaraInstance, Collector.YaraRules);

                            // Verify that we processed the result successfully
                            if (ProcessResult != 0)
                            {
                                if (ProcessResult == 1)
                                {
                                    SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "The collector failed to write to file", true);
                                }
                                else if (ProcessResult == 2)
                                {
                                    SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "The collector failed to POST the result", true);
                                }
                                else
                                {
                                    SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "The collector failed write to the eventlog", true);
                                }

                                // Write status to eventlog if dictated by the output type
                                if (Collector.OutputType == OutputType.eventlog)
                                {
                                    WriteEventLogEntry($"{{\"Collector\":\"Stop\",\"Error\":true,\"ErrorCode\":{ProcessResult}}}", EventLogEntryType.Error, EventIds.StopError, Collector.Path);
                                }

                                // This collector encountered an error, terminate the service
                                TerminateCollector();
                            }
                        }
                    };

                    // Specify the providers details
                    if (Collector.CollectorType == CollectorType.Kernel)
                    {
                        TraceSession.EnableKernelProvider((KernelTraceEventParser.Keywords)Collector.KernelKeywords);
                    }
                    else
                    {
                        // Note that the collector doesn't know if you specified a wrong provider name,
                        // the only tell is that you won't get any events ;)
                        TraceSession.EnableProvider(Collector.ProviderName, (TraceEventLevel)Collector.UserTraceEventLevel, (ulong)Collector.UserKeywords);
                    }

                    // Write status to eventlog if dictated by the output type
                    if (Collector.OutputType == OutputType.eventlog)
                    {
                        String ConvertKeywords;
                        if (Collector.CollectorType == CollectorType.Kernel)
                        {
                            ConvertKeywords = Enum.GetName(typeof(KernelTraceEventParser.Keywords), Collector.KernelKeywords);
                        }
                        else
                        {
                            ConvertKeywords = "0x" + String.Format("{0:X}", (ulong)Collector.UserKeywords);
                        }
                        String Message = $"{{\"Collector\":\"Start\",\"Data\":{{\"Type\":\"{Collector.CollectorType}\",\"Provider\":\"{Collector.ProviderName}\",\"Keywords\":\"{ConvertKeywords}\",\"FilterOption\":\"{Collector.FilterOption}\",\"FilterValue\":\"{Collector.FilterValue}\",\"YaraPath\":\"{Collector.YaraScan}\",\"YaraOption\":\"{Collector.YaraOptions}\"}}}}";
                        WriteEventLogEntry(Message, EventLogEntryType.SuccessAudit, EventIds.Start, Collector.Path);
                    }

                    // Populate the trace bookkeeper
                    var CollectorInstance = new CollectorInstance
                    {
                        CollectorGUID = Collector.CollectorGUID,
                        EventSource = EventSource,
                        EventParseSessionName = EventParseSessionName,
                    };
                    SilkUtility.CollectorTaskList.Add(CollectorInstance);

                    // Signal the ManualResetEvent
                    SilkUtility.SignalThreadStarted.Set();

                    // Continuously process all new events in the data source
                    EventSource.Process();

                    void TerminateCollector()
                    {
                        EventSource.StopProcessing();
                        TraceSession?.Stop();
                        SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Collector terminated", false);
                        return;
                    }
                }
            }
        }
    }
}