using System;
using System.Collections.Generic;
using System.Threading;
using System.Linq;
using System.ServiceProcess;
using Microsoft.Diagnostics.Tracing.Session;

namespace SilkService
{
    public partial class SilkService : ServiceBase
    {
        public SilkService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            SilkUtility.WriteToServiceTextLog("[+] SilkService started at: " + DateTime.Now);
            List<CollectorParameters> CollectorConfig = SilkParameters.ReadXmlConfig();
            if (!CollectorConfig.Any())
            {
                // We didn't find any ETWCollector elements so we stop the service
                // Logs in ServiceLog text file
                // Stop -> OnStop -> Change service state
                Stop();
            }
            else
            {
                Boolean IsSuccess = SilkParameters.ValidateCollectorParameters(CollectorConfig);
                if (!IsSuccess)
                {
                    // There was an error in parsing the collector parameters so we stop the service
                    // Logs in ServiceLog text file
                    // Stop -> OnStop -> Change service state
                    Stop();
                }
                else
                {
                    // Check if the config has 1+ Kernel collectors
                    // Check if multiple collectors are writing to the same file
                    int KCCount = 0;
                    Boolean IsSamePath = false;
                    HashSet<String> CCPath = new HashSet<String>();
                    for (int i = 0; i < CollectorConfig.Count; i++)
                    {
                        if (CollectorConfig[i].CollectorType == CollectorType.Kernel)
                        {
                            KCCount += 1;
                        }

                        if (CollectorConfig[i].OutputType == OutputType.file)
                        {
                            if (!CCPath.Add(CollectorConfig[i].Path))
                            {
                                IsSamePath = true;
                            }
                        }
                    }

                    if (KCCount > 1 | IsSamePath)
                    {
                        if (KCCount > 1)
                        {
                            SilkUtility.WriteToServiceTextLog("[!] SilkService can only support one Kernel collector..");
                        } else
                        {
                            SilkUtility.WriteToServiceTextLog("[!] File based output paths must be unique..");
                        }
                        
                        Stop();
                    } else
                    {
                        // We spin up the collector threads
                        SilkUtility.WriteToServiceTextLog("[*] Starting collector threads: " + DateTime.Now);
                        foreach (CollectorParameters Collector in CollectorConfig)
                        {
                            // We create a thread for the collector
                            Thread CollectorThread = new Thread(() => {
                                try
                                {
                                    SilkUtility.WriteToServiceTextLog("    [+] GUID:     " + Collector.CollectorGUID);
                                    SilkUtility.WriteToServiceTextLog("    [>] Type:     " + Collector.CollectorType);
                                    if (Collector.CollectorType == CollectorType.User)
                                    {
                                        SilkUtility.WriteToServiceTextLog("    [>] Provider: " + Collector.ProviderName);
                                    }
                                    else
                                    {
                                        SilkUtility.WriteToServiceTextLog("    [>] Provider: " + Collector.KernelKeywords);
                                    }
                                    SilkUtility.WriteToServiceTextLog("    [>] Out Type: " + Collector.OutputType);
                                    ETWCollector.StartTrace(Collector);
                                }
                                catch (Exception ex) { SilkUtility.WriteToServiceTextLog("[!] " + ex.ToString()); }

                                // If any collectors terminate by internal error we stop the service
                                Stop();
                            });

                            // We have to mark threads as background to ensure they exit in a timely fashion
                            CollectorThread.IsBackground = false;
                            // Start the collector thread
                            CollectorThread.Start();

                            // We wait for the thread to signal and then reset the event
                            SilkUtility.SignalThreadStarted.WaitOne();
                            SilkUtility.SignalThreadStarted.Reset();
                        }
                    }
                }
            }
        }

        protected override void OnStop()
        {
            // Guardrail for timeout
            RequestAdditionalTime(5000);

            // Check if any collector tasks are registered
            if (SilkUtility.CollectorTaskList.Any())
            {
                // We pop terminated threads out of the list
                foreach (CollectorInstance CollectorTask in SilkUtility.CollectorTaskList)
                {
                    try
                    {
                        CollectorTask.EventSource.StopProcessing();
                        TraceEventSession.GetActiveSession(CollectorTask.EventParseSessionName).Dispose();
                        SilkUtility.CollectorTaskList.Remove(CollectorTask);
                        SilkUtility.WriteCollectorGuidMessageToServiceTextLog(CollectorTask.CollectorGUID, "Collector terminated", false);
                    } catch { }
                }
            }

            // Write status to log
            SilkUtility.WriteToServiceTextLog("[+] SilkService stopped at: " + DateTime.Now);
        }
    }
}
