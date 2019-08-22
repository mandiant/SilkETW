using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using YaraSharp;

namespace SilkService
{
    class SilkParameters
    {
        // Parse SilkService XML config
        public static List<CollectorParameters> ReadXmlConfig()
        {
            // Load config
            String ConfigPath = AppDomain.CurrentDomain.BaseDirectory + "\\SilkServiceConfig.xml";
            XElement XmlConfigFile = null;
            try
            {
                XmlConfigFile = XElement.Load(ConfigPath);
            } catch
            {
                SilkUtility.WriteToServiceTextLog("[!] SilkServiceConfig.xml configuration file invalid or not found");
                return SilkUtility.SilkServiceParameterSets;
            }

            // Define XML elements
            XName CI = XName.Get("ETWCollector");
            XName CG = XName.Get("Guid");
            XName CT = XName.Get("CollectorType");
            XName KK = XName.Get("KernelKeywords");
            XName OT = XName.Get("OutputType");
            XName P = XName.Get("Path");
            XName PN = XName.Get("ProviderName");
            XName UTEL = XName.Get("UserTraceEventLevel");
            XName UK = XName.Get("UserKeywords");
            XName FO = XName.Get("FilterOption");
            XName FV = XName.Get("FilterValue");
            XName YS = XName.Get("YaraScan");
            XName YO = XName.Get("YaraOptions");

            // Initialize result struct
            var CollectorParamInstance = new CollectorParameters();

            // Loop ETWCollector elements
            try
            {
                foreach (XElement Collector in XmlConfigFile.Elements(CI))
                {
                    XElement ParamContainer;

                    // Loop all possible params
                    try // (1) --> CollectorGUID, ID of the the collector instance for internal tracking
                    {
                        ParamContainer = Collector.Element(CG);
                        Guid EnumContainer;
                        if (Guid.TryParse(ParamContainer.Value, out EnumContainer))
                        {
                            CollectorParamInstance.CollectorGUID = EnumContainer;
                        }
                        else
                        {
                            CollectorParamInstance.CollectorGUID = Guid.Empty;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.CollectorGUID = Guid.Empty;
                    }
                    try // (2) --> CollectorType
                    {
                        ParamContainer = Collector.Element(CT);
                        CollectorType EnumContainer;
                        if (Enum.TryParse(ParamContainer.Value, true, out EnumContainer))
                        {
                            CollectorParamInstance.CollectorType = EnumContainer;
                        }
                        else
                        {
                            CollectorParamInstance.CollectorType = CollectorType.None;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.CollectorType = CollectorType.None;
                    }
                    try // (3) --> KernelKeywords
                    {
                        ParamContainer = Collector.Element(KK);
                        KernelKeywords EnumContainer;
                        if (Enum.TryParse(ParamContainer.Value, true, out EnumContainer))
                        {
                            CollectorParamInstance.KernelKeywords = EnumContainer;
                        }
                        else
                        {
                            CollectorParamInstance.KernelKeywords = KernelKeywords.None;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.KernelKeywords = KernelKeywords.None;
                    }
                    try // (4) --> OutputType
                    {
                        ParamContainer = Collector.Element(OT);
                        OutputType EnumContainer;
                        if (Enum.TryParse(ParamContainer.Value, true, out EnumContainer))
                        {
                            CollectorParamInstance.OutputType = EnumContainer;
                        }
                        else
                        {
                            CollectorParamInstance.OutputType = OutputType.None;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.OutputType = OutputType.None;
                    }
                    try // (5) --> Path
                    {
                        ParamContainer = Collector.Element(P);
                        if (!String.IsNullOrEmpty(ParamContainer.Value))
                        {
                            CollectorParamInstance.Path = ParamContainer.Value;
                        }
                        else
                        {
                            CollectorParamInstance.Path = String.Empty;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.Path = String.Empty;
                    }
                    try // (6) --> ProviderName
                    {
                        ParamContainer = Collector.Element(PN);
                        if (!String.IsNullOrEmpty(ParamContainer.Value))
                        {
                            CollectorParamInstance.ProviderName = ParamContainer.Value;
                        }
                        else
                        {
                            CollectorParamInstance.ProviderName = String.Empty;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.ProviderName = String.Empty;
                    }
                    try // (7) --> UserTraceEventLevel
                    {
                        ParamContainer = Collector.Element(UTEL);
                        UserTraceEventLevel EnumContainer;
                        if (Enum.TryParse(ParamContainer.Value, true, out EnumContainer))
                        {
                            CollectorParamInstance.UserTraceEventLevel = EnumContainer;
                        }
                        else
                        {
                            CollectorParamInstance.UserTraceEventLevel = UserTraceEventLevel.Informational;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.UserTraceEventLevel = UserTraceEventLevel.Informational;
                    }
                    try // (8) --> UserKeywords
                    {
                        ParamContainer = Collector.Element(UK);
                        if (!String.IsNullOrEmpty(ParamContainer.Value))
                        {
                            CollectorParamInstance.UserKeywords = ParamContainer.Value;
                        }
                        else
                        {
                            CollectorParamInstance.UserKeywords = "0xffffffffffffffff";
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.UserKeywords = "0xffffffffffffffff";
                    }
                    try // (9) --> FilterOption
                    {
                        ParamContainer = Collector.Element(FO);
                        FilterOption EnumContainer;
                        if (Enum.TryParse(ParamContainer.Value, true, out EnumContainer))
                        {
                            CollectorParamInstance.FilterOption = EnumContainer;
                        }
                        else
                        {
                            CollectorParamInstance.FilterOption = FilterOption.None;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.FilterOption = FilterOption.None;
                    }
                    try // (10) --> FilterValue
                    {
                        ParamContainer = Collector.Element(FV);
                        if (!String.IsNullOrEmpty(ParamContainer.Value))
                        {
                            CollectorParamInstance.FilterValue = ParamContainer.Value;
                        }
                        else
                        {
                            CollectorParamInstance.FilterValue = String.Empty;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.FilterValue = String.Empty;
                    }
                    try // (11) --> YaraScan
                    {
                        ParamContainer = Collector.Element(YS);
                        if (!String.IsNullOrEmpty(ParamContainer.Value))
                        {
                            CollectorParamInstance.YaraScan = ParamContainer.Value;
                        }
                        else
                        {
                            CollectorParamInstance.YaraScan = String.Empty;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.YaraScan = String.Empty;
                    }
                    try // (12) --> YaraOptions
                    {
                        ParamContainer = Collector.Element(YO);
                        YaraOptions EnumContainer;
                        if (Enum.TryParse(ParamContainer.Value, true, out EnumContainer))
                        {
                            CollectorParamInstance.YaraOptions = EnumContainer;
                        }
                        else
                        {
                            CollectorParamInstance.YaraOptions = YaraOptions.None;
                        }
                    }
                    catch
                    {
                        CollectorParamInstance.YaraOptions = YaraOptions.None;
                    }

                    // Add result to ouput object
                    SilkUtility.SilkServiceParameterSets.Add(CollectorParamInstance);
                }
            }
            catch
            {
                SilkUtility.WriteToServiceTextLog("[!] Parsing error encountered while processing SilkService XML configuration file");
            }

            if (SilkUtility.SilkServiceParameterSets.Count == 0)
            {
                SilkUtility.WriteToServiceTextLog("[!] SilkService XML configuration file did not contain any ETWCollector elements");
            }

            return SilkUtility.SilkServiceParameterSets;
        }

        // Spin up collector threads
        public static Boolean ValidateCollectorParameters(List<CollectorParameters> Collectors)
        {
            // Loop collector configs
            for (int i = 0; i < Collectors.Count; i++)
            {
                // Assign list instance to variable
                CollectorParameters Collector = Collectors[i];

                // What type of collector are we creating?
                if (Collector.CollectorType == CollectorType.None)
                {
                    SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid CollectorType specified", true);
                    return false;
                }
                else if (Collector.CollectorType == CollectorType.Kernel)
                {
                    if (Collector.KernelKeywords == KernelKeywords.None)
                    {
                        SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid KernelKeywords specified", true);
                        return false;
                    }
                }
                else if (Collector.CollectorType == CollectorType.User)
                {
                    if (String.IsNullOrEmpty(Collector.ProviderName))
                    {
                        SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid ProviderName specified", true);
                        return false;
                    }

                    // Check and convert UserKeywords to ulong
                    if (String.IsNullOrEmpty((String)Collector.UserKeywords))
                    {
                        SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid UserKeywords specified", true);
                        return false;
                    }
                    else
                    {
                        try
                        {
                            if (((String)Collector.UserKeywords).StartsWith("0x"))
                            {
                                Collector.UserKeywords = Convert.ToUInt64((String)Collector.UserKeywords, 16);
                            }
                            else
                            {
                                Collector.UserKeywords = Convert.ToUInt64((String)Collector.UserKeywords);
                            }
                        }
                        catch
                        {
                            SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid UserKeywords mask specified", true);
                            return false;
                        }
                    }
                }

                // Validate output parameters
                if (Collector.OutputType == OutputType.None)
                {
                    SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid OutputType specified", true);
                    return false;
                }
                else
                {
                    if (Collector.OutputType == OutputType.file)
                    {
                        if (String.IsNullOrEmpty(Collector.Path))
                        {
                            SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid output path specified", true);
                            return false;
                        }
                        else
                        {
                            try
                            {
                                FileAttributes CheckAttrib = File.GetAttributes(Collector.Path);
                                if (CheckAttrib.HasFlag(FileAttributes.Directory))
                                {
                                    SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Output path is a directory, not a file", true);
                                    return false;
                                }
                            }
                            catch { }
                            if (!(Directory.Exists(System.IO.Path.GetDirectoryName(Collector.Path))))
                            {
                                SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Output path does not exist", true);
                                return false;
                            }
                            else
                            {
                                if (!(SilkUtility.DirectoryHasPermission(System.IO.Path.GetDirectoryName(Collector.Path), System.Security.AccessControl.FileSystemRights.Write)))
                                {
                                    SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "No write access to output path", true);
                                    return false;
                                }
                            }
                        }
                    }
                    else if (Collector.OutputType == OutputType.url)
                    {
                        if (String.IsNullOrEmpty(Collector.Path))
                        {
                            SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "No URL specified", true);
                            return false;
                        }
                        else
                        {
                            Uri uriResult;
                            bool UrlResult = Uri.TryCreate(Collector.Path, UriKind.Absolute, out uriResult) && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
                            if (!UrlResult)
                            {
                                SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid URL specified", true);
                                return false;
                            }
                        }
                    }
                    else if (Collector.OutputType == OutputType.eventlog)
                    {
                        Collector.Path = "SilkService-Log";
                    }
                }

                // Validate filter options
                // None, EventName, ProcessID, ProcessName, Opcode
                if (Collector.FilterOption != FilterOption.None)
                {
                    if (String.IsNullOrEmpty((String)Collector.FilterValue))
                    {
                        SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid FilterValue specified", true);
                        return false;
                    }
                    if (Collector.FilterOption == FilterOption.ProcessID)
                    {
                        try
                        {
                            Collector.FilterValue = Convert.ToUInt32((String)Collector.FilterValue);
                        }
                        catch
                        {
                            SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid ProcessID specified", true);
                            return false;
                        }
                    }
                    if (Collector.FilterOption == FilterOption.Opcode)
                    {
                        try
                        {
                            Collector.FilterValue = byte.Parse((String)Collector.FilterValue);
                            if ((byte)Collector.FilterValue > 9)
                            {
                                SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Opcode outside valid range (0-9)", true);
                                return false;
                            }
                        }
                        catch
                        {
                            SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid Opcode specified", true);
                            return false;
                        }
                    }
                    else
                    {
                        Collector.FilterValue = (String)Collector.FilterValue;
                    }
                }

                // Validate Yara folder path
                if (Collector.YaraScan != String.Empty)
                {
                    try
                    {
                        FileAttributes CheckAttrib = File.GetAttributes(Collector.YaraScan);
                        if (!(CheckAttrib.HasFlag(FileAttributes.Directory)))
                        {
                            SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "YaraScan path is not a directory", true);
                            return false;
                        }
                        else
                        {
                            List<string> YaraRuleCollection = Directory.GetFiles(Collector.YaraScan, "*.yar", SearchOption.AllDirectories).ToList();
                            if (YaraRuleCollection.Count == 0)
                            {
                                SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "YaraScan directory does not conatin any *.yar files", true);
                                return false;
                            }
                            else
                            {
                                // We already initialize yara for performace,
                                // new rules can not be added at runtime.
                                Collector.YaraInstance = new YSInstance();
                                Collector.YaraContext = new YSContext();
                                Collector.YaraCompiler = Collector.YaraInstance.CompileFromFiles(YaraRuleCollection, null);
                                Collector.YaraRules = Collector.YaraCompiler.GetRules();
                                YSReport YaraReport = Collector.YaraCompiler.GetErrors();

                                if (!(YaraReport.IsEmpty()))
                                {
                                    SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "The following yara errors were detected", true);

                                    Dictionary<string, List<string>> Errors = YaraReport.Dump();
                                    foreach (KeyValuePair<string, List<string>> Error in Errors)
                                    {
                                        SilkUtility.WriteToServiceTextLog("==> " + Error.Key);
                                        foreach (String ErrorMsg in Error.Value)
                                        {
                                            SilkUtility.WriteToServiceTextLog("    + " + ErrorMsg);
                                        }
                                    }
                                    return false;
                                }

                            }
                        }
                    }
                    catch
                    {
                        SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid YaraScan folder path", true);
                        return false;
                    }

                    if (Collector.YaraOptions == YaraOptions.None)
                    {
                        SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Invalid YaraOptions specified", true);
                        return false;
                    }
                }

                // Overwrite list entry
                Collectors[i] = Collector;

                // We passed all collector parameter checks
                SilkUtility.WriteCollectorGuidMessageToServiceTextLog(Collector.CollectorGUID, "Parameter validation success", false);
            }

            // Validation complete
            return true;
        }
    }
}
