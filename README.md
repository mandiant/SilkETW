# SilkETW & SilkService

SilkETW & SilkService are flexible C# wrappers for ETW, they are meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection. While both projects have obvious defensive (and offensive) applications they should primarily be considered as research tools.

For easy consumption, output data is serialized to JSON. The JSON data can either be written to file and analyzed locally using PowerShell, stored in the Windows eventlog or shipped off to 3rd party infrastructure such as [Elasticsearch](https://www.elastic.co/).

For more information on the future of SilkETW & SilkService, see the [Roadmap](#roadmap) section.

## Media

For more background on SilkETW and SilkService please consult the following resources.

* SilkETW: Because Free Telemetry is … Free! - [here](https://www.fireeye.com/blog/threat-research/2019/03/silketw-because-free-telemetry-is-free.html)
* SilkETW & SilkService BlackHat Arsenal 2019 - [here](https://github.com/FuzzySecurity/BH-Arsenal-2019)
* Threat Hunting with ETW events and HELK — Part 1: Installing SilkETW (by [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)) - [here](https://medium.com/threat-hunters-forge/threat-hunting-with-etw-events-and-helk-part-1-installing-silketw-6eb74815e4a0)
* Threat Hunting with ETW events and HELK — Part 2: Shipping ETW events to HELK (by [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)) - [here](https://medium.com/threat-hunters-forge/threat-hunting-with-etw-events-and-helk-part-2-shipping-etw-events-to-helk-16837116d2f5)

## Implementation Details

### Libraries

SilkETW is buit on .Net v4.5 and uses a number of 3rd party libraries, as shown below. Please see [LICENSE-3RD-PARTY](LICENSE-3RD-PARTY.txt) for further details.

```
ModuleId                                 Version LicenseUrl                                                   
--------                                 ------- ----------                                                   
McMaster.Extensions.CommandLineUtils     2.3.2   https://licenses.nuget.org/Apache-2.0                        
Microsoft.Diagnostics.Tracing.TraceEvent 2.0.36  https://github.com/Microsoft/perfview/blob/master/LICENSE.TXT
Newtonsoft.Json                          12.0.1  https://licenses.nuget.org/MIT                               
System.ValueTuple                        4.4.0   https://github.com/dotnet/corefx/blob/master/LICENSE.TXT     
YaraSharp                                1.3.1   https://github.com/stellarbear/YaraSharp/blob/master/LICENSE
```

## SilkETW

### Command Line Options

Command line usage is fairly straight forward and user input is validated in the execution prologue. See the image below for further details.

![Help](Images/help.png)

## SilkService

### Caveat

SilkService was created because a large number of people wanted to run SilkETW headless and perform ETW collection for multiple sources at the same time. While there is obvious appeal to this, the following points should be kept in mind.

* SilkETW & SilkService were created by a one-man engineering army, ([@FuzzySec](https://twitter.com/fuzzysec)), they are not backed by a department of developers and as such may contain bugs. If you do encounter bugs or see ways to improve these projects you are strongly encouraged to file tickets and/or submit pull requests.
* ETW collection can be resource intensive. Do not roll out SilkService across a wide range of hosts without thorough performance testing. Ensure that the configuration can run stably on your least powerful machines.

### Setup

After compiling or downloading the release package you can install the service by issuing the following command from an elevated prompt.

```
sc create SillkService binPath= "C:\Path\To\SilkService.exe" start= demand
```

### Configuration

SilkService ingests an XML configuration file, "SilkServiceConfig.xml", which should be placed in the same directory as the service binary. An example configuration file can be seen below.

```xml
<SilkServiceConfig>
	<!--
		This is a user collector
		-> Microsoft-Windows-DotNETRuntime
		-> GUID or string based name
	-->
	<ETWCollector>
		<Guid>45c82358-c52d-4892-8237-ba001d396fb4</Guid>
		<CollectorType>user</CollectorType>
		<ProviderName>e13c0d23-ccbc-4e12-931b-d9cc2eee27e4</ProviderName>
		<UserKeywords>0x2038</UserKeywords>
		<OutputType>url</OutputType>
		<Path>https://some.elk:9200/NetETW/_doc/</Path>
	</ETWCollector>
	<!--
		This is a user collector
	-->
	<ETWCollector>
		<Guid>6720babc-dedc-4906-86b9-d0bc0089ec50</Guid>
		<CollectorType>user</CollectorType>
		<ProviderName>Microsoft-Windows-DNS-Client</ProviderName>
		<OutputType>eventlog</OutputType>
		<YaraScan>C:\Some\Path\RuleFolder</YaraScan>
		<YaraOptions>Matches</YaraOptions>
	</ETWCollector>
	<!--
		This is a kernel collector
	-->
	<ETWCollector>
		<Guid>21ac2393-3bbb-4702-a01c-b593e21913dc</Guid>
		<CollectorType>kernel</CollectorType>
		<KernelKeywords>Process</KernelKeywords>
		<OutputType>file</OutputType>
		<Path>C:\Users\b33f\Desktop\kproc.json</Path>
	</ETWCollector>
</SilkServiceConfig>
```

Note that each ETWCollector element should have a random GUID, this is used for internal tracking and logging purposes. You can generate GUID's in PowerShell using the following command:

```powershell
PS C:\> [guid]::NewGuid()

Guid
----
eee52b87-3f32-4651-b0c3-e7bb9af334aa
```

### Auditing

At runtime SilkService will create a "Logs" subfolder to record service runtime information. This is an invaluable resource to poll the service state, verify service parameter validation and review error information. SilkService has a preference to shut down gracefully if it encounters any type of error, even if such an error does not strictly require termination. This design decision was made purposely as it is not a sound strategy to have dangling collectors or partial operability.

**Always consult the service log if the service shuts itself down!**

### Something went wrong?

It is always possible that something goes wrong. Consult the service log for further details. While SilkService is configured to terminate and clean up ETW collectors or error it is possible that a stale collector remains registered after process termination. To list running collectors you can use the following command.

```
logman -ets
```

If any stale collectors are identified they can be removed by issuing the following commands from an elevated prompt.

```powershell
Get-EtwTraceProvider |Where-Object {$.SessionName -like "SilkService*"} |ForEach-Object {Stop-EtwTraceSession -Name $.SessionName}
Get-EtwTraceProvider |Where-Object {$_.SessionName -like "SilkService*"} |Remove-EtwTraceProvider
```

## Output Format

### JSON Output Structure

The JSON output, prior to serialization, is formatted according to the following C# struct.

```csharp
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
```

Note that, depending on the provider and the event type, you will have variable data in the XmlEventData hash table. Sample JSON output can be seen below for "Microsoft-Windows-Kernel-Process" -> "ThreadStop/Stop".

```json
{
   "ProviderGuid":"22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716",
   "YaraMatch":[

   ],
   "ProviderName":"Microsoft-Windows-Kernel-Process",
   "EventName":"ThreadStop/Stop",
   "Opcode":2,
   "OpcodeName":"Stop",
   "TimeStamp":"2019-03-03T17:58:14.2862348+00:00",
   "ThreadID":11996,
   "ProcessID":8416,
   "ProcessName":"N/A",
   "PointerSize":8,
   "EventDataLength":76,
   "XmlEventData":{
      "FormattedMessage":"Thread 11,996 (in Process 8,416) stopped. ",
      "StartAddr":"0x7fffe299a110",
      "ThreadID":"11,996",
      "UserStackLimit":"0x3d632000",
      "StackLimit":"0xfffff38632d39000",
      "MSec":"560.5709",
      "TebBase":"0x91c000",
      "CycleTime":"4,266,270",
      "ProcessID":"8,416",
      "PID":"8416",
      "StackBase":"0xfffff38632d40000",
      "SubProcessTag":"0",
      "TID":"11996",
      "ProviderName":"Microsoft-Windows-Kernel-Process",
      "PName":"",
      "UserStackBase":"0x3d640000",
      "EventName":"ThreadStop/Stop",
      "Win32StartAddr":"0x7fffe299a110"
   }
}
```

## Post-Collection

### Filter data in PowerShell

You can import JSON output from SilkETW in PowerShell using the following simple function.

```powershell
function Get-SilkData {
	param($Path)
	$JSONObject = @()
	Get-Content $Path | ForEach-Object {
		$JSONObject += $_ | ConvertFrom-Json
	}
	$JSONObject
}
```

In the example below we will collect process event data from the Kernel provider and use image loads to identify Mimikatz execution. We can collect the required data with the following command.

```
SilkETW.exe -t kernel -kk ImageLoad -ot file -p C:\Users\b33f\Desktop\mimikatz.json
```

With data in hand it is easy to sort, grep and filter for the properties we are interested in.

![Mimikatz](Images/mimi.png)

### Yara

SilkETW includes Yara functionality to filter or tag event data. Again, this has obvious defensive capabilities but it can just as easily be used to augment your ETW research.

In this example we will use the following Yara rule to detect Seatbelt execution in memory through Cobalt Strike's execute-assembly.

```
rule Seatbelt_GetTokenInformation
{
	strings:
		$s1 = "ManagedInteropMethodName=GetTokenInformation" ascii wide nocase
		$s2 = "TOKEN_INFORMATION_CLASS" ascii wide nocase
		$s3 = /bool\(native int,valuetype \w+\.\w+\/\w+,native int,int32,int32&/
		$s4 = "locals (int32,int64,int64,int64,int64,int32& pinned,bool,int32)" ascii wide nocase
	
	condition:
		all of ($s*)
}
```

We can start collecting .Net ETW data with the following command. The "-yo" option here indicates that we should only write Yara matches to disk!

```
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -l verbose -y C:\Users\b33f\Desktop\yara -yo matches -ot file -p C:\Users\b33f\Desktop\yara.json
```

We can see at runtime that our Yara rule was hit.

![Seatbelt](Images/seatbelt.png)

Note also that we are only capturing a subset of the "Microsoft-Windows-DotNETRuntime" events (0x2038), specifically: JitKeyword, InteropKeyword, LoaderKeyword and NGenKeyword.

## How to get SilkETW & SilkService?

You can either download the source and compile it in Visual Studio. Please note that you can get the community edition of Visual Studio free of charge. Or you can grab the latest pre-built version from [releases](https://github.com/fireeye/SilkETW/releases).

## Future Work

### Changelog

For details on version specific changes, please refer to the [Changelog](Changelog.txt).

### RoadMap

* Offer users the option to write trace data to disk as *.etl files.
* ~~Offer users the option to write trace data to the Windows event log.~~ **(v0.5+)**
* ~~Offer users pre-compiled releases.~~ **(v0.6+)**
* ~~Create a separate instance (SilkService) which can be deployed as a service with a configuration file.~~ **(v0.7+)**
* Suggestions welcome!
