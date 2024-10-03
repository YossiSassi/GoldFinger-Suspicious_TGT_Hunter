<h1><span style="color: #2b2301;">GoldFinger - Suspicious Kerberos TGT Detection for </span><span style="color: #008080;">h</span><span style="color: #2b2301;">Ac</span><span style="color: #008080;">K</span><span style="color: #2b2301;">tive Directory</span></h1>
<hr />
<h2 style="color: #2e6c80;">Description</h2>
GoldFinger is a Suspicious TGT detector - focusing on <strong>Golden Tickets & potential Pass-The-Hash attempts.<BR>
GoldFinger collects, analyzes & hunts for indicators of potential Golden Tickets & Pass-The-Hash on Domain-Joined EndPoints.</strong><BR>
It is essentially built from a TGT Collector - collecting all Authentication Tickets from all Sessions on available Domain Endpoints, and then a main script that checks for a set of anomalies that indicate a suspicious manipulation.<BR>
It has two collection methods - Either WinRM (default), or SMB (using PaExec, via the admin$ share). WinRM has an option to Enable WinRM remotely, as a separate parameter.<BR>
Before running the tool, make sure the other script ('GoldFinger-EndPointTicketCollector.ps1') is available in the same folder, and then Run this Script with or without relevant parameters.<BR>
Requirements: The script needs to run as a user that has Local Admin permissions on all targetted EndPoints.<BR>
<BR><B>It is HIGHLY recommended to exclude the file 'GoldFinger-EndPointTicketCollector.ps1', as well as the PaExec known open source executable (if SMB will be used) from AV/EDR engines on EndPoints *BEFORE* running the main script, to allow smoother operations & avoid blocking and/or false detections as 'malicious'/HackTool.<BR>Common blocking of the tool would be a detection on the EndPoint of 'PowerView!ams!'. You'll need to add the exclusion of the script.</B><br><br>
<b>You can ensure exclusion of both PaExec binary and Goldfinger-EndPointCollector.ps1 by using the following hashes, on any EPP (e.g. Av/EDR):<br>
'paExec.exe' SHA256: AB50D8D707B97712178A92BBAC74CCC2A5699EB41C17AA77F713FF3E568DCEDB , MD5: B1DFB4F9EB3E598D1892A3BD3A92F079<br>
'GoldFinger-EndPointTicketCollector.ps1' SHA256: CC437D7CB87DAC52BD03A6F1385EED6BB673445E4DAA4ACB6AE6508A098D372C, MD5: 92FD323A69877DFFC2C5136B457CCCF4
</b>
<h2 style="color: #2e6c80;">Short description</h2>
Purpose: TGT collector|analyzer|hunting for indicators of potential Golden Tickets & Pass-The-Hash on EndPoints in the domain (research in progress).
<BR>Requirements: Need to have either WinRM enabled and running on EndPoints (has an option to Enable WinRM remotely for you), or SMB access (using PaExec, via admin$ share)
<BR>Instructions: Make sure the other script ('GoldFinger-EndPointTicketCollector.ps1') is available in the same folder, and then Run .\GoldFinger-Main.ps1 Script.
<BR>NOTE1: Run the script with a user that has Local Admin permissions on all targetted EndPoints.
<BR>NOTE2: <strong>It is also HIGHLY recommended to "whitelist"/exclude the file 'GoldFinger-EndPointTicketCollector.ps1' from AV/EDR engines settings on the EndPoints *BEFORE* running the main script</strong>, to allow smoother operations & avoid false detections as 'malicious'/HackTool.
<BR><BR>
You can also run the GoldFinger-EndPointTicketCollector.ps1 script locally on a system, redirect its output to a text file, and separately analyze the output using this script, using -TextFileToAnalyze option, providing the full path to a text file containing re-directed output from the EndPoint-Collector script.<BR>
e.g. <BR>
On the suspicious system, run:<BR>
.\GoldFinger-EndPointTicketCollector.ps1 > c:\temp\tickets.txt<BR>
and then, from your host, run the main script using the parameter to analize offline:<BR>
.\GoldFinger-Main.ps1 -TextFileToAnalyze c:\temp\tickets.txt 
<BR>

<h2 style="color: #2e6c80;">Parameters</h2>
.PARAMETER CollectionMethod<BR>
The protocol/service used to collect the tickets from the domain-joined endpoint. Default is WinRM (PSRemoting).<BR>
The 'SMB' option uses PaExec "behind the scenes" (no need to obtain the executable separately) to access the admin$ share of the remote EndPoint.<BR>
<BR>
.PARAMETER SMBTimeOut<BR>
The timeout for each SMB session, in Seconds. Default is 30 seconds.<BR>
<BR>
.PARAMETER WorkstationsOnly<BR>
If specified, the tool will targets only Enabled computer accounts with Client Operating systems (Excluding Servers).<BR>
<BR>
.PARAMETER IncludeComputerTGT<BR>
By default, the tool focuses on user TGTs. if this parameter is specified, it will also collect Computer TGTs (useful as Ticket collector).<BR>
<BR>
.PARAMETER DomainDN<BR>
The distinguished domain name, in format of "DC=Domain,DC=com". Allow querying of other domains. Default is current domain (user/machine joined domain).<BR>
<BR>
.PARAMETER ScriptFolder<BR>
The folder that holds the 'GoldFinger-EndPointTicketCollector.ps1' additional script. Also all outputs are saved there. Default is current/main script directory.<BR>
<BR>
.PARAMETER Credential<BR>
Optional for specifying alternate credentials to be used to access remote EndPoints. default is currently logged-on/running user.<BR>
<BR>
.PARAMETER StartWinRMServiceOnEndPoints<BR>
Tries to start the WinRM Service on the remote EndPoints, if it is Not running. Reports success or failure.<BR>
<BR>
.PARAMETER EnablePSRemotingOnEndPoints<BR>
Tries to enable WinRM/PSRemoting on the remote EndPoints, if it is Not enabled (No relevant SPN found in AD). Reports success or failures.<BR>
<BR>
.PARAMETER ComputerName<BR>
Targets a specific computer(s). By default, the tool targets ALL enabled & accessible computer accounts in the domain.<BR>
<BR>
.PARAMETER ExcludedComputerName<BR>
Excludes a specific computer(s) from the domain, and not targeting/collecting tickets from those computers. useful to "skip" certain servers that may produce a heavy workload or false positive (e.g. Management Servers that might perform multiple TGT operations as part of how they work).<BR>
Note that by default, the script skips domain controllers (Not relevant for these checks) and SCCM Servers.<BR>
<BR>
.PARAMETER TextFileToAnalyze<BR>
The full path to a text file containing re-directed output from the EndPointCollector script.<BR>
<BR>
.PARAMETER LoggingLevel<BR>
The level of logging requested. <BR>
Default value is 'FailedJobsOnly' and is useful for minimal logging of WinRM collection method.<BR>
The value 'Full' is useful mainly for SMB collection method, for detailed/verbose reports of each endPoint and the current status of the script run.<BR>
<BR>
.PARAMETER LogName<BR>
The file name and location of the logging file, e.g. "c:\temp\GoldFinger.log".<BR>
By default, if LoggingLevel=Full was specified, the log file is kept in the current folder, named as "GoldFinger_LOG_ddMMyyyyHHmmss.log"<BR>
<h2 style="color: #2e6c80;">Usage examples</h2>
.\GoldFinger-Main.ps1<BR>
Runs the tool with default options, on all enabled computer accounts in the domain, with WinRM accessible.<BR>
<BR>
.\GoldFinger-Main.ps1 -CollectionMethod SMB -LoggingLevel Full -Verbose<BR>
Runs the tool using the SMB protocol. uses PaExec to access admin$ share, copy the Collector script, execute it, and collect back the data.<BR>
The 'LoggingLevel Full' parameter will create a detailed log of all the entire process & access attempts.<BR>
the '-Verbose' parameter show additional information to the console/screen while running.<BR>
<BR>
.\GoldFinger-Main.ps1 -WorkstationsOnly -CollectionMethod SMB -SMBTimeOut 60<BR>
Runs the tool using the SMB protocol, yet on workstation OS only - Server operating system will be excluded.<BR>
Uses SMB (PaExec to access admin$ share, copy the Collector script, execute it, and collect back the data).<BR>
The '-SMBTimeOut 60' parameter extends the default 30 seconds SMB timeout to 60 seconds.<BR>
<BR>
.\GoldFinger-Main.ps1 -IncludeComputerTGT -WorkstationsOnly<BR>
Runs the tool using WinRM (default) on workstations OS only, and reports all TGTs, including Computer TGTs.<BR>
<BR>
.\GoldFinger-Main.ps1 -DomainDN "dc=ACME,DC=Local" -Credential (Get-Credential)<BR>
Runs the tool using WinRM (default) on a remote domain (acme.local), using specific credentials.<BR>
The '-Credential (Get-Credential)' parameter will prompt the user to enter credentials to be used to access remote EndPoints as Local Admin.<BR>
<BR>
.\GoldFinger-Main.ps1 -StartWinRMServiceOnEndPoints -EnablePSRemotingOnEndPoints -ComputerName "PC01"<BR>
Runs the tool using WinRM (default) on only one computer (PC01), and will try to Enable and Start the WinRM service on that host, remotely.<BR>
Note: Might require an additional run *After* the service was enabled.<BR>
<BR>
.\GoldFinger-Main.ps1 -ComputerName "PC01","PC02","SRV01" -LoggingLevel Full -CollectionMethod SMB<BR>
Runs the tool using SMB on 3 specific computers only, with full logging of detailed process and connection attempts.<BR>
<BR>
.\GoldFinger-Main.ps1 -WorkstationsOnly -ExcludedComputerName $(Get-Content c:\temp\ExcludedComputers.txt)<BR>
Runs the tool using WinRM on workstations only (Client OS), while excluding/skipping a specific list of hosts - specified at the 'c:\temp\ExcludedComputers.txt' file.<BR>
<BR>
.\GoldFinger-Main.ps1 -WorkstationsOnly -ExcludedComputerName $ExcludedComputers<BR>
Runs the tool using WinRM on workstations only (Client OS), while excluding/skipping a specific list of hosts, previously saved into a variable named $ExcludedComputers<BR>
<BR>
.\GoldFinger-Main.ps1 -TextFileToAnalyze c:\temp\tickets.txt<BR>
Analyzes the input text file containing re-directed result from the EndPoint-Collector script.<BR>
<hr />
Reserach & code by 1nTh35h311 (<a title="@yossi_sassi" href="https://twitter.com/yossi_sassi" target="_blank">@yossi_sassi</a>), 10root Cyber Security
<h4 style="color: #2e6c80;"><span style="color: #333399;">
Collector script section heavily based on work by Jared Atkinson (@jaredcatkinson) & Matthew Graeber (@mattifestation) - Thank you!</span></h4>
<p><strong>Comments and suggestions are <a href="mailto:yossis@protonmail.com" target="_blank"><span style="color: #333333;">welcome</span></a></strong></p>
<hr />
<h2 style="color: #2e6c80;">Other useful resources</h2>
<p><strong><a title="HacktiveDirectory.com" href="https://www.hacktivedirectory.com" target="_blank">hacktivedirectory.com</a> - </strong>Useful forensic tools for AD Security</p>
<p>&nbsp;</p>
