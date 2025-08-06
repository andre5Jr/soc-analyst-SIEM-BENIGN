📝 Project Title:

TryHackMe – Benign: Detecting LOLBIN Abuse in Host-Centric Logs via Splunk

🎯 Objective:

Analyze host-centric Windows process execution logs (Event ID 4688) ingested into Splunk to detect unauthorized user accounts, LOLBIN abuse, and malicious payload delivery. This investigation focuses on identifying post-compromise actions taken on an HR department host following suspicious IDS alerts.

🛠️ Tools Used:

Splunk (Search & Reporting)
Windows Event Logs (Event ID 4688)
LOLBIN Identification (bitsadmin, certutil, etc.)
Process Behavior Analysis
Base64 and Command Decoding Tools

❌ Skills Demonstrated:

Event 4688-based threat hunting
User and host behavior correlation
Detection of LOLBIN (Living Off the Land Binary) abuse
Payload delivery analysis and flag extraction
Incident triage across segmented networks

Project Overview
This investigation was conducted in the context of a simulated enterprise where the network is divided into IT, HR, and Marketing departments. Following an IDS alert about potentially suspicious process execution, logs from the affected host were ingested into Splunk under the win_eventlogs index.

Using Windows Event ID 4688, which records every process creation on an endpoint, we tracked indicators of compromise including malicious account creation, scheduled task usage, and payload downloads using system binaries (LOLBINs). The ultimate goal was to extract a malicious flag embedded in the downloaded file and identify the full URL used by the attacker.

Task Breakdown

✏️ Task 1: How many logs are ingested from the month of March, 2022?
⭕️ Objective: Determine how many logs were ingested from March 2022.

⭕️ Method:

Set time filter in Splunk to March 1–31, 2022.
Run:

spl
Copy
Edit
index=win_eventlogs EventCode=4688 | stats count

🔱 Answer: 13959

✏️ Task 2: Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?
⭕️ Objective: Detect the suspicious or unknown user account created by the attacker.

⭕️ Method:

spl
Copy
Edit
index=win_eventlogs EventCode=4688 | stats count by Account_Name
Compare usernames against known users in each department (HR: Haroon, Chris, Diana). Identify anomalies.

🔱 Answer: Amel1a

✏️ Task 3: Which user from the HR department was observed to be running scheduled tasks?
⭕️ Objective: Determine which HR user executed schtasks.exe.

⭕️ Method:

spl
Copy
Edit
index=win_eventlogs CommandLine="*schtasks.exe*"
Filter for HR usernames (Haroon, Chris, Diana). Look at Account_Name field in the event.

🔱 Answer: Chris.fort

✏️ Task 4: Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.
⭕️ Objective: Identify which HR user ran a system binary to fetch a payload.

⭕️ Method:

spl
Copy
Edit
index=win_eventlogs CommandLine="*http*"
Cross-reference Account_Name with HR users. Investigate who ran processes like bitsadmin.exe.

🔱 Answer: haroon

✏️ Task 5: To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?
⭕️ Objective: Name the system binary used to download the file.

⭕️ Method:

From Task 4 results, extract the binary used in New_Process_Name or CommandLine.

Common LOLBINs:

bitsadmin.exe

certutil.exe

powershell.exe

🔱 Answer: certutil.exe

✏️ Task 6: What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)
⭕️ Objective: Find the date the LOLBIN was executed.

⭕️ Method:

Check _time field of the log entry from Task 5.

Format the date as YYYY-MM-DD.

🔱 Answer: 2022-03-04

✏️ Task 7: Which third-party site was accessed to download the malicious payload?
⭕️ Objective: Identify the third-party site used for hosting the payload.

⭕️ Method:

spl
Copy
Edit
index=win_eventlogs CommandLine="*http*"
Inspect CommandLine or ParentCommandLine for domains such as transfer.sh, pastebin, anonfiles, etc.

🔱 Answer: controlc.com

✏️ Task 8: What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?
⭕️ Objective: Extract the name of the file saved to disk.

⭕️ Method:

Look in the CommandLine for bitsadmin or certutil download commands.
Identify the file name after output, outfile, or at the end of the command.

🔱 Answer: benign.exe

✏️ Task 9: The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?
⭕️ Objective: Reveal the malicious content pattern (e.g., THM{...}) in the downloaded file.

⭕️ Method:

Inspect the file contents (e.g., with type, cat, strings, or external analysis).
Look for string pattern: THM{.*}

🔱 Answer: THM{KJ&*H^B0}

✏️ Task 10: What is the URL that the infected host connected to?
⭕️ Objective: Identify the complete URL used to retrieve the malicious payload.

⭕️ Method:

Backtrack to the LOLBIN execution event from Task 5.
Extract full URL from the CommandLine field.

🔱 Answer: https://controlc.com/e4d11035

🔍 Analysis and Reflection

💡 Challenges Faced:

Separating legitimate admin activity from malicious impersonation

Tracing LOLBIN activity back to users in a segmented network

Identifying obfuscated or minimal command-line executions

💡 Lessons Learned:

Windows Event ID 4688 offers deep insight into attacker behavior

LOLBINs are commonly abused and often go unnoticed by AV/EDR

Context-aware filtering (user + department + time) improves detection accuracy

💡 Relevance to SOC Analyst Roles:

Reinforces log parsing and event reconstruction skills

Builds familiarity with post-exploitation techniques

Teaches how to enrich Splunk data with behavioral logic

💡 Relevance to Penetration Testing / Red Teaming:

Illustrates how attackers blend into normal activity

Shows how simple payload delivery via built-in tools can succeed

Emphasizes the importance of defense-in-depth and user monitoring

✅ Conclusion

💡 Summary:
Using Splunk and Windows Event ID 4688 logs, this investigation uncovered a suspicious user account, confirmed the use of bitsadmin.exe to download a payload, and identified a malicious file saved from a third-party file host. Through precise filtering and analysis, we extracted the malicious flag and the complete URL used in the attack campaign.

💡 Skills Gained:

Process execution analysis in Splunk

Detection of LOLBIN-based post-exploitation

Attribution of user actions across segmented environments

Extraction of flags and indicators from threat activity

💡 Next Steps:

Configure Splunk alerts for LOLBINs used with external URLs

Correlate Event IDs 4688 with file modification logs (Event ID 4663)

Simulate similar attacks in a lab environment to build detection playbooks

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T1-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T1-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T2-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T3-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T3-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T3-3.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T4-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T5-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T6-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T7-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T8-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T9-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T9-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-BENIGN/blob/043c486c7dbff66b940da6aac6d5b465d77f9397/T10-1.png)  



