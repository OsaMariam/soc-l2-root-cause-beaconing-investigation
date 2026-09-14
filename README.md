# SOC Level 2 Investigation: Root Cause Analysis of a Malware Beaconing Incident

**TryHackMe, Senior Security Analyst Intro | SOC Level 2 Learning Path | July 2026**

Taking an escalated beaconing alert and tracing it back three days and three processes to the actual entry point, then closing the detection gap that let it through.

**[Read the full report with all 9 screenshots (PDF)](SOC-L2-Root-Cause-Investigation.pdf)** for the original document exactly as written, with every figure.

---

## Goal

This lab was designed to simulate a full working day as a SOC Level 2 senior security analyst. Instead of triaging alerts from a queue like a Level 1 analyst, the objective was to take an escalated EDR alert about malware beaconing on a corporate laptop (LPT-0152) and find the root cause of the infection. That meant building a complete event timeline in the SIEM, deciding how to contain the threat, closing the detection gap that allowed the malware in, and handling an incoming threat intelligence report.

The bigger goal for me was practising the mindset shift from Level 1 to Level 2 work. **A Level 1 analyst asks whether an alert is a true or false positive. A Level 2 analyst asks how the threat got in, what else it touched, and why existing detections missed it.**

## Tools used

- TryHackMe SOC Level 2 simulation environment (browser based SOC platform)
- SIEM with Splunk style SPL search for event timeline reconstruction
- Sysmon telemetry from Windows endpoints (Event ID 1, Process Creation)
- SIEM Rules module for detection rule development
- Threat intelligence reports (CTI feed within the simulation)
- Internal communication channels (IT Team Hotline and SOC Slack channel simulation)

## What I did

Received an escalated EDR alert from the L1 team reporting a malware infection with beaconing activity on LPT-0152, a corporate laptop used by an external contractor.

Queried the SIEM for Sysmon process creation events on the affected host and built a table of timestamps, users, command lines, and parent processes to reconstruct the event timeline.

Traced the process chain backwards: `rundll32.exe` loading `beacon.dll` from `C:\Windows\Temp` was spawned by `loader.exe` in the user's AppData\Roaming folder, which was launched by a file named `ReleaseNotes.pdf.exe` in the Downloads folder.

Identified `ReleaseNotes.pdf.exe` as a double extension executable disguised as a PDF, confirming the initial infection vector, and verified the data stealer infection with threat intelligence tools.

Made the containment decision: isolate LPT-0152 from the network, complete the analysis, and clean the host, rather than shutting down the entire network or waiting on the user for answers.

Investigated why the malicious file went undetected for three days after being downloaded through Microsoft Edge, and closed the gap by building a detection rule covering double extension file downloads.

Reviewed an incoming threat intelligence report about the Akira ransomware group actively exploiting a SonicWall SSL-VPN vulnerability targeting our region, then escalated it through the correct channels so the temporary mitigation could be applied before the vendor patch.

## Investigation summary

The investigation started with a simple question. The EDR flagged beaconing on LPT-0152, but where did it come from? Rather than working only with what the alert showed, I went to the SIEM and pulled all process creation events for the host:

```
index=windows host=LPT-0152 EventCode=1
| table _time host user CommandLine ParentImage
```

Sorting the results into a timeline made the infection chain readable. The beaconing came from `rundll32.exe` executing `beacon.dll` out of `C:\Windows\Temp`. Its parent process was `loader.exe` sitting in the user j.miller's AppData\Roaming folder, which is a common staging location for malware because standard users can write there without admin rights.

Following the chain one more step back, `loader.exe` had been launched by `ReleaseNotes.pdf.exe` from the Downloads folder. **That double extension was the giveaway.** A real PDF does not end in .exe. The user thought they were opening release notes and actually executed a data stealer.

With the root cause confirmed, the next step was the response decision. The options were shutting down the entire network, asking the user about the files and waiting, or isolating the host.

I chose to isolate LPT-0152, finish the analysis, and clean the host. My reasoning: shutting down the whole network for a single infected endpoint causes more business damage than the malware itself, and waiting on a user's reply leaves an active data stealer running. Host isolation stops the bleeding immediately while preserving the evidence needed to complete the investigation.

Resolving the incident was not the end of the job. Checking back through the timeline, `ReleaseNotes.pdf.exe` had been downloaded through Microsoft Edge three days earlier and not a single rule fired on it. That is a detection gap, and leaving it open means the same attack works again tomorrow.

Blaming the user or pushing the issue back to L1 does not fix anything, so I built a detection rule covering double extension downloads. Now the SIEM flags this technique automatically instead of relying on someone noticing it during an investigation.

The final part of the day was proactive rather than reactive. A threat intelligence report came in about the Akira ransomware group exploiting a SonicWall SSL-VPN vulnerability, with our region heavily targeted and no vendor patch available until the next day. The only known mitigation was disabling LDAP within the SSL-VPN feature on the firewall.

Since the SOC does not manage firewalls directly, the right move was communication. I notified the IT team through the hotline for the urgent firewall change and posted to the SOC Slack channel so every analyst was aware and watching for related activity.

## Results and findings

**Root cause identified.** The beaconing on LPT-0152 was traced to a data stealer infection. Full chain: `ReleaseNotes.pdf.exe` downloaded via Microsoft Edge, then `loader.exe` staged in AppData\Roaming, then `rundll32.exe` executing `beacon.dll` from `C:\Windows\Temp`.

**Initial infection vector.** A double extension executable disguised as a PDF document, a social engineering technique that relies on Windows hiding file extensions by default.

**Containment outcome.** LPT-0152 was isolated from the network, the analysis was completed, and the host was cleaned. The threat was contained without unnecessary business disruption.

**Detection gap closed.** The malicious download sat undetected for three days. A new detection rule covering double extension downloads now closes that gap for future attacks.

**Proactive defence.** The Akira and SonicWall SSL-VPN threat was escalated to the IT team and broadcast to the SOC, enabling the temporary mitigation to be applied ahead of the vendor patch.

**Challenge result.** Completed all decision points with optimal responses and finished the room's full challenge simulation.

## Skills demonstrated

- Alert triage and escalation handling, L1 to L2 workflow
- SIEM investigation and log analysis using SPL queries
- Event timeline reconstruction with Sysmon Event ID 1 (process creation)
- Root cause analysis and process chain (parent and child) analysis
- Malware analysis fundamentals: staging directories, double extension executables, DLL execution via rundll32
- Incident response decision making and host containment and isolation
- Detection engineering: identifying detection gaps and building new SIEM rules
- Threat intelligence analysis and risk based prioritisation
- Incident communication and stakeholder escalation (IT and SOC channels)
- Security documentation and investigation reporting

## What I learned

This lab changed how I think about investigations. Coming from Level 1 style triage, my habit was to answer the question in front of me: is this alert real or not? This room forced me to keep going after that answer, to trace the infection back three days and three processes to find the actual entry point. The alert was rundll32 beaconing, but the real story was a fake PDF a contractor downloaded earlier in the week.

The containment decision taught me that incident response is about proportion, not just speed. Shutting everything down feels safe but punishes the whole business for one infected laptop. Isolating the single host achieves the same protection with a fraction of the damage.

I also learned that a resolved incident with an open detection gap is only half resolved. If the same file can land undetected tomorrow, the work is not done. Building the detection rule felt like the most valuable part of the exercise, because it turns one investigation into permanent coverage.

Finally, the threat intelligence task reminded me that a lot of L2 work is communication. I could not patch the SonicWall vulnerability myself. The value I added was getting the right information to the right people fast. Knowing who to call and what to tell them is a skill in itself, and it is one I want to keep sharpening as I work towards a SOC analyst role.
