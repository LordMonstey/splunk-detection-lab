window.PORTFOLIO_DATA = {
  indexes: [
    { name: "sysmon", lifetime: 15227, searchable: 390, diskMb: 8, maxMb: 12000, retentionDays: 90, color: "#57b7ff" },
    { name: "windows", lifetime: 4719, searchable: 83, diskMb: 2, maxMb: 8000, retentionDays: 90, color: "#55e6a5" },
    { name: "risk", lifetime: 0, searchable: 0, diskMb: 1, maxMb: 1000, retentionDays: 365, color: "#ffcc66" },
    { name: "notable", lifetime: 0, searchable: 0, diskMb: 1, maxMb: 1000, retentionDays: 365, color: "#ff7a90" }
  ],

  eventCodes: [
    { code: "23", label: "File Delete", count: 171 },
    { code: "11", label: "File Create", count: 131 },
    { code: "13", label: "Registry Value", count: 68 },
    { code: "10", label: "Process Access", count: 13 },
    { code: "7", label: "Image Load", count: 5 },
    { code: "17", label: "Named Pipe", count: 2 }
  ],

  detections: [
    {
      id: "ps-encoded",
      title: "PowerShell Encoded Command",
      techniques: ["T1059.001"],
      tactic: "Execution",
      status: "production",
      risk: 60,
      severity: "high",
      schedule: "Every 5m"
    },
    {
      id: "local-account",
      title: "Local Account Creation",
      techniques: ["T1136.001"],
      tactic: "Persistence",
      status: "production",
      risk: 55,
      severity: "medium",
      schedule: "Every 10m"
    },
    {
      id: "run-key",
      title: "Run Key Modification",
      techniques: ["T1547.001"],
      tactic: "Persistence",
      status: "production",
      risk: 55,
      severity: "medium",
      schedule: "Every 10m"
    },
    {
      id: "rundll32",
      title: "Rundll32 with Unusual Parent",
      techniques: ["T1218.011"],
      tactic: "Defense Evasion",
      status: "production",
      risk: 65,
      severity: "high",
      schedule: "Every 5m"
    },
    {
      id: "mshta",
      title: "Mshta Remote Content Execution",
      techniques: ["T1218.005"],
      tactic: "Defense Evasion",
      status: "production",
      risk: 65,
      severity: "high",
      schedule: "Every 5m"
    },
    {
      id: "regsvr32",
      title: "Regsvr32 Scriptlet Execution",
      techniques: ["T1218.010"],
      tactic: "Defense Evasion",
      status: "production",
      risk: 70,
      severity: "high",
      schedule: "Every 5m"
    },
    {
      id: "certutil",
      title: "Certutil Download or Decode",
      techniques: ["T1140", "T1105"],
      tactic: "Defense Evasion",
      status: "production",
      risk: 60,
      severity: "medium",
      schedule: "Every 10m"
    },
    {
      id: "lsass",
      title: "Suspicious LSASS Process Access",
      techniques: ["T1003.001"],
      tactic: "Credential Access",
      status: "production",
      risk: 90,
      severity: "critical",
      schedule: "Every 5m"
    },
    {
      id: "amsi",
      title: "PowerShell AMSI Bypass",
      techniques: ["T1059.001", "T1562.001"],
      tactic: "Execution",
      status: "testing",
      risk: 75,
      severity: "high",
      schedule: "Every 5m"
    },
    {
      id: "failed-logons",
      title: "Failed Logon Burst",
      techniques: ["T1110.001", "T1110.003"],
      tactic: "Credential Access",
      status: "testing",
      risk: 50,
      severity: "medium",
      schedule: "Every 10m"
    },
    {
      id: "download-cradle",
      title: "PowerShell Download Cradle",
      techniques: ["T1059.001", "T1105"],
      tactic: "Execution",
      status: "testing",
      risk: 70,
      severity: "high",
      schedule: "Every 5m"
    },
    {
      id: "cmd-obfuscation",
      title: "Command Shell Obfuscation",
      techniques: ["T1059.003", "T1027"],
      tactic: "Execution",
      status: "testing",
      risk: 50,
      severity: "medium",
      schedule: "Every 10m"
    },
    {
      id: "scheduled-task",
      title: "Scheduled Task Creation",
      techniques: ["T1053.005"],
      tactic: "Persistence",
      status: "testing",
      risk: 55,
      severity: "medium",
      schedule: "Every 10m"
    },
    {
      id: "registry-helper",
      title: "Registry Persistence Helper",
      techniques: ["T1112", "T1546.012"],
      tactic: "Persistence",
      status: "testing",
      risk: 70,
      severity: "high",
      schedule: "Every 10m"
    },
    {
      id: "ps-entropy",
      title: "Obfuscated PowerShell Entropy",
      techniques: ["T1027"],
      tactic: "Defense Evasion",
      status: "testing",
      risk: 50,
      severity: "medium",
      schedule: "Every 15m"
    },
    {
      id: "defender-tamper",
      title: "Windows Defender Tampering",
      techniques: ["T1562.001"],
      tactic: "Defense Evasion",
      status: "testing",
      risk: 75,
      severity: "high",
      schedule: "Every 5m"
    },
    {
      id: "icacls",
      title: "Icacls Permissive ACL Change",
      techniques: ["T1222.001"],
      tactic: "Defense Evasion",
      status: "testing",
      risk: 45,
      severity: "medium",
      schedule: "Every 15m"
    },
    {
      id: "transfer-tools",
      title: "Curl or Bitsadmin Transfer",
      techniques: ["T1105"],
      tactic: "Command and Control",
      status: "testing",
      risk: 50,
      severity: "medium",
      schedule: "Every 10m"
    }
  ],

  cases: {
    lsass: {
      title: "Suspicious access to LSASS process memory",
      tactic: "CREDENTIAL ACCESS",
      technique: "T1003.001 / OS Credential Dumping: LSASS Memory",
      source: "Sysmon Event ID 10",
      risk: "90 / 100",
      severity: "critical",
      schedule: "Every 5 minutes",
      hypothesis: "A non-standard process requesting high-impact access rights to lsass.exe can indicate credential dumping or an attempted memory read.",
      tuning: "Explicit access-mask selection + Microsoft signer baseline",
      evidence: "assets/evidence/t1003-lsass.png",
      codeLabel: "win_sysmon_t1003.001_lsass_access_suspicious.spl",
      code: [
        "`sysmon_event(10)`",
        "| where like(lower(TargetImage), \"%\\\\lsass.exe\")",
        "| where GrantedAccess IN (\"0x1010\", \"0x1038\", \"0x1410\",",
        "                          \"0x1438\", \"0x1fffff\")",
        "| lookup allowlist_lsass_access process_path AS SourceImage",
        "    OUTPUT signer AS allowlisted_signer",
        "| where isnull(allowlisted_signer)",
        "| eval risk_score=90, severity=\"critical\"",
        "| table _time host user SourceImage TargetImage",
        "        GrantedAccess CallTrace risk_score severity"
      ].join("\n"),
      timeline: [
        { label: "Emulate", detail: "Atomic Red Team T1003.001 generates controlled LSASS access." },
        { label: "Collect", detail: "Sysmon records source process, target image, mask, and call trace." },
        { label: "Match", detail: "The rule selects high-impact rights and removes the approved baseline." },
        { label: "Enrich", detail: "MITRE technique, risk 90, host, user, and process context are attached." },
        { label: "Respond", detail: "Triage process ancestry, signer, account activity, and host isolation need." }
      ]
    },
    regsvr32: {
      title: "Regsvr32 scriptlet execution",
      tactic: "DEFENSE EVASION",
      technique: "T1218.010 / System Binary Proxy Execution: Regsvr32",
      source: "Sysmon Event ID 1",
      risk: "70 / 100",
      severity: "high",
      schedule: "Every 5 minutes",
      hypothesis: "Regsvr32 loading a remotely hosted scriptlet can proxy execution through a trusted Windows binary and evade basic application controls.",
      tuning: "Remote URI + scriptlet flags, with parent/process context retained",
      evidence: "assets/evidence/t1218-regsvr32.png",
      codeLabel: "win_sysmon_t1218.010_regsvr32_scriptlet.spl",
      code: [
        "`sysmon_event(1)`",
        "| where match(lower(Image), \"\\\\\\\\regsvr32\\\\.exe$\")",
        "| where match(lower(CommandLine), \"(/i:|scrobj\\\\.dll)\")",
        "| where match(lower(CommandLine), \"https?://\")",
        "| eval risk_score=70, severity=\"high\"",
        "| table _time host user ParentImage Image CommandLine",
        "        ProcessId ParentProcessId risk_score severity"
      ].join("\n"),
      timeline: [
        { label: "Emulate", detail: "A safe Atomic test invokes the regsvr32 scriptlet execution path." },
        { label: "Collect", detail: "Process creation captures command line, image, parent, user, and hashes." },
        { label: "Match", detail: "The analytic requires both scriptlet indicators and a remote URI." },
        { label: "Enrich", detail: "T1218.010 and a risk score of 70 make the event analyst-ready." },
        { label: "Respond", detail: "Review the remote resource, process tree, DNS, and adjacent downloads." }
      ]
    },
    powershell: {
      title: "PowerShell encoded command",
      tactic: "EXECUTION",
      technique: "T1059.001 / Command and Scripting Interpreter: PowerShell",
      source: "Sysmon Event ID 1",
      risk: "60 / 100",
      severity: "high",
      schedule: "Every 5 minutes",
      hypothesis: "Encoded PowerShell flags hide command intent from casual inspection and are a strong triage signal when combined with full process context.",
      tuning: "Flag variants + encoded payload length + parent/process context",
      evidence: "assets/evidence/t1059-powershell.png",
      codeLabel: "win_sysmon_t1059.001_powershell_encoded.spl",
      code: [
        "`sysmon_event(1)`",
        "| where match(lower(Image), \"\\\\\\\\powershell(\\\\.exe)?$\")",
        "| where match(lower(CommandLine),",
        "    \"-(enc|encodedcommand|e)\\\\s+[a-z0-9+/=]{16,}\")",
        "| eval risk_score=60, severity=\"high\"",
        "| table _time host user ParentImage Image CommandLine",
        "        ProcessId ParentProcessId risk_score severity"
      ].join("\n"),
      timeline: [
        { label: "Emulate", detail: "Atomic Red Team runs a benign encoded PowerShell payload." },
        { label: "Collect", detail: "Sysmon preserves the command line and complete parent process context." },
        { label: "Match", detail: "Flag aliases and a minimum payload length reduce substring noise." },
        { label: "Enrich", detail: "T1059.001, severity, risk, host, and user are added consistently." },
        { label: "Respond", detail: "Decode the payload, inspect ancestry, and correlate network activity." }
      ]
    }
  }
};
