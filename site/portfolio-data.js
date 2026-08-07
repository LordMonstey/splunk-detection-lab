window.LAB_DATA = {
  meta: {
    project: "Splunk Administration & Detection Engineering Lab",
    author: "A.S",
    splunkVersion: "10.2.1",
    appVersion: "0.7.3",
    operatingSystem: "Debian",
    topology: {
      fr: "Instance standalone · 1 endpoint Windows",
      en: "Standalone instance · 1 Windows endpoint"
    },
    repository: "https://github.com/LordMonstey/splunk-detection-lab"
  },

  provenance: {
    snapshot: {
      id: "public-validation-snapshot-2026-08-06",
      capturedAt: "2026-08-06",
      totalEvents: 173,
      sysmonEvents: 148,
      windowsEvents: 4,
      source: {
        fr: "Export de recherche Splunk · snapshot public assaini",
        en: "Splunk search export · sanitized public snapshot"
      },
      scope: {
        fr: "Fenêtre publique figée ; aucune requête n’est envoyée à la VM.",
        en: "Frozen public window; no request is sent to the VM."
      }
    },
    lifetime: {
      capturedAt: "2026-08-06",
      totalEvents: 173,
      source: {
        fr: "Métadonnées des indexes Splunk · agrégat vérifié",
        en: "Splunk index metadata · verified aggregate"
      },
      scope: {
        fr: "Compteurs de la campagne contrôlée, y compris les sorties RBA versionnées.",
        en: "Controlled-campaign counters, including versioned RBA outputs."
      }
    },
    detections: {
      capturedAt: "2026-08-06",
      source: "savedsearches.conf + detection catalog + validation report",
      scope: {
        fr: "18 analytiques exécutées séquentiellement ; cinq scénarios positifs observés.",
        en: "18 analytics dispatched sequentially; five positive scenarios observed."
      }
    }
  },

  validation: {
    dispatched: 18,
    passed: 18,
    positive: 5,
    errors: 0,
    dashboardSearches: 49,
    dashboardErrors: 0,
    meanRuntimeMs: 317,
    cimProcessCompleteness: 100,
    appVersion: "0.6.4"
  },

  rba: {
    riskModifiers: 19,
    cumulativeRisk: 1185,
    techniques: 5,
    currentFindings: 1,
    findingVersions: 2,
    posture: "critical",
    mode: {
      fr: "RBA compatible Splunk ES · matérialisation contrôlée",
      en: "Splunk ES-compatible RBA · controlled materialization"
    }
  },

  sources: [
    {
      index: "sysmon",
      sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
      channel: "Sysmon Operational",
      count: 148
    },
    {
      index: "windows",
      sourcetype: "XmlWinEventLog:Security",
      channel: "Windows Security",
      count: 4
    },
    {
      index: "risk",
      sourcetype: "stash",
      channel: "RBA risk modifiers",
      count: 19
    },
    {
      index: "notable",
      sourcetype: "stash",
      channel: "Finding versions",
      count: 2
    }
  ],

  indexes: [
    {
      name: "sysmon",
      lifetime: 148,
      snapshot: 148,
      maxMb: 12000,
      retentionDays: 90,
      role: { fr: "Télémétrie Sysmon", en: "Sysmon telemetry" },
      state: "searchable"
    },
    {
      name: "windows",
      lifetime: 4,
      snapshot: 4,
      maxMb: 8000,
      retentionDays: 90,
      role: { fr: "Canaux Windows natifs", en: "Native Windows channels" },
      state: "searchable"
    },
    {
      name: "risk",
      lifetime: 19,
      snapshot: 19,
      maxMb: 1000,
      retentionDays: 365,
      role: { fr: "Modificateurs RBA ES-compatible", en: "ES-compatible RBA modifiers" },
      state: "searchable"
    },
    {
      name: "notable",
      lifetime: 2,
      snapshot: 2,
      maxMb: 1000,
      retentionDays: 365,
      role: { fr: "Versions du finding corrélé", en: "Correlated finding versions" },
      state: "searchable"
    }
  ],

  eventCodes: [
    { code: "1", fr: "Création de processus", en: "Process Creation", count: 134 },
    { code: "10", fr: "Accès processus", en: "Process Access", count: 12 },
    { code: "13", fr: "Valeur de registre", en: "Registry Value", count: 2 }
  ],

  tacticOrder: [
    { key: "execution", fr: "Exécution", en: "Execution" },
    { key: "persistence", fr: "Persistance", en: "Persistence" },
    { key: "defense-evasion", fr: "Évasion de défense", en: "Defense Evasion" },
    { key: "credential-access", fr: "Accès aux identifiants", en: "Credential Access" },
    { key: "command-control", fr: "Commande et contrôle", en: "Command and Control" }
  ],

  attackTactics: {
    "T1003.001": "credential-access",
    "T1027": "defense-evasion",
    "T1053.005": "persistence",
    "T1059.001": "execution",
    "T1059.003": "execution",
    "T1105": "command-control",
    "T1110.001": "credential-access",
    "T1110.003": "credential-access",
    "T1112": "defense-evasion",
    "T1136.001": "persistence",
    "T1140": "defense-evasion",
    "T1218.005": "defense-evasion",
    "T1218.010": "defense-evasion",
    "T1218.011": "defense-evasion",
    "T1222.001": "defense-evasion",
    "T1546.012": "persistence",
    "T1547.001": "persistence",
    "T1547.014": "persistence",
    "T1562.001": "defense-evasion"
  },

  detections: [
    {
      id: "win_sysmon_t1059.001_powershell_encoded",
      file: "win_sysmon_t1059.001_powershell_encoded.md",
      title: { fr: "Commande PowerShell encodée", en: "PowerShell Encoded Command" },
      status: "production",
      risk: 60,
      severity: "high",
      tactic: "execution",
      techniques: ["T1059.001"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "manual", evidence: null },
      spl: "`sysmon_process_creation` (Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\pwsh.exe\") | where match(CommandLine, \"(?i)\\\\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\\\\s\") | eval encoded_blob = mvindex(split(CommandLine, \" \"), -1) | eval blob_len = len(encoded_blob) | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents values(blob_len) as blob_lengths by dest user process_name process_guid"
    },
    {
      id: "win_sysmon_t1059.001_powershell_download_cradle",
      file: "win_sysmon_t1059.001_powershell_download_cradle.md",
      title: { fr: "PowerShell Download Cradle", en: "PowerShell Download Cradle" },
      status: "testing",
      risk: 70,
      severity: "high",
      tactic: "execution",
      techniques: ["T1059.001", "T1105"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`sysmon_process_creation` (Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\pwsh.exe\") | where match(CommandLine, \"(?i)(iex|invoke-expression)\") AND match(CommandLine, \"(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\\\\s|net\\\\.webclient|start-bitstransfer)\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid"
    },
    {
      id: "win_pwsh_t1059.001_amsi_bypass",
      file: "win_pwsh_t1059.001_amsi_bypass.md",
      title: { fr: "Contournement AMSI via PowerShell", en: "PowerShell AMSI Bypass" },
      status: "testing",
      risk: 75,
      severity: "high",
      tactic: "execution",
      techniques: ["T1059.001", "T1562.001"],
      dataSource: "PowerShell Operational · EventID 4104",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`wineventlog_powershell_operational` EventID=4104 | where match(Message, \"(?i)AmsiUtils|amsiInitFailed|amsi\\\\.dll|System\\\\.Management\\\\.Automation\\\\.AmsiUtils\") | stats count min(_time) as firstTime max(_time) as lastTime values(Message) as script_blocks by host"
    },
    {
      id: "win_sysmon_t1059.003_cmd_obfuscation",
      file: "win_sysmon_t1059.003_cmd_obfuscation.md",
      title: { fr: "Obfuscation de ligne de commande", en: "Command Shell Obfuscation" },
      status: "testing",
      risk: 50,
      severity: "medium",
      tactic: "execution",
      techniques: ["T1059.003", "T1027"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/10 * * * *", earliest: "-15m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`sysmon_process_creation` Image=\"*\\\\cmd.exe\" | eval caret_count = mvcount(split(CommandLine, \"^\")) - 1 | where caret_count >= 3 | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents max(caret_count) as max_carets by dest user process_name process_guid"
    },
    {
      id: "win_sysmon_t1547.001_run_key_modification",
      file: "win_sysmon_t1547.001_run_key_modification.md",
      title: { fr: "Modification d’une clé Run", en: "Run Key Modification" },
      status: "production",
      risk: 55,
      severity: "medium",
      tactic: "persistence",
      techniques: ["T1547.001"],
      dataSource: "Sysmon · EventID 13",
      schedule: { cron: "*/10 * * * *", earliest: "-15m@m", latest: "-1m@m" },
      validation: { type: "manual", evidence: null },
      spl: "`sysmon_registry_event` EventID=13 (TargetObject=\"*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*\" OR TargetObject=\"*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce*\") | eval writer = mvindex(split(Image,\"\\\\\"), -1) | where NOT match(writer, \"(?i)^(msiexec|setup|installer|trustedinstaller|wuauclt|svchost)\\\\.exe$\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(TargetObject) as run_keys values(Details) as run_values values(writer) as writers by dest user process_guid"
    },
    {
      id: "win_sysmon_t1053.005_scheduled_task_creation",
      file: "win_sysmon_t1053.005_scheduled_task_creation.md",
      title: { fr: "Création d’une tâche planifiée", en: "Scheduled Task Creation" },
      status: "testing",
      risk: 55,
      severity: "medium",
      tactic: "persistence",
      techniques: ["T1053.005"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/10 * * * *", earliest: "-15m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`sysmon_process_creation` Image=\"*\\\\schtasks.exe\" | where match(CommandLine, \"(?i)\\\\s/(create|change)\\\\b\") AND (match(CommandLine, \"(?i)/ru\\\\s+system\") OR match(CommandLine, \"(?i)/tr\\\\s+.+(powershell|cmd\\\\.exe|wscript|cscript|mshta|rundll32|regsvr32)\") OR match(CommandLine, \"(?i)/sc\\\\s+(onlogon|onstart|once|minute)\")) | eval parent_name = mvindex(split(ParentImage,\"\\\\\"), -1) | where NOT match(parent_name, \"(?i)^(mmc|taskschd|trustedinstaller|msiexec|setup)\\\\.exe$\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid"
    },
    {
      id: "win_secevt_t1136.001_local_account_creation",
      file: "win_secevt_t1136.001_local_account_creation.md",
      title: { fr: "Création d’un compte local", en: "Local Account Creation" },
      status: "production",
      risk: 55,
      severity: "medium",
      tactic: "persistence",
      techniques: ["T1136.001"],
      dataSource: "Windows Security · EventID 4720",
      schedule: { cron: "*/15 * * * *", earliest: "-20m@m", latest: "-1m@m" },
      validation: { type: "atomic", evidence: null },
      spl: "`wineventlog_security` EventID=4720 | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(TargetUserName) as new_account values(SubjectUserName) as creator by dest"
    },
    {
      id: "win_sysmon_t1112_registry_persistence_helper",
      file: "win_sysmon_t1112_registry_persistence_helper.md",
      title: { fr: "Persistance via helper de registre", en: "Registry Persistence Helper" },
      status: "testing",
      risk: 70,
      severity: "high",
      tactic: "persistence",
      techniques: ["T1112", "T1546.012", "T1547.014"],
      dataSource: "Sysmon · EventID 13",
      schedule: { cron: "*/10 * * * *", earliest: "-15m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`sysmon_registry_event` EventID=13 (TargetObject=\"*\\\\Image File Execution Options\\\\*\\\\Debugger*\" OR TargetObject=\"*\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit*\" OR TargetObject=\"*\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Shell*\" OR TargetObject=\"*\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_DLLs*\" OR TargetObject=\"*\\\\Active Setup\\\\Installed Components\\\\*\\\\StubPath*\") | eval writer = mvindex(split(Image,\"\\\\\"), -1) | where NOT match(writer, \"(?i)^(TrustedInstaller|msiexec|setup|wuauclt|svchost)\\\\.exe$\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(TargetObject) as registry_keys values(Details) as registry_values values(writer) as writers by dest user process_guid"
    },
    {
      id: "win_sysmon_t1218.011_rundll32_unusual_parent",
      file: "win_sysmon_t1218.011_rundll32_unusual_parent.md",
      title: { fr: "Rundll32 avec parent inhabituel", en: "Rundll32 with Unusual Parent" },
      status: "production",
      risk: 65,
      severity: "high",
      tactic: "defense-evasion",
      techniques: ["T1218.011"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "manual", evidence: null },
      spl: "`sysmon_process_creation` Image=\"*\\\\rundll32.exe\" | eval parent_name = mvindex(split(ParentImage,\"\\\\\"), -1) | where NOT match(parent_name, \"(?i)^(explorer|services|svchost|taskhost|wininit|userinit|sihost|searchindexer)\\\\.exe$\") OR NOT match(CommandLine, \"(?i)\\\\.dll\") OR match(CommandLine, \"(?i)javascript:|mshtml.*RunHTMLApplication\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid"
    },
    {
      id: "win_sysmon_t1218.005_mshta_execution",
      file: "win_sysmon_t1218.005_mshta_execution.md",
      title: { fr: "Exécution de contenu distant via Mshta", en: "Mshta Remote Content Execution" },
      status: "production",
      risk: 65,
      severity: "high",
      tactic: "defense-evasion",
      techniques: ["T1218.005"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "atomic", evidence: null },
      spl: "`sysmon_process_creation` Image=\"*\\\\mshta.exe\" | where match(CommandLine, \"(?i)https?://|javascript:|vbscript:|about:|\\\\.hta\\\\b\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid"
    },
    {
      id: "win_sysmon_t1218.010_regsvr32_remote",
      file: "win_sysmon_t1218.010_regsvr32_remote.md",
      title: { fr: "Exécution de scriptlet via Regsvr32", en: "Regsvr32 Scriptlet Execution" },
      status: "production",
      risk: 70,
      severity: "high",
      tactic: "defense-evasion",
      techniques: ["T1218.010"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "atomic", evidence: null },
      spl: "`sysmon_process_creation` Image=\"*\\\\regsvr32.exe\" | where match(CommandLine, \"(?i)https?://|/i:.+\\\\\\\\.+|scrobj\\\\.dll\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid"
    },
    {
      id: "win_sysmon_t1027_obfuscated_powershell_entropy",
      file: "win_sysmon_t1027_obfuscated_powershell_entropy.md",
      title: { fr: "PowerShell obfusqué par entropie", en: "Obfuscated PowerShell Entropy" },
      status: "testing",
      risk: 50,
      severity: "medium",
      tactic: "defense-evasion",
      techniques: ["T1027"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/15 * * * *", earliest: "-20m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`sysmon_process_creation` (Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\pwsh.exe\") | eval cmd_len = len(CommandLine) | eval weird_chars = mvcount(split(CommandLine, \"`\"))-1 + mvcount(split(CommandLine, \"+\"))-1 + mvcount(split(CommandLine, \"$\"))-1 + mvcount(split(CommandLine, \"{\"))-1 + mvcount(split(CommandLine, \"}\"))-1 | eval weird_ratio = round((weird_chars / cmd_len) * 100, 2) | where cmd_len > 200 AND weird_ratio > 8 | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines max(cmd_len) as cmd_length max(weird_ratio) as weirdness_pct by dest user process_name process_guid"
    },
    {
      id: "win_sysmon_t1140_certutil_decode",
      file: "win_sysmon_t1140_certutil_decode.md",
      title: { fr: "Téléchargement ou décodage via Certutil", en: "Certutil Download or Decode" },
      status: "testing",
      risk: 60,
      severity: "medium",
      tactic: "defense-evasion",
      techniques: ["T1140", "T1105"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/10 * * * *", earliest: "-15m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`sysmon_process_creation` (Image=\"*\\\\certutil.exe\" OR OriginalFileName=\"CertUtil.exe\") | where match(CommandLine, \"(?i)\\\\s-(decode|decodehex|encode|encodehex|urlcache)\\\\b\") OR match(CommandLine, \"(?i)\\\\s-split\\\\s+-f\\\\s+https?://\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid"
    },
    {
      id: "win_sysmon_t1562.001_defender_tamper",
      file: "win_sysmon_t1562.001_defender_tamper.md",
      title: { fr: "Altération de Windows Defender", en: "Windows Defender Tampering" },
      status: "testing",
      risk: 75,
      severity: "high",
      tactic: "defense-evasion",
      techniques: ["T1562.001"],
      dataSource: "Sysmon · EventID 1 / 13",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "((`sysmon_process_creation` (Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\pwsh.exe\") CommandLine=\"*MpPreference*\" (CommandLine=\"*-DisableRealtimeMonitoring*\" OR CommandLine=\"*-ExclusionPath*\" OR CommandLine=\"*-ExclusionProcess*\" OR CommandLine=\"*-ExclusionExtension*\")) OR (`sysmon_registry_event` EventID=13 (TargetObject=\"*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\*\" OR TargetObject=\"*\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\*\"))) | eval action_type = if(EventID==1, \"powershell_cmd\", \"registry_write\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(TargetObject) as registry_keys values(action_type) as actions by dest user process_guid"
    },
    {
      id: "win_sysmon_t1222.001_icacls_permissive",
      file: "win_sysmon_t1222.001_icacls_permissive.md",
      title: { fr: "Modification permissive d’ACL via Icacls", en: "Icacls Permissive ACL Change" },
      status: "testing",
      risk: 45,
      severity: "medium",
      tactic: "defense-evasion",
      techniques: ["T1222.001"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/15 * * * *", earliest: "-20m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`sysmon_process_creation` Image=\"*\\\\icacls.exe\" | where match(CommandLine, \"(?i)/grant.*\\\\b(everyone|users|authenticated\\\\s*users|domain\\\\s*users):\\\\s*\\\\(?[FM]\\\\)?\") OR match(CommandLine, \"(?i)/grant.*\\\\bs-1-1-0:\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid"
    },
    {
      id: "win_sysmon_t1003.001_lsass_access_suspicious",
      file: "win_sysmon_t1003.001_lsass_access_suspicious.md",
      title: { fr: "Accès suspect à la mémoire de LSASS", en: "Suspicious LSASS Process Access" },
      status: "production",
      risk: 90,
      severity: "critical",
      tactic: "credential-access",
      techniques: ["T1003.001"],
      dataSource: "Sysmon · EventID 10",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "atomic", evidence: null },
      spl: "`sysmon_process_access` TargetImage=\"*\\\\lsass.exe\" | eval source_name = mvindex(split(SourceImage,\"\\\\\"), -1) | where NOT match(source_name, \"(?i)^(wininit|svchost|lsass|services|TaskMgr|SgrmBroker)\\\\.exe$\") AND (GrantedAccess=\"0x1010\" OR GrantedAccess=\"0x1410\" OR GrantedAccess=\"0x1438\" OR GrantedAccess=\"0x143a\" OR GrantedAccess=\"0x1fffff\") | lookup allowlist_lsass_access source_process_name AS source_name OUTPUTNEW signer AS allowlisted_signer reason AS allowlist_reason | where isnull(allowlisted_signer) | `cim_endpoint_processes_rename` | eval user=coalesce(user, SourceUser, \"unknown\") | stats count min(_time) as firstTime max(_time) as lastTime values(SourceImage) as source_images values(SourceCommandLine) as source_cmds values(GrantedAccess) as access_masks values(CallTrace) as call_traces by dest user SourceProcessGUID | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`"
    },
    {
      id: "win_secevt_t1110.001_failed_logon_burst",
      file: "win_secevt_t1110.001_failed_logon_burst.md",
      title: { fr: "Rafale d’échecs d’authentification", en: "Failed Logon Burst" },
      status: "testing",
      risk: 50,
      severity: "medium",
      tactic: "credential-access",
      techniques: ["T1110.001", "T1110.003"],
      dataSource: "Windows Security · EventID 4625",
      schedule: { cron: "*/5 * * * *", earliest: "-15m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`wineventlog_security` EventID=4625 | bucket _time span=15m | stats count dc(TargetUserName) as users_targeted values(TargetUserName) as users values(IpAddress) as src_ips values(LogonType) as logon_types by _time host | where (count >= 10 AND users_targeted == 1) OR (users_targeted >= 5) | eval pattern = case(users_targeted == 1, \"brute_force_single_user\", users_targeted >= 5, \"password_spray\", 1==1, \"other\")"
    },
    {
      id: "win_sysmon_t1105_curl_wget_download",
      file: "win_sysmon_t1105_curl_wget_download.md",
      title: { fr: "Transfert via Curl ou Bitsadmin", en: "Curl or Bitsadmin Transfer" },
      status: "testing",
      risk: 50,
      severity: "medium",
      tactic: "command-control",
      techniques: ["T1105"],
      dataSource: "Sysmon · EventID 1",
      schedule: { cron: "*/5 * * * *", earliest: "-10m@m", latest: "-1m@m" },
      validation: { type: "implemented", evidence: null },
      spl: "`sysmon_process_creation` (Image=\"*\\\\curl.exe\" OR Image=\"*\\\\bitsadmin.exe\") | where match(CommandLine, \"(?i)https?://\") AND NOT match(CommandLine, \"(?i)https?://(127\\\\.|localhost|10\\\\.|172\\\\.(1[6-9]|2[0-9]|3[01])\\\\.|192\\\\.168\\\\.)\") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid"
    }
  ],

  cases: [
    {
      key: "lsass",
      detectionId: "win_sysmon_t1003.001_lsass_access_suspicious",
      hypothesis: {
        fr: "Un processus non standard demandant des droits à fort impact sur lsass.exe peut signaler une lecture mémoire ou une tentative de credential dumping.",
        en: "A non-standard process requesting high-impact access rights on lsass.exe can indicate credential dumping or an attempted memory read."
      },
      tuning: {
        fr: "Noms de processus Microsoft connus exclus, puis contrôle explicite des masques 0x1010, 0x1410, 0x1438, 0x143a et 0x1fffff.",
        en: "Known Microsoft process names are excluded, followed by explicit checks for masks 0x1010, 0x1410, 0x1438, 0x143a, and 0x1fffff."
      },
      evidence: "assets/evidence/risk-correlation-assurance.png",
      evidenceAlt: {
        fr: "Surface agrégée RBA et entité utilisée pour illustrer le workflow LSASS ; aucun événement brut du cas n’est publié.",
        en: "Aggregate RBA and entity surface used to illustrate the LSASS workflow; no raw case event is published."
      },
      fields: [
        ["SourceImage", "[processus hors allowlist]"],
        ["TargetImage", "*\\lsass.exe"],
        ["GrantedAccess", "0x1010 | 0x1410 | 0x1438 | 0x143a | 0x1fffff"],
        ["RuleName", "technique_id=T1003.001"]
      ],
      response: {
        fr: "Vérifier le signataire et l’ascendance, corréler les accès compte, puis décider de l’isolation de l’hôte.",
        en: "Verify signer and ancestry, correlate account activity, then decide whether the host requires isolation."
      }
    },
    {
      key: "regsvr32",
      detectionId: "win_sysmon_t1218.010_regsvr32_remote",
      hypothesis: {
        fr: "Regsvr32 chargeant un scriptlet distant peut détourner un binaire Windows signé pour contourner des contrôles applicatifs simples.",
        en: "Regsvr32 loading a remote scriptlet can proxy execution through a signed Windows binary and evade basic application controls."
      },
      tuning: {
        fr: "Présence d’une URI, d’un argument /i ou de scrobj.dll ; contexte parent et ligne de commande conservés.",
        en: "URI, /i argument, or scrobj.dll indicator required; parent context and command line are preserved."
      },
      evidence: "assets/evidence/detection-factory-control-plane.png",
      evidenceAlt: {
        fr: "Surface agrégée Detection Factory utilisée pour illustrer le workflow Regsvr32 ; aucun événement brut du cas n’est publié.",
        en: "Aggregate Detection Factory surface used to illustrate the Regsvr32 workflow; no raw case event is published."
      },
      fields: [
        ["Image", "*\\regsvr32.exe"],
        ["CommandLine", "[URI ou /i:... associé à scrobj.dll]"],
        ["ParentImage", "[processus parent à qualifier]"],
        ["Technique", "T1218.010"]
      ],
      response: {
        fr: "Examiner la ressource distante, l’arbre de processus, le DNS et les téléchargements adjacents.",
        en: "Review the remote resource, process tree, DNS, and adjacent downloads."
      }
    },
    {
      key: "powershell",
      detectionId: "win_sysmon_t1059.001_powershell_encoded",
      hypothesis: {
        fr: "Les paramètres PowerShell encodés masquent l’intention de la commande et deviennent un signal fort lorsqu’ils sont associés au contexte processus.",
        en: "Encoded PowerShell flags hide command intent and become a strong signal when paired with process context."
      },
      tuning: {
        fr: "Variantes complètes du paramètre, extraction de la longueur du blob et conservation de l’ascendance.",
        en: "Full flag variants, encoded blob length extraction, and preserved ancestry."
      },
      evidence: "assets/evidence/engineering-command-center.png",
      evidenceAlt: {
        fr: "Surface agrégée Command Center utilisée pour illustrer le workflow PowerShell ; aucun événement brut du cas n’est publié.",
        en: "Aggregate Command Center surface used to illustrate the PowerShell workflow; no raw case event is published."
      },
      fields: [
        ["Image", "*\\powershell.exe | *\\pwsh.exe"],
        ["CommandLine", "-[e|enc|encodedcommand] [blob]"],
        ["ParentImage", "[processus parent à qualifier]"],
        ["Technique", "T1059.001"]
      ],
      response: {
        fr: "Décoder le payload dans un environnement contrôlé, inspecter l’ascendance et corréler l’activité réseau.",
        en: "Decode the payload in a controlled environment, inspect ancestry, and correlate network activity."
      }
    }
  ],

  evidence: [
    {
      id: "command-center",
      image: "assets/evidence/engineering-command-center.png",
      title: { fr: "Command Center Splunk", en: "Splunk Command Center" },
      caption: {
        fr: "Capture agrégée revue : contrôle de plateforme, télémétrie, indexes, scheduler et inventaire des 18 détections.",
        en: "Reviewed aggregate capture: platform control, telemetry, indexes, scheduler, and 18-detection inventory."
      },
      claim: "conf/splunk/local/data/ui/views/splunk_engineering_command_center.xml"
    },
    {
      id: "detection-factory",
      image: "assets/evidence/detection-factory-control-plane.png",
      title: { fr: "Detection Factory", en: "Detection Factory" },
      caption: {
        fr: "Capture agrégée revue : 18/18 dispatchs, cinq scénarios positifs, runtime mesuré et catalogue déployable.",
        en: "Reviewed aggregate capture: 18/18 dispatches, five positive scenarios, measured runtime, and deployable catalog."
      },
      claim: "49/49 dashboard searches · 18/18 detection dispatches"
    },
    {
      id: "risk-investigation",
      image: "assets/evidence/risk-correlation-assurance.png",
      title: { fr: "Investigation RBA & entité", en: "RBA & Entity Investigation" },
      caption: {
        fr: "Capture agrégée revue : 19 modificateurs, cinq techniques, finding corrélé versionné et contexte d’entité.",
        en: "Reviewed aggregate capture: 19 modifiers, five techniques, versioned correlated finding, and entity context."
      },
      claim: "risk=19 · cumulative_risk=1185 · current_finding=1"
    }
  ],

  adminEvidence: [
    {
      id: "custom-datamodel",
      category: { fr: "MODÈLE DE DONNÉES", en: "DATA MODEL" },
      title: {
        fr: "Data model custom accéléré et qualifié",
        en: "Qualified accelerated custom data model"
      },
      metric: "13/13",
      metricLabel: { fr: "contrôles d’acceptation", en: "acceptance checks" },
      reference: {
        fr: "parité 100 % · 4 buckets · fraîcheur < 900 s",
        en: "100% parity · 4 buckets · freshness < 900 s"
      },
      detail: {
        fr: "Security Telemetry Qualification est un modèle custom, explicitement distinct d’un data model CIM natif. Définition, ACL, accélération, tstats summariesonly=t, parité et fraîcheur ont été contrôlés sur le runtime 0.7.3.",
        en: "Security Telemetry Qualification is a custom model, explicitly distinct from a native CIM data model. Definition, ACLs, acceleration, tstats summariesonly=t, parity, and freshness were checked on runtime 0.7.3."
      },
      artifact: "artifacts/public/custom-datamodel-live-evidence-10.2.1-20260807.json"
    },
    {
      id: "upgrade-rollback",
      category: { fr: "GESTION DU CHANGEMENT", en: "CHANGE MANAGEMENT" },
      title: {
        fr: "Upgrade avec retour arrière qualifié",
        en: "Qualified upgrade and rollback"
      },
      metric: "32/32",
      metricLabel: { fr: "smoke tests", en: "smoke tests" },
      reference: "9.4.13 → 10.2.1 → 9.4.13 → 10.2.1",
      detail: {
        fr: "Montée en version directe, retour au snapshot, contrôle d’intégrité des inventaires puis seconde montée en version. Décision finale CLOSE.",
        en: "Direct upgrade, snapshot rollback, inventory integrity checks, then a second upgrade. Final decision: CLOSE."
      },
      artifact: "artifacts/public/upgrade-evidence-9-4-13-to-10-2-1-live.json"
    },
    {
      id: "tls-lifecycle",
      category: { fr: "SÉCURITÉ DU TRANSPORT", en: "TRANSPORT SECURITY" },
      title: {
        fr: "Rotation TLS et reprise du KV Store",
        en: "TLS rotation and KV Store recovery"
      },
      metric: "12/12",
      metricLabel: { fr: "contrôles actifs", en: "live controls" },
      reference: "TLS 1.2 · rotation C · KV ready",
      detail: {
        fr: "Le profil serverAuth-only a révélé une dépendance KV Store. Le certificat à double usage serverAuth/clientAuth a rétabli le service et validé les tests négatifs.",
        en: "A serverAuth-only profile exposed a KV Store dependency. A dual-purpose serverAuth/clientAuth certificate restored service and passed the negative tests."
      },
      artifact: "artifacts/public/tls-rotation-evidence-20260807.json"
    },
    {
      id: "rbac-governance",
      category: { fr: "GOUVERNANCE DES ACCÈS", en: "ACCESS GOVERNANCE" },
      title: {
        fr: "Contrat RBAC testé en conditions réelles",
        en: "Live-tested RBAC contract"
      },
      metric: "38/38",
      metricLabel: { fr: "tests d’autorisation", en: "authorization tests" },
      reference: {
        fr: "6 rôles · 14 positifs · 24 négatifs",
        en: "6 roles · 14 positive · 24 negative"
      },
      detail: {
        fr: "Six rôles, 67 capabilities déclarées et une matrice d’accès vérifiée. Les six comptes éphémères du test ont été supprimés après qualification.",
        en: "Six roles, 67 declared capabilities, and a verified access matrix. All six ephemeral test accounts were removed after qualification."
      },
      artifact: "artifacts/public/rbac-live-evidence-9.4.13-20260807.json"
    },
    {
      id: "mco-readonly",
      category: { fr: "MCO ET OBSERVABILITÉ", en: "OPERATIONS & OBSERVABILITY" },
      title: {
        fr: "Qualification MCO en lecture seule",
        en: "Read-only operations qualification"
      },
      metric: "5/5",
      metricLabel: { fr: "domaines qualifiés", en: "qualified domains" },
      reference: {
        fr: "santé · KV · licence · scheduler · capacité",
        en: "health · KV · license · scheduler · capacity"
      },
      detail: {
        fr: "Santé, KV Store, licence, scheduler et fraîcheur/capacité vérifiés sans publier les noms d’index, les recherches ni les événements bruts.",
        en: "Health, KV Store, license, scheduler, and freshness/capacity verified without publishing index names, searches, or raw events."
      },
      artifact: "artifacts/public/mco-live-read-only-qualification-20260807.json"
    },
    {
      id: "periodic-reporting",
      category: { fr: "REPORTING PÉRIODIQUE", en: "PERIODIC REPORTING" },
      title: {
        fr: "Collecte quotidienne et hebdomadaire idempotente",
        en: "Idempotent daily and weekly collection"
      },
      metric: "16/16",
      metricLabel: { fr: "contrôles live", en: "live checks" },
      reference: {
        fr: "2 schedules · 16 lignes · 0 doublon · 10 requêtes agrégées",
        en: "2 schedules · 16 rows · 0 duplicates · 10 aggregate queries"
      },
      detail: {
        fr: "Les collecteurs quotidien MCO et hebdomadaire CIM ont été dispatchés puis rejoués sans créer de doublon. Le dashboard utilise dix requêtes aggregate-only. Une seule période existe par famille : aucune tendance n’est revendiquée.",
        en: "The daily operations and weekly CIM collectors were dispatched and replayed without creating duplicates. The dashboard uses ten aggregate-only queries. Only one period exists per family, so no trend is claimed."
      },
      artifact: "artifacts/public/periodic-reporting-live-evidence-10.2.1-20260807.json"
    },
    {
      id: "parsing-rollback",
      category: { fr: "QUALITÉ & ROLLBACK", en: "QUALITY & ROLLBACK" },
      title: {
        fr: "Régression de parsing interceptée avant promotion",
        en: "Parsing regression intercepted before promotion"
      },
      metric: "100 → 0 → 100",
      metricLabel: { fr: "complétude (%)", en: "completeness (%)" },
      reference: {
        fr: "baseline PASS · candidat NO-GO · rollback PASS",
        en: "baseline PASS · candidate NO-GO · rollback PASS"
      },
      detail: {
        fr: "Le candidat a conservé 5/5 événements mais cassé les champs obligatoires et l’horodatage. Le gate a bloqué sa promotion, puis le même package baseline et la même configuration effective ont restauré 100 % de conformité.",
        en: "The candidate retained 5/5 events but broke required fields and timestamp conformance. The gate blocked promotion, then the same baseline package and effective configuration restored 100% compliance."
      },
      artifact: "artifacts/public/parsing-canary-rollback-evidence-20260807.json"
    },
    {
      id: "cluster-resilience",
      category: { fr: "RÉSILIENCE", en: "RESILIENCE" },
      title: {
        fr: "Continuité de recherche sur cluster dédié",
        en: "Search continuity on a dedicated cluster"
      },
      metric: "RF2 / SF2",
      metricLabel: { fr: "facteurs rétablis", en: "factors restored" },
      reference: {
        fr: "1 CM · 2 peers · 1 SH · reprise 222 s",
        en: "1 CM · 2 peers · 1 SH · recovery 222 s"
      },
      detail: {
        fr: "Perte contrôlée d’un pair : recherche maintenue pendant l’incident, facteurs de réplication et de recherche rétablis, puis retour complet au vert.",
        en: "Controlled peer loss: search remained available, replication and search factors recovered, then the topology returned fully green."
      },
      artifact: "artifacts/public/cluster-resilience-evidence-20260806.json"
    },
    {
      id: "linux-onboarding",
      category: { fr: "ONBOARDING ET CIM", en: "ONBOARDING & CIM" },
      title: {
        fr: "Sources Linux normalisées et contrôlées",
        en: "Normalized and controlled Linux sources"
      },
      metric: "13/13",
      metricLabel: { fr: "événements attendus", en: "expected events" },
      reference: {
        fr: "3 sourcetypes · 4 périmètres CIM · app 0.7.2",
        en: "3 sourcetypes · 4 CIM scopes · app 0.7.2"
      },
      detail: {
        fr: "Rsyslog, journald et auditd intégrés avec quatre contrats CIM à 100 %, zéro doublon, aucun risque de troncature et un p95 d’indexation de 3 s.",
        en: "Rsyslog, journald, and auditd onboarded with four 100% CIM contracts, zero duplicates, no truncation risk, and 3-second p95 indexing latency."
      },
      artifact: "artifacts/public/linux-onboarding-evidence-20260807.json"
    }
  ],

  gaps: [
    {
      technique: "T1021.001 / T1021.002",
      fr: "RDP et partages administratifs nécessitent un second endpoint.",
      en: "RDP and administrative shares require a second endpoint.",
      dependency: { fr: "Télémétrie latérale", en: "Lateral telemetry" }
    },
    {
      technique: "T1071.001 / T1090",
      fr: "Le C2 HTTP et les proxys nécessitent une source proxy ou NDR.",
      en: "HTTP C2 and proxy techniques require proxy or NDR telemetry.",
      dependency: { fr: "Réseau", en: "Network" }
    },
    {
      technique: "T1078",
      fr: "Les comptes valides nécessitent davantage de contexte identité et une baseline.",
      en: "Valid Accounts requires broader identity context and baselining.",
      dependency: { fr: "Identité", en: "Identity" }
    },
    {
      technique: "T1486",
      fr: "Le chiffrement pour impact nécessite un jeu de données ransomware contrôlé.",
      en: "Data Encrypted for Impact requires a controlled ransomware-pattern dataset.",
      dependency: { fr: "Dataset", en: "Dataset" }
    },
    {
      technique: "Active Directory",
      fr: "Aucun contrôleur de domaine n’est présent dans le périmètre.",
      en: "No domain controller is present in scope.",
      dependency: { fr: "Infrastructure", en: "Infrastructure" }
    }
  ]
};
