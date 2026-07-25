window.LAB_DATA = {
  meta: {
    project: "Splunk Platform & Detection Engineering Lab",
    author: "A.S",
    splunkVersion: "10.2.1",
    operatingSystem: "Debian",
    topology: {
      fr: "Instance standalone · 1 endpoint Windows",
      en: "Standalone instance · 1 Windows endpoint"
    },
    repository: "https://github.com/LordMonstey/splunk-detection-lab"
  },

  provenance: {
    snapshot: {
      id: "public-search-snapshot-2026-07-25",
      capturedAt: "2026-07-25",
      totalEvents: 473,
      sysmonEvents: 390,
      windowsEvents: 83,
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
      capturedAt: "2026-07-25",
      totalEvents: 19946,
      source: {
        fr: "Métadonnées des indexes Splunk · agrégat vérifié",
        en: "Splunk index metadata · verified aggregate"
      },
      scope: {
        fr: "Compteurs cumulés des indexes sysmon et windows.",
        en: "Cumulative counters for the sysmon and windows indexes."
      }
    },
    detections: {
      capturedAt: "2026-07-25",
      source: "conf/splunk/local/savedsearches.conf + detections/*.md",
      scope: {
        fr: "Inventaire versionné de recherches planifiées, pas un flux ES actif.",
        en: "Versioned scheduled-search inventory, not an active ES feed."
      }
    }
  },

  sources: [
    {
      index: "sysmon",
      sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
      channel: "Sysmon Operational",
      count: 390
    },
    {
      index: "windows",
      sourcetype: "XmlWinEventLog:Security",
      channel: "Windows Security",
      count: 76
    },
    {
      index: "windows",
      sourcetype: "XmlWinEventLog:Application",
      channel: "Windows Application",
      count: 6
    },
    {
      index: "windows",
      sourcetype: "XmlWinEventLog:System",
      channel: "Windows System",
      count: 1
    }
  ],

  indexes: [
    {
      name: "sysmon",
      lifetime: 15227,
      snapshot: 390,
      maxMb: 12000,
      retentionDays: 90,
      role: { fr: "Télémétrie Sysmon", en: "Sysmon telemetry" },
      state: "searchable"
    },
    {
      name: "windows",
      lifetime: 4719,
      snapshot: 83,
      maxMb: 8000,
      retentionDays: 90,
      role: { fr: "Canaux Windows natifs", en: "Native Windows channels" },
      state: "searchable"
    },
    {
      name: "risk",
      lifetime: 0,
      snapshot: 0,
      maxMb: 1000,
      retentionDays: 365,
      role: { fr: "Destination RBA préparée", en: "Prepared RBA destination" },
      state: "configured-inactive"
    },
    {
      name: "notable",
      lifetime: 0,
      snapshot: 0,
      maxMb: 1000,
      retentionDays: 365,
      role: { fr: "Destination de synthèse préparée", en: "Prepared summary destination" },
      state: "configured-inactive"
    }
  ],

  eventCodes: [
    { code: "23", fr: "Suppression de fichier", en: "File Delete", count: 171 },
    { code: "11", fr: "Création de fichier", en: "File Create", count: 131 },
    { code: "13", fr: "Valeur de registre", en: "Registry Value", count: 68 },
    { code: "10", fr: "Accès processus", en: "Process Access", count: 13 },
    { code: "7", fr: "Chargement d’image", en: "Image Load", count: 5 },
    { code: "17", fr: "Named Pipe", en: "Named Pipe", count: 2 }
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
      validation: { type: "manual", evidence: "assets/evidence/t1059-powershell.png" },
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
      validation: { type: "atomic", evidence: "assets/evidence/t1218-regsvr32.png" },
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
      validation: { type: "atomic", evidence: "assets/evidence/t1003-lsass.png" },
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
      evidence: "assets/evidence/t1003-lsass.png",
      evidenceAlt: {
        fr: "Résultat Splunk validant l’accès suspect à LSASS",
        en: "Splunk result validating suspicious LSASS access"
      },
      fields: [
        ["SourceImage", "C:\\Tools\\procdump64.exe"],
        ["TargetImage", "C:\\Windows\\System32\\lsass.exe"],
        ["GrantedAccess", "0x1fffff"],
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
      evidence: "assets/evidence/t1218-regsvr32.png",
      evidenceAlt: {
        fr: "Résultat Splunk validant Regsvr32 Squiblydoo",
        en: "Splunk result validating Regsvr32 Squiblydoo"
      },
      fields: [
        ["Image", "C:\\Windows\\System32\\regsvr32.exe"],
        ["CommandLine", "regsvr32.exe /s /n /u /i:[remote] scrobj.dll"],
        ["ParentImage", "C:\\Windows\\System32\\cmd.exe"],
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
      evidence: "assets/evidence/t1059-powershell.png",
      evidenceAlt: {
        fr: "Résultat Splunk validant PowerShell EncodedCommand",
        en: "Splunk result validating PowerShell EncodedCommand"
      },
      fields: [
        ["Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"],
        ["CommandLine", "powershell.exe -EncodedCommand [truncated]"],
        ["ParentImage", "C:\\Windows\\System32\\cmd.exe"],
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
      title: { fr: "Dashboard natif Splunk", en: "Native Splunk dashboard" },
      caption: {
        fr: "Simple XML déployé sur Splunk 10.2.1.",
        en: "Simple XML deployed on Splunk 10.2.1."
      },
      claim: "conf/splunk/local/data/ui/views/splunk_engineering_command_center.xml"
    },
    {
      id: "lsass-proof",
      image: "assets/evidence/t1003-lsass.png",
      title: { fr: "LSASS · T1003.001", en: "LSASS · T1003.001" },
      caption: {
        fr: "Atomic Red Team + Sysmon EventID 10.",
        en: "Atomic Red Team + Sysmon EventID 10."
      },
      claim: "tests/atomic/evidence/T1003.001-detection-fired.png"
    },
    {
      id: "regsvr32-proof",
      image: "assets/evidence/t1218-regsvr32.png",
      title: { fr: "Regsvr32 · T1218.010", en: "Regsvr32 · T1218.010" },
      caption: {
        fr: "Chemin Squiblydoo observé et retrouvé.",
        en: "Squiblydoo path observed and retrieved."
      },
      claim: "tests/atomic/evidence/T1218.010-regsvr32-squiblydoo.png"
    },
    {
      id: "powershell-proof",
      image: "assets/evidence/t1059-powershell.png",
      title: { fr: "PowerShell · T1059.001", en: "PowerShell · T1059.001" },
      caption: {
        fr: "EncodedCommand capturé avec le contexte processus.",
        en: "EncodedCommand captured with process context."
      },
      claim: "tests/atomic/evidence/T1059.001-encoded-powershell.png"
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
