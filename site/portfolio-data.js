window.LAB_DATA = {
  sources: [
    { index: "sysmon", sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", count: 390 },
    { index: "windows", sourcetype: "XmlWinEventLog:Security", count: 76 },
    { index: "windows", sourcetype: "XmlWinEventLog:Application", count: 6 },
    { index: "windows", sourcetype: "XmlWinEventLog:System", count: 1 }
  ],

  indexes: [
    { name: "sysmon", lifetime: 15227, searchable: 390, diskMb: 8, maxMb: 12000, retentionDays: 90 },
    { name: "windows", lifetime: 4719, searchable: 83, diskMb: 2, maxMb: 8000, retentionDays: 90 },
    { name: "risk", lifetime: 0, searchable: 0, diskMb: 1, maxMb: 1000, retentionDays: 365 },
    { name: "notable", lifetime: 0, searchable: 0, diskMb: 1, maxMb: 1000, retentionDays: 365 }
  ],

  eventCodes: [
    { code: "23", fr: "Suppression de fichier", en: "File Delete", count: 171 },
    { code: "11", fr: "Création de fichier", en: "File Create", count: 131 },
    { code: "13", fr: "Valeur de registre", en: "Registry Value", count: 68 },
    { code: "10", fr: "Accès processus", en: "Process Access", count: 13 },
    { code: "7", fr: "Chargement d’image", en: "Image Load", count: 5 },
    { code: "17", fr: "Named Pipe", en: "Named Pipe", count: 2 }
  ],

  detections: [
    {
      id: "ps-encoded",
      fr: "Commande PowerShell encodée",
      en: "PowerShell Encoded Command",
      techniques: ["T1059.001"],
      tactic: { fr: "Exécution", en: "Execution" },
      status: "production",
      risk: 60,
      severity: "high",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1059.001_powershell_encoded.md",
      case: "powershell"
    },
    {
      id: "local-account",
      fr: "Création d’un compte local",
      en: "Local Account Creation",
      techniques: ["T1136.001"],
      tactic: { fr: "Persistance", en: "Persistence" },
      status: "production",
      risk: 55,
      severity: "medium",
      schedule: "*/15 * * * *",
      file: "win_secevt_t1136.001_local_account_creation.md"
    },
    {
      id: "run-key",
      fr: "Modification d’une clé Run",
      en: "Run Key Modification",
      techniques: ["T1547.001"],
      tactic: { fr: "Persistance", en: "Persistence" },
      status: "production",
      risk: 55,
      severity: "medium",
      schedule: "*/10 * * * *",
      file: "win_sysmon_t1547.001_run_key_modification.md"
    },
    {
      id: "rundll32",
      fr: "Rundll32 avec parent inhabituel",
      en: "Rundll32 with Unusual Parent",
      techniques: ["T1218.011"],
      tactic: { fr: "Évasion de défense", en: "Defense Evasion" },
      status: "production",
      risk: 65,
      severity: "high",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1218.011_rundll32_unusual_parent.md"
    },
    {
      id: "mshta",
      fr: "Exécution de contenu distant via Mshta",
      en: "Mshta Remote Content Execution",
      techniques: ["T1218.005"],
      tactic: { fr: "Évasion de défense", en: "Defense Evasion" },
      status: "production",
      risk: 65,
      severity: "high",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1218.005_mshta_execution.md"
    },
    {
      id: "regsvr32",
      fr: "Exécution de scriptlet via Regsvr32",
      en: "Regsvr32 Scriptlet Execution",
      techniques: ["T1218.010"],
      tactic: { fr: "Évasion de défense", en: "Defense Evasion" },
      status: "production",
      risk: 70,
      severity: "high",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1218.010_regsvr32_remote.md",
      case: "regsvr32"
    },
    {
      id: "certutil",
      fr: "Téléchargement ou décodage via Certutil",
      en: "Certutil Download or Decode",
      techniques: ["T1140", "T1105"],
      tactic: { fr: "Évasion de défense", en: "Defense Evasion" },
      status: "production",
      risk: 60,
      severity: "medium",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1140_certutil_decode.md"
    },
    {
      id: "lsass",
      fr: "Accès suspect à la mémoire de LSASS",
      en: "Suspicious LSASS Process Access",
      techniques: ["T1003.001"],
      tactic: { fr: "Accès aux identifiants", en: "Credential Access" },
      status: "production",
      risk: 90,
      severity: "critical",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1003.001_lsass_access_suspicious.md",
      case: "lsass"
    },
    {
      id: "amsi",
      fr: "Contournement AMSI via PowerShell",
      en: "PowerShell AMSI Bypass",
      techniques: ["T1059.001", "T1562.001"],
      tactic: { fr: "Exécution", en: "Execution" },
      status: "testing",
      risk: 75,
      severity: "high",
      schedule: "*/5 * * * *",
      file: "win_pwsh_t1059.001_amsi_bypass.md"
    },
    {
      id: "failed-logons",
      fr: "Rafale d’échecs d’authentification",
      en: "Failed Logon Burst",
      techniques: ["T1110.001", "T1110.003"],
      tactic: { fr: "Accès aux identifiants", en: "Credential Access" },
      status: "testing",
      risk: 50,
      severity: "medium",
      schedule: "*/5 * * * *",
      file: "win_secevt_t1110.001_failed_logon_burst.md"
    },
    {
      id: "download-cradle",
      fr: "PowerShell Download Cradle",
      en: "PowerShell Download Cradle",
      techniques: ["T1059.001", "T1105"],
      tactic: { fr: "Exécution", en: "Execution" },
      status: "testing",
      risk: 70,
      severity: "high",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1059.001_powershell_download_cradle.md"
    },
    {
      id: "cmd-obfuscation",
      fr: "Obfuscation de ligne de commande",
      en: "Command Shell Obfuscation",
      techniques: ["T1059.003", "T1027"],
      tactic: { fr: "Exécution", en: "Execution" },
      status: "testing",
      risk: 50,
      severity: "medium",
      schedule: "*/10 * * * *",
      file: "win_sysmon_t1059.003_cmd_obfuscation.md"
    },
    {
      id: "scheduled-task",
      fr: "Création d’une tâche planifiée",
      en: "Scheduled Task Creation",
      techniques: ["T1053.005"],
      tactic: { fr: "Persistance", en: "Persistence" },
      status: "testing",
      risk: 55,
      severity: "medium",
      schedule: "*/10 * * * *",
      file: "win_sysmon_t1053.005_scheduled_task_creation.md"
    },
    {
      id: "registry-helper",
      fr: "Persistance via helper de registre",
      en: "Registry Persistence Helper",
      techniques: ["T1112", "T1546.012"],
      tactic: { fr: "Persistance", en: "Persistence" },
      status: "testing",
      risk: 70,
      severity: "high",
      schedule: "*/10 * * * *",
      file: "win_sysmon_t1112_registry_persistence_helper.md"
    },
    {
      id: "ps-entropy",
      fr: "PowerShell obfusqué par entropie",
      en: "Obfuscated PowerShell Entropy",
      techniques: ["T1027"],
      tactic: { fr: "Évasion de défense", en: "Defense Evasion" },
      status: "testing",
      risk: 50,
      severity: "medium",
      schedule: "*/15 * * * *",
      file: "win_sysmon_t1027_obfuscated_powershell_entropy.md"
    },
    {
      id: "defender-tamper",
      fr: "Altération de Windows Defender",
      en: "Windows Defender Tampering",
      techniques: ["T1562.001"],
      tactic: { fr: "Évasion de défense", en: "Defense Evasion" },
      status: "testing",
      risk: 75,
      severity: "high",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1562.001_defender_tamper.md"
    },
    {
      id: "icacls",
      fr: "Modification permissive d’ACL via Icacls",
      en: "Icacls Permissive ACL Change",
      techniques: ["T1222.001"],
      tactic: { fr: "Évasion de défense", en: "Defense Evasion" },
      status: "testing",
      risk: 45,
      severity: "medium",
      schedule: "*/15 * * * *",
      file: "win_sysmon_t1222.001_icacls_permissive.md"
    },
    {
      id: "transfer-tools",
      fr: "Transfert via Curl ou Bitsadmin",
      en: "Curl or Bitsadmin Transfer",
      techniques: ["T1105"],
      tactic: { fr: "Commande et contrôle", en: "Command and Control" },
      status: "testing",
      risk: 50,
      severity: "medium",
      schedule: "*/5 * * * *",
      file: "win_sysmon_t1105_curl_wget_download.md"
    }
  ],

  cases: {
    lsass: {
      title: {
        fr: "Accès suspect à la mémoire du processus LSASS",
        en: "Suspicious access to LSASS process memory"
      },
      tactic: { fr: "ACCÈS AUX IDENTIFIANTS", en: "CREDENTIAL ACCESS" },
      technique: "T1003.001 · OS Credential Dumping: LSASS Memory",
      source: "Sysmon · EventCode 10 · ProcessAccess",
      risk: "90 / 100",
      severity: "critical",
      severityLabel: { fr: "CRITIQUE", en: "CRITICAL" },
      schedule: "*/5 * * * * · earliest=-10m@m · latest=-1m@m",
      hypothesis: {
        fr: "Un processus non standard demandant des droits d’accès à fort impact sur lsass.exe peut signaler une lecture mémoire ou une tentative de credential dumping.",
        en: "A non-standard process requesting high-impact access rights to lsass.exe can indicate credential dumping or an attempted memory read."
      },
      tuning: {
        fr: "Masques d’accès explicites + baseline de signataires Microsoft",
        en: "Explicit access masks + Microsoft signer baseline"
      },
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
      fields: [
        ["SourceImage", "C:\\Tools\\procdump64.exe"],
        ["TargetImage", "C:\\Windows\\System32\\lsass.exe"],
        ["GrantedAccess", "0x1fffff"],
        ["RuleName", "technique_id=T1003.001"]
      ],
      timeline: [
        {
          label: { fr: "Émuler", en: "Emulate" },
          detail: { fr: "Atomic Red Team T1003.001 génère un accès LSASS contrôlé.", en: "Atomic Red Team T1003.001 generates controlled LSASS access." }
        },
        {
          label: { fr: "Collecter", en: "Collect" },
          detail: { fr: "Sysmon conserve le processus source, la cible, le masque et la call trace.", en: "Sysmon records source process, target image, mask, and call trace." }
        },
        {
          label: { fr: "Détecter", en: "Match" },
          detail: { fr: "La règle sélectionne les droits à fort impact et retire la baseline approuvée.", en: "The rule selects high-impact rights and removes the approved baseline." }
        },
        {
          label: { fr: "Enrichir", en: "Enrich" },
          detail: { fr: "Technique MITRE, risque 90, hôte, utilisateur et contexte processus.", en: "MITRE technique, risk 90, host, user, and process context are attached." }
        },
        {
          label: { fr: "Répondre", en: "Respond" },
          detail: { fr: "Trier l’ascendance, le signataire, le compte et le besoin d’isolation.", en: "Triage process ancestry, signer, account activity, and host isolation need." }
        }
      ]
    },

    regsvr32: {
      title: {
        fr: "Exécution de scriptlet via Regsvr32",
        en: "Regsvr32 scriptlet execution"
      },
      tactic: { fr: "ÉVASION DE DÉFENSE", en: "DEFENSE EVASION" },
      technique: "T1218.010 · System Binary Proxy Execution: Regsvr32",
      source: "Sysmon · EventCode 1 · ProcessCreate",
      risk: "70 / 100",
      severity: "high",
      severityLabel: { fr: "ÉLEVÉE", en: "HIGH" },
      schedule: "*/5 * * * * · earliest=-10m@m · latest=-1m@m",
      hypothesis: {
        fr: "Regsvr32 chargeant un scriptlet distant peut détourner un binaire Windows signé afin de contourner des contrôles applicatifs simples.",
        en: "Regsvr32 loading a remotely hosted scriptlet can proxy execution through a trusted Windows binary and evade basic application controls."
      },
      tuning: {
        fr: "URI distante + indicateurs scriptlet + contexte parent/processus",
        en: "Remote URI + scriptlet indicators + parent/process context"
      },
      evidence: "assets/evidence/t1218-regsvr32.png",
      codeLabel: "win_sysmon_t1218.010_regsvr32_remote.spl",
      code: [
        "`sysmon_event(1)`",
        "| where match(lower(Image), \"\\\\\\\\regsvr32\\\\.exe$\")",
        "| where match(lower(CommandLine), \"(/i:|scrobj\\\\.dll)\")",
        "| where match(lower(CommandLine), \"https?://\")",
        "| eval risk_score=70, severity=\"high\"",
        "| table _time host user ParentImage Image CommandLine",
        "        ProcessId ParentProcessId risk_score severity"
      ].join("\n"),
      fields: [
        ["Image", "C:\\Windows\\System32\\regsvr32.exe"],
        ["CommandLine", "regsvr32.exe /s /n /u /i:… scrobj.dll"],
        ["ParentImage", "C:\\Windows\\System32\\cmd.exe"],
        ["Technique", "T1218.010"]
      ],
      timeline: [
        {
          label: { fr: "Émuler", en: "Emulate" },
          detail: { fr: "Un test Atomic sûr invoque le chemin d’exécution Squiblydoo.", en: "A safe Atomic test invokes the Squiblydoo execution path." }
        },
        {
          label: { fr: "Collecter", en: "Collect" },
          detail: { fr: "ProcessCreate capture la ligne de commande, l’image, le parent et les hashes.", en: "Process creation captures command line, image, parent, user, and hashes." }
        },
        {
          label: { fr: "Détecter", en: "Match" },
          detail: { fr: "L’analytique exige les indicateurs scriptlet et une ressource distante.", en: "The analytic requires scriptlet indicators and a remote resource." }
        },
        {
          label: { fr: "Enrichir", en: "Enrich" },
          detail: { fr: "T1218.010 et un risque 70 rendent l’événement exploitable.", en: "T1218.010 and a risk score of 70 make the event analyst-ready." }
        },
        {
          label: { fr: "Répondre", en: "Respond" },
          detail: { fr: "Examiner la ressource distante, l’arbre processus, le DNS et les téléchargements.", en: "Review the remote resource, process tree, DNS, and adjacent downloads." }
        }
      ]
    },

    powershell: {
      title: {
        fr: "Commande PowerShell encodée",
        en: "PowerShell encoded command"
      },
      tactic: { fr: "EXÉCUTION", en: "EXECUTION" },
      technique: "T1059.001 · Command and Scripting Interpreter: PowerShell",
      source: "Sysmon · EventCode 1 · ProcessCreate",
      risk: "60 / 100",
      severity: "high",
      severityLabel: { fr: "ÉLEVÉE", en: "HIGH" },
      schedule: "*/5 * * * * · earliest=-10m@m · latest=-1m@m",
      hypothesis: {
        fr: "Les paramètres PowerShell encodés masquent l’intention de la commande et deviennent un signal de triage fort lorsqu’ils sont associés au contexte processus complet.",
        en: "Encoded PowerShell flags hide command intent and become a strong triage signal when combined with full process context."
      },
      tuning: {
        fr: "Variantes de paramètres + longueur minimale du payload + contexte parent",
        en: "Flag variants + minimum payload length + parent context"
      },
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
      fields: [
        ["Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"],
        ["CommandLine", "powershell.exe -EncodedCommand [truncated]"],
        ["ParentImage", "C:\\Windows\\System32\\cmd.exe"],
        ["Technique", "T1059.001"]
      ],
      timeline: [
        {
          label: { fr: "Émuler", en: "Emulate" },
          detail: { fr: "Un test contrôlé exécute une charge PowerShell encodée bénigne.", en: "A controlled test runs a benign encoded PowerShell payload." }
        },
        {
          label: { fr: "Collecter", en: "Collect" },
          detail: { fr: "Sysmon préserve la commande et le contexte complet du processus parent.", en: "Sysmon preserves the command line and full parent process context." }
        },
        {
          label: { fr: "Détecter", en: "Match" },
          detail: { fr: "Les alias de paramètres et la longueur minimale réduisent le bruit.", en: "Flag aliases and a minimum payload length reduce substring noise." }
        },
        {
          label: { fr: "Enrichir", en: "Enrich" },
          detail: { fr: "T1059.001, sévérité, risque, hôte et utilisateur sont ajoutés.", en: "T1059.001, severity, risk, host, and user are attached." }
        },
        {
          label: { fr: "Répondre", en: "Respond" },
          detail: { fr: "Décoder le payload, inspecter l’ascendance et corréler l’activité réseau.", en: "Decode the payload, inspect ancestry, and correlate network activity." }
        }
      ]
    }
  }
};
