(function () {
  "use strict";

  var data = window.LAB_DATA;
  if (!data || !Array.isArray(data.detections)) {
    return;
  }

  var translations = {
    fr: {
      skip: "Aller au contenu",
      ariaWordmark: "Splunk Lab, posture de détection",
      ariaLanguage: "Langue",
      ariaSigned: "Signé A.S",
      ariaMainNavigation: "Navigation principale",
      ariaDataContext: "Contexte des données",
      ariaPostureMetrics: "Indicateurs de posture",
      ariaPlatformMetrics: "Indicateurs de plateforme",
      ariaSearchPresets: "Recherches disponibles",
      ariaFooterLinks: "Liens de pied de page",
      ariaClose: "Fermer",
      publicWorkspace: "INGÉNIERIE DE DÉTECTION · OPÉRATIONS SPLUNK",
      snapshotReady: "Snapshot disponible",
      repository: "Dépôt",
      appSubtitle: "PLATEFORME · CONTENU · PREUVES",
      navPosture: "Posture de détection",
      navPlatform: "Plateforme & données",
      navInvestigations: "Investigations",
      navAssurance: "Assurance",
      snapshotMode: "SNAPSHOT PUBLIC",
      snapshotDescription: "Données figées et assainies · aucune connexion à la VM · 25 juillet 2026",
      contentAnalytics: "CONTENT ANALYTICS",
      configuredPosture: "POSTURE CONFIGURÉE",
      postureTitle: "Posture du contenu de détection",
      postureIntro: "Inventaire filtrable des recherches planifiées : couverture ATT&CK, risque analytique configuré, cadence et niveau de validation.",
      sourceOfTruth: "SOURCE DE VÉRITÉ",
      runtime: "RUNTIME",
      analytic: "Analytique",
      analyticPlaceholder: "Titre, ID ou technique",
      status: "Statut",
      allStatuses: "Tous",
      tactic: "Tactique",
      allTactics: "Toutes",
      severity: "Sévérité",
      allSeverities: "Toutes",
      critical: "Critique",
      high: "Élevée",
      medium: "Moyenne",
      cadence: "Cadence",
      allCadences: "Toutes",
      reset: "Réinitialiser",
      tacticCoverage: "Couverture par tactique",
      tacticCoverageDetail: "Nombre d’analytiques dans le périmètre filtré",
      validationState: "État de validation",
      promotionContract: "Contrat de promotion du contenu",
      statusFootnote: "Production = preuve commitée et validation documentée.",
      riskDistribution: "Risque analytique configuré",
      notObservedRisk: "Score du contenu, pas des événements observés",
      cadenceDistribution: "Cadence des recherches",
      schedulerDistribution: "Distribution du scheduler",
      esDestinations: "Destinations ES-ready",
      configuredNotActive: "Configurées dans le lab, inactives dans ce snapshot",
      inactive: "INACTIF",
      indexedEvents: "événement indexé",
      indexedEventsPlural: "événements indexés",
      esDisclaimer: "Aucune donnée RBA ou Enterprise Security n’est simulée sur cette page.",
      attackMatrix: "Matrice ATT&CK du contenu",
      matrixDetail: "Technique unique · statut le plus mûr · intensité selon le risque configuré",
      risk45: "Risque 45–55",
      risk60: "Risque 60–70",
      risk75: "Risque 75–90",
      analyticRegister: "Registre des analytiques",
      heatmapDetail: "Trié par risque configuré · sélectionner une ligne pour enquêter",
      openSpecs: "Ouvrir les spécifications",
      state: "ÉTAT",
      detection: "DÉTECTION",
      risk: "RISQUE",
      schedule: "PLANIFICATION",
      validation: "VALIDATION",
      noDetection: "Aucune analytique ne correspond à ce périmètre.",
      platformEngineering: "PLATFORM ENGINEERING",
      dataQuality: "QUALITÉ DES DONNÉES",
      platformTitle: "Santé de la plateforme et des données",
      platformIntro: "Une vue d’administration lisible hors VM : capacité, rétention, composition du snapshot et chemin de livraison.",
      instance: "INSTANCE",
      license: "LICENCE",
      snapshotWorkbench: "Atelier de requêtes du snapshot",
      honestSearch: "Trois agrégats pris en charge · aucun job Splunk distant",
      readOnly: "LECTURE SEULE",
      presetSources: "Sources",
      presetSavedSearches: "Recherches",
      definitions: "définitions",
      configuredDefinitions: "Définitions de recherche configurées et versionnées",
      snapshotQuery: "Requête du snapshot",
      run: "Exécuter",
      snapshotManifest: "Manifeste du snapshot",
      captured: "Capturé",
      scope: "Périmètre",
      sanitizedWindow: "Fenêtre assainie",
      transport: "Transport",
      noNetwork: "Aucun · objet JS local",
      integrity: "Intégrité",
      supportedQueries: "REQUÊTES PRISES EN CHARGE",
      unsupportedNote: "Toute autre entrée est refusée explicitement ; l’interface ne simule ni SID, ni durée, ni résultat.",
      indexInventory: "Inventaire des indexes",
      purpose: "USAGE",
      lifetime: "LIFETIME",
      capacity: "CAPACITÉ",
      retention: "RÉTENTION",
      deliveryPath: "Chemin de livraison contrôlé",
      deliveryDetail: "Du capteur au contenu versionné",
      verifiedPath: "CHEMIN VÉRIFIÉ",
      windowsEndpoint: "Endpoint Windows",
      ufDetail: "Abonnements explicites dans inputs.conf",
      indexDetail: "Séparation sysmon / windows et rétention bornée",
      knowledgeObjects: "Objets de connaissance",
      scheduledContent: "Contenu planifié",
      schedulerDetail: "18 définitions déployées et suppressions ciblées",
      controlPlane: "Contrôles d’administration",
      effectiveConfig: "Configuration effective et reprise",
      confSyntax: "Syntaxe des .conf",
      lookupControl: "Lookup d’allowlist",
      sshControl: "Authentification par clé",
      managementApiControl: "API de management hors loopback",
      analystWorkflow: "ANALYST WORKFLOW",
      fieldEvidence: "PREUVE TERRAIN",
      investigationTitle: "Atelier d’investigation",
      investigationIntro: "Trois cas validés relient l’émulation, la télémétrie source, le SPL déployé, le tuning et l’action analyste.",
      method: "MÉTHODE",
      methodFlow: "Atomic / manuel → Sysmon → SPL",
      evidence: "PREUVE",
      committed: "Commitée",
      caseQueue: "FILE D’INVESTIGATION",
      sampleNotice: "Échantillons assainis",
      detectionHypothesis: "HYPOTHÈSE DE DÉTECTION",
      precisionControl: "CONTRÔLE DE PRÉCISION",
      deployedSpl: "SPL DÉPLOYÉ",
      copy: "Copier",
      preservedFields: "CHAMPS CONSERVÉS",
      sanitizedSample: "ÉCHANTILLON ASSAINI",
      analystAction: "ACTION ANALYSTE",
      openEvidence: "OUVRIR LA PREUVE",
      emulate: "Émuler",
      emulateDetail: "Atomic ou scénario manuel borné.",
      collect: "Collecter",
      collectDetail: "Conserver les champs nécessaires au triage.",
      match: "Détecter",
      matchDetail: "Appliquer le SPL et les exclusions explicites.",
      validate: "Valider",
      validateDetail: "Retrouver l’événement et commiter la preuve.",
      respond: "Répondre",
      respondDetail: "Passer du signal au contexte et à la décision.",
      engineeringAssurance: "ENGINEERING ASSURANCE",
      traceability: "TRAÇABILITÉ",
      assuranceTitle: "Preuves & maîtrise de la livraison",
      assuranceIntro: "Chaque affirmation publique renvoie à une configuration, une spécification ou une capture ; les limites restent visibles.",
      deliveryModel: "MODÈLE",
      publicSurface: "SURFACE PUBLIQUE",
      staticReadOnly: "Statique / lecture seule",
      claimLedger: "Registre des affirmations",
      claimLedgerDetail: "De la métrique affichée à l’artefact versionné",
      traceable: "TRAÇABLE",
      publicClaim: "AFFIRMATION PUBLIQUE",
      sourceArtifact: "ARTEFACT SOURCE",
      verification: "VÉRIFICATION",
      claimTelemetry: "Composition des 473 événements",
      frozenAggregate: "Agrégat figé",
      claimDetections: "Recherches planifiées et cadences",
      deployedContent: "Contenu déployé",
      claimCoverage: "Techniques et statuts ATT&CK",
      contentPosture: "Posture du contenu",
      claimEvidence: "Preuves et constats de validation",
      controlledLab: "Lab contrôlé",
      claimRetention: "Capacité et rétention",
      localInstance: "Instance locale",
      promotionQueue: "File de promotion",
      promotionQueueDetail: "Un blocage concret, pas un score décoratif",
      promotionFinding: "CONSTAT",
      promotionFindingDetail: "Le test Atomic renomme certutil.exe.",
      promotionCandidate: "CANDIDAT",
      promotionBlockerLabel: "BLOCAGE",
      promotionBlocker: "L’extraction de OriginalFileName n’est pas encore prouvée de bout en bout.",
      promotionNextProof: "PROCHAINE PREUVE",
      promotionNextProofDetail: "Rejouer T1140 #2, capturer le résultat et l’événement brut, puis promouvoir.",
      validationGallery: "Galerie de validation",
      galleryDetail: "Captures conservées avec le chemin de preuve",
      declaredGaps: "Écarts déclarés",
      gapsDetail: "La dépendance manquante est traitée comme une donnée d’ingénierie",
      boundary: "PÉRIMÈTRE",
      publicSurfaceSecurity: "Surface publique maîtrisée",
      securityDetail: "Propriétés vérifiables du portfolio statique",
      staticOnly: "HTML, CSS et JS statiques",
      staticOnlyDetail: "Aucun backend, formulaire ou compte utilisateur.",
      sameOrigin: "Ressources servies localement",
      sameOriginDetail: "Aucune police, bibliothèque ou télémétrie tierce.",
      cspDetail: "Scripts, styles et images limités à l’origine.",
      noSecrets: "Aucun secret client",
      noSecretsDetail: "Le snapshot ne contient ni adresse privée, ni identifiant d’administration.",
      declaredScope: "Périmètre déclaré",
      scopeDetail: "Ce qui est démontré — et ce qui ne l’est pas",
      scopeYes1: "Splunk Enterprise standalone et administration locale",
      scopeYes2: "Sysmon + canaux Windows via Universal Forwarder",
      scopeYes3: "Détection-as-code et validation contrôlée",
      scopeNo1: "Aucune instance Enterprise Security présentée comme active",
      scopeNo2: "Aucun SOAR, cluster indexer ou domaine Active Directory",
      footerDetail: "Configuration, SPL et preuves versionnés",
      craftedBy: "Conçu et maintenu par",
      backToPosture: "Retour à la posture ↑",
      evidenceTitle: "Preuve de validation",
      kpiAnalytics: "Analytiques dans le périmètre",
      kpiProduction: "Validées Production",
      kpiTechniques: "Techniques ATT&CK uniques",
      kpiMedianRisk: "Risque configuré médian",
      kpiDataSources: "Familles de données",
      filteredScope: "périmètre filtré",
      production: "Production",
      testing: "Testing",
      ofAnalytics: "des analytiques",
      configuredScore: "score configuré",
      dataFamilies: "sources logiques",
      searchReady: "Résultat local du snapshot",
      rows: "lignes",
      row: "ligne",
      queryRejected: "Requête refusée : cet agrégat n’existe pas dans le snapshot public.",
      queryHelp: "Utilisez exactement l’une des trois requêtes prises en charge.",
      events: "événements",
      snapshotEvents: "Événements du snapshot",
      lifetimeEvents: "Événements cumulés",
      sourcetypes: "Sourcetypes présents",
      activeIndexes: "Indexes recherchables",
      configuredInactive: "CONFIGURÉ · INACTIF",
      searchable: "RECHERCHABLE",
      atomicEvidence: "Atomic + preuve",
      manualEvidence: "Manuel + preuve",
      implemented: "Implémentée · à promouvoir",
      minutes: "minutes",
      copied: "SPL copié dans le presse-papiers.",
      copyFailed: "Copie automatique indisponible ; sélectionnez le SPL manuellement.",
      severityCritical: "CRITIQUE",
      severityHigh: "ÉLEVÉE",
      severityMedium: "MOYENNE",
      evidenceModalAlt: "Capture de validation Splunk en pleine résolution",
      matrixTechniques: "techniques",
      sourceLabel: "Source",
      countLabel: "Nombre",
      currentSnapshot: "snapshot public",
      noRows: "Aucun résultat dans ce périmètre."
    },
    en: {
      skip: "Skip to content",
      ariaWordmark: "Splunk Lab, detection posture",
      ariaLanguage: "Language",
      ariaSigned: "Signed A.S",
      ariaMainNavigation: "Main navigation",
      ariaDataContext: "Data context",
      ariaPostureMetrics: "Posture metrics",
      ariaPlatformMetrics: "Platform metrics",
      ariaSearchPresets: "Available searches",
      ariaFooterLinks: "Footer links",
      ariaClose: "Close",
      publicWorkspace: "DETECTION ENGINEERING · SPLUNK OPERATIONS",
      snapshotReady: "Snapshot available",
      repository: "Repository",
      appSubtitle: "Platform · Content · Evidence",
      navPosture: "Detection posture",
      navPlatform: "Platform & data",
      navInvestigations: "Investigations",
      navAssurance: "Assurance",
      snapshotMode: "PUBLIC SNAPSHOT",
      snapshotDescription: "Frozen, sanitized data · no VM connection · July 25, 2026",
      contentAnalytics: "CONTENT ANALYTICS",
      configuredPosture: "CONFIGURED POSTURE",
      postureTitle: "Detection Content Posture",
      postureIntro: "Filterable scheduled-search inventory: ATT&CK coverage, configured analytic risk, cadence, and validation level.",
      sourceOfTruth: "SOURCE OF TRUTH",
      runtime: "RUNTIME",
      analytic: "Analytic",
      analyticPlaceholder: "Title, ID, or technique",
      status: "Status",
      allStatuses: "All",
      tactic: "Tactic",
      allTactics: "All",
      severity: "Severity",
      allSeverities: "All",
      critical: "Critical",
      high: "High",
      medium: "Medium",
      cadence: "Cadence",
      allCadences: "All",
      reset: "Reset",
      tacticCoverage: "Coverage by tactic",
      tacticCoverageDetail: "Analytics in the filtered scope",
      validationState: "Validation state",
      promotionContract: "Content promotion contract",
      statusFootnote: "Production = committed evidence and documented validation.",
      riskDistribution: "Configured analytic risk",
      notObservedRisk: "Content score, not observed event risk",
      cadenceDistribution: "Search cadence",
      schedulerDistribution: "Scheduler distribution",
      esDestinations: "ES-ready destinations",
      configuredNotActive: "Configured in the lab, inactive in this snapshot",
      inactive: "INACTIVE",
      indexedEvents: "indexed event",
      indexedEventsPlural: "indexed events",
      esDisclaimer: "No RBA or Enterprise Security data is simulated on this page.",
      attackMatrix: "Content ATT&CK matrix",
      matrixDetail: "Unique technique · highest maturity · intensity by configured risk",
      risk45: "Risk 45–55",
      risk60: "Risk 60–70",
      risk75: "Risk 75–90",
      analyticRegister: "Analytic register",
      heatmapDetail: "Sorted by configured risk · select a row to investigate",
      openSpecs: "Open specifications",
      state: "STATE",
      detection: "DETECTION",
      risk: "RISK",
      schedule: "SCHEDULE",
      validation: "VALIDATION",
      noDetection: "No analytic matches this scope.",
      platformEngineering: "PLATFORM ENGINEERING",
      dataQuality: "DATA QUALITY",
      platformTitle: "Platform & Data Health",
      platformIntro: "An administration view that works without the VM: capacity, retention, snapshot composition, and delivery path.",
      instance: "INSTANCE",
      license: "LICENSE",
      snapshotWorkbench: "Snapshot Search Workbench",
      honestSearch: "Three supported aggregates · no remote Splunk job",
      readOnly: "READ-ONLY",
      presetSources: "Sources",
      presetSavedSearches: "Saved searches",
      definitions: "definitions",
      configuredDefinitions: "Configured and versioned search definitions",
      snapshotQuery: "Snapshot query",
      run: "Run",
      snapshotManifest: "Snapshot manifest",
      captured: "Captured",
      scope: "Scope",
      sanitizedWindow: "Sanitized window",
      transport: "Transport",
      noNetwork: "None · local JS object",
      integrity: "Integrity",
      supportedQueries: "SUPPORTED QUERIES",
      unsupportedNote: "Any other input is explicitly refused; the interface simulates no SID, duration, or result.",
      indexInventory: "Index inventory",
      purpose: "PURPOSE",
      lifetime: "LIFETIME",
      capacity: "CAPACITY",
      retention: "RETENTION",
      deliveryPath: "Controlled delivery path",
      deliveryDetail: "From sensor to versioned content",
      verifiedPath: "VERIFIED PATH",
      windowsEndpoint: "Windows endpoint",
      ufDetail: "Explicit channel subscriptions in inputs.conf",
      indexDetail: "Separate sysmon / windows indexes and bounded retention",
      knowledgeObjects: "Knowledge objects",
      scheduledContent: "Scheduled content",
      schedulerDetail: "18 deployed definitions and targeted suppression",
      controlPlane: "Administration controls",
      effectiveConfig: "Effective configuration and recovery",
      confSyntax: ".conf syntax",
      lookupControl: "Allowlist lookup",
      sshControl: "Key-based authentication",
      managementApiControl: "Management API outside loopback",
      analystWorkflow: "ANALYST WORKFLOW",
      fieldEvidence: "FIELD EVIDENCE",
      investigationTitle: "Investigation Workbench",
      investigationIntro: "Three validated cases connect emulation, source telemetry, deployed SPL, tuning, and analyst action.",
      method: "METHOD",
      methodFlow: "Atomic / manual → Sysmon → SPL",
      evidence: "EVIDENCE",
      committed: "Committed",
      caseQueue: "INVESTIGATION QUEUE",
      sampleNotice: "Sanitized samples",
      detectionHypothesis: "DETECTION HYPOTHESIS",
      precisionControl: "PRECISION CONTROL",
      deployedSpl: "DEPLOYED SPL",
      copy: "Copy",
      preservedFields: "PRESERVED FIELDS",
      sanitizedSample: "SANITIZED SAMPLE",
      analystAction: "ANALYST ACTION",
      openEvidence: "OPEN EVIDENCE",
      emulate: "Emulate",
      emulateDetail: "Bounded Atomic or manual scenario.",
      collect: "Collect",
      collectDetail: "Preserve fields required for triage.",
      match: "Match",
      matchDetail: "Apply SPL and explicit exclusions.",
      validate: "Validate",
      validateDetail: "Retrieve the event and commit evidence.",
      respond: "Respond",
      respondDetail: "Move from signal to context and decision.",
      engineeringAssurance: "ENGINEERING ASSURANCE",
      traceability: "TRACEABILITY",
      assuranceTitle: "Evidence & Delivery Assurance",
      assuranceIntro: "Every public claim points to configuration, specification, or a screenshot; limits remain visible.",
      deliveryModel: "MODEL",
      publicSurface: "PUBLIC SURFACE",
      staticReadOnly: "Static / read-only",
      claimLedger: "Claim ledger",
      claimLedgerDetail: "From displayed metric to versioned artifact",
      traceable: "TRACEABLE",
      publicClaim: "PUBLIC CLAIM",
      sourceArtifact: "SOURCE ARTIFACT",
      verification: "VERIFICATION",
      claimTelemetry: "Composition of 473 events",
      frozenAggregate: "Frozen aggregate",
      claimDetections: "Scheduled searches and cadences",
      deployedContent: "Deployed content",
      claimCoverage: "ATT&CK techniques and status",
      contentPosture: "Content posture",
      claimEvidence: "Validation evidence and findings",
      controlledLab: "Controlled lab",
      claimRetention: "Capacity and retention",
      localInstance: "Local instance",
      promotionQueue: "Promotion queue",
      promotionQueueDetail: "A concrete blocker, not a decorative score",
      promotionFinding: "FINDING",
      promotionFindingDetail: "The Atomic test renames certutil.exe.",
      promotionCandidate: "CANDIDATE",
      promotionBlockerLabel: "BLOCKER",
      promotionBlocker: "End-to-end OriginalFileName extraction has not yet been proven.",
      promotionNextProof: "NEXT EVIDENCE",
      promotionNextProofDetail: "Rerun T1140 #2, capture the result and raw event, then promote.",
      validationGallery: "Validation gallery",
      galleryDetail: "Screenshots retained with their evidence path",
      declaredGaps: "Declared gaps",
      gapsDetail: "The missing dependency is treated as engineering data",
      boundary: "BOUNDARY",
      publicSurfaceSecurity: "Controlled public surface",
      securityDetail: "Verifiable properties of the static portfolio",
      staticOnly: "Static HTML, CSS, and JS",
      staticOnlyDetail: "No backend, form, or user account.",
      sameOrigin: "Same-origin assets",
      sameOriginDetail: "No third-party font, library, or telemetry.",
      cspDetail: "Scripts, styles, and images are origin-restricted.",
      noSecrets: "No client-side secret",
      noSecretsDetail: "The snapshot contains no private address or administration credential.",
      declaredScope: "Declared scope",
      scopeDetail: "What is demonstrated — and what is not",
      scopeYes1: "Standalone Splunk Enterprise and local administration",
      scopeYes2: "Sysmon + Windows channels through Universal Forwarder",
      scopeYes3: "Detection-as-code and controlled validation",
      scopeNo1: "No Enterprise Security instance presented as active",
      scopeNo2: "No SOAR, indexer cluster, or Active Directory domain",
      footerDetail: "Versioned configuration, SPL, and evidence",
      craftedBy: "Designed and maintained by",
      backToPosture: "Back to posture ↑",
      evidenceTitle: "Validation evidence",
      kpiAnalytics: "Analytics in scope",
      kpiProduction: "Production validated",
      kpiTechniques: "Unique ATT&CK techniques",
      kpiMedianRisk: "Median configured risk",
      kpiDataSources: "Data families",
      filteredScope: "filtered scope",
      production: "Production",
      testing: "Testing",
      ofAnalytics: "of analytics",
      configuredScore: "configured score",
      dataFamilies: "logical sources",
      searchReady: "Local snapshot result",
      rows: "rows",
      row: "row",
      queryRejected: "Query refused: this aggregate is not present in the public snapshot.",
      queryHelp: "Use exactly one of the three supported queries.",
      events: "events",
      snapshotEvents: "Snapshot events",
      lifetimeEvents: "Lifetime events",
      sourcetypes: "Sourcetypes present",
      activeIndexes: "Searchable indexes",
      configuredInactive: "CONFIGURED · INACTIVE",
      searchable: "SEARCHABLE",
      atomicEvidence: "Atomic + evidence",
      manualEvidence: "Manual + evidence",
      implemented: "Implemented · awaiting promotion",
      minutes: "minutes",
      copied: "SPL copied to the clipboard.",
      copyFailed: "Automatic copy is unavailable; select the SPL manually.",
      severityCritical: "CRITICAL",
      severityHigh: "HIGH",
      severityMedium: "MEDIUM",
      evidenceModalAlt: "Full-resolution Splunk validation screenshot",
      matrixTechniques: "techniques",
      sourceLabel: "Source",
      countLabel: "Count",
      currentSnapshot: "public snapshot",
      noRows: "No result in this scope."
    }
  };

  var currentLanguage = readStoredLanguage();
  var activeView = getInitialView();
  var activeCaseKey = data.cases[0].key;
  var toastTimer = 0;

  var queryDefinitions = {
    sources: "index=* | stats count by index sourcetype | sort - count",
    eventcodes: "index=sysmon | stats count by EventCode | sort - count",
    savedsearches: "| rest /services/saved/searches | search disabled=0 | stats count"
  };

  function readStoredLanguage() {
    try {
      var stored = window.localStorage.getItem("splunkPortfolioLanguage");
      return stored === "en" ? "en" : "fr";
    } catch (error) {
      return "fr";
    }
  }

  function storeLanguage(language) {
    try {
      window.localStorage.setItem("splunkPortfolioLanguage", language);
    } catch (error) {
      return;
    }
  }

  function getInitialView() {
    var candidate = window.location.hash.replace("#", "");
    return ["posture", "platform", "investigations", "assurance"].indexOf(candidate) >= 0
      ? candidate
      : "posture";
  }

  function text(key) {
    return translations[currentLanguage][key] || translations.fr[key] || key;
  }

  function localized(value) {
    if (value && typeof value === "object") {
      return value[currentLanguage] || value.fr || value.en || "";
    }
    return value == null ? "" : String(value);
  }

  function formatNumber(value) {
    return new Intl.NumberFormat(currentLanguage === "fr" ? "fr-FR" : "en-US").format(value);
  }

  function create(tagName, className, content) {
    var element = document.createElement(tagName);
    if (className) {
      element.className = className;
    }
    if (content !== undefined && content !== null) {
      element.textContent = String(content);
    }
    return element;
  }

  function svgElement(tagName, attributes) {
    var element = document.createElementNS("http://www.w3.org/2000/svg", tagName);
    Object.keys(attributes || {}).forEach(function (name) {
      element.setAttribute(name, String(attributes[name]));
    });
    return element;
  }

  function createBarSvg(value, maximum, label) {
    var width = maximum > 0 ? Math.max(0, Math.min(100, (value / maximum) * 100)) : 0;
    var svg = svgElement("svg", {
      class: "bar-svg",
      viewBox: "0 0 100 10",
      preserveAspectRatio: "none",
      role: "img",
      "aria-label": label
    });
    var title = svgElement("title");
    title.textContent = label;
    svg.appendChild(title);
    svg.appendChild(svgElement("rect", { class: "bar-track", x: 0, y: 0, width: 100, height: 10 }));
    svg.appendChild(svgElement("rect", { class: "bar-value", x: 0, y: 0, width: width, height: 10 }));
    return svg;
  }

  function normalizeQuery(value) {
    return value.trim().replace(/\s+/g, " ");
  }

  function cadenceMinutes(detection) {
    var match = detection.schedule.cron.match(/^\*\/(\d+)/);
    return match ? Number(match[1]) : 0;
  }

  function tacticDefinition(key) {
    return data.tacticOrder.find(function (item) {
      return item.key === key;
    });
  }

  function tacticLabel(key) {
    var tactic = tacticDefinition(key);
    return tactic ? localized(tactic) : key;
  }

  function severityLabel(severity) {
    return text("severity" + severity.charAt(0).toUpperCase() + severity.slice(1));
  }

  function validationLabel(detection) {
    if (detection.validation.type === "atomic") {
      return text("atomicEvidence");
    }
    if (detection.validation.type === "manual") {
      return text("manualEvidence");
    }
    return text("implemented");
  }

  function median(values) {
    if (!values.length) {
      return 0;
    }
    var sorted = values.slice().sort(function (a, b) {
      return a - b;
    });
    var middle = Math.floor(sorted.length / 2);
    return sorted.length % 2
      ? sorted[middle]
      : (sorted[middle - 1] + sorted[middle]) / 2;
  }

  function unique(values) {
    return Array.from(new Set(values));
  }

  function detectionTactics(detection) {
    return unique(detection.techniques.map(function (technique) {
      return data.attackTactics[technique] || detection.tactic;
    }));
  }

  function getFilteredDetections() {
    var query = document.getElementById("analytic-filter").value.trim().toLocaleLowerCase();
    var status = document.getElementById("status-filter").value;
    var tactic = document.getElementById("tactic-filter").value;
    var severity = document.getElementById("severity-filter").value;
    var cadence = document.getElementById("cadence-filter").value;

    return data.detections.filter(function (detection) {
      var searchable = [
        localized(detection.title),
        detection.id,
        detection.file,
        detection.techniques.join(" "),
        detectionTactics(detection).map(tacticLabel).join(" ")
      ].join(" ").toLocaleLowerCase();

      return (!query || searchable.indexOf(query) >= 0)
        && (status === "all" || detection.status === status)
        && (tactic === "all" || detectionTactics(detection).indexOf(tactic) >= 0)
        && (severity === "all" || detection.severity === severity)
        && (cadence === "all" || cadenceMinutes(detection) === Number(cadence));
    });
  }

  function populateTacticSelect() {
    var select = document.getElementById("tactic-filter");
    var selected = select.value || "all";
    var options = [create("option", "", text("allTactics"))];
    options[0].value = "all";
    data.tacticOrder.forEach(function (tactic) {
      var option = create("option", "", localized(tactic));
      option.value = tactic.key;
      options.push(option);
    });
    select.replaceChildren.apply(select, options);
    select.value = data.tacticOrder.some(function (item) {
      return item.key === selected;
    }) ? selected : "all";
  }

  function renderPosture() {
    var filtered = getFilteredDetections();
    document.getElementById("filter-count").textContent =
      formatNumber(filtered.length) + " / " + formatNumber(data.detections.length);
    renderPostureKpis(filtered);
    renderTacticChart(filtered);
    renderStatusChart(filtered);
    renderSeverityChart(filtered);
    renderCadenceChart(filtered);
    renderAttackMatrix(filtered);
    renderDetectionTable(filtered);
  }

  function renderPostureKpis(detections) {
    var productionCount = detections.filter(function (item) {
      return item.status === "production";
    }).length;
    var techniques = unique(detections.flatMap(function (item) {
      return item.techniques;
    }));
    var sources = unique(detections.map(function (item) {
      return item.dataSource.split(" · ")[0];
    }));
    var productionPercent = detections.length
      ? Math.round((productionCount / detections.length) * 100)
      : 0;
    var definitions = [
      {
        label: text("kpiAnalytics"),
        value: detections.length,
        note: text("filteredScope"),
        className: "kpi-blue"
      },
      {
        label: text("kpiProduction"),
        value: productionCount,
        note: productionPercent + "% " + text("ofAnalytics"),
        className: "kpi-green"
      },
      {
        label: text("kpiTechniques"),
        value: techniques.length,
        note: "Enterprise ATT&CK",
        className: "kpi-purple"
      },
      {
        label: text("kpiMedianRisk"),
        value: median(detections.map(function (item) {
          return item.risk;
        })),
        note: text("configuredScore"),
        className: "kpi-orange"
      },
      {
        label: text("kpiDataSources"),
        value: sources.length,
        note: text("dataFamilies"),
        className: "kpi-cyan"
      }
    ];

    var children = definitions.map(function (definition) {
      var card = create("article", "posture-kpi " + definition.className);
      card.appendChild(create("span", "", definition.label));
      card.appendChild(create("strong", "", formatNumber(definition.value)));
      card.appendChild(create("small", "", definition.note));
      return card;
    });
    document.getElementById("posture-kpis").replaceChildren.apply(
      document.getElementById("posture-kpis"),
      children
    );
  }

  function renderTacticChart(detections) {
    var counts = {};
    data.tacticOrder.forEach(function (item) {
      counts[item.key] = 0;
    });
    detections.forEach(function (item) {
      detectionTactics(item).forEach(function (tactic) {
        counts[tactic] = (counts[tactic] || 0) + 1;
      });
    });
    var maximum = Math.max.apply(Math, Object.values(counts).concat([1]));

    var rows = data.tacticOrder.map(function (tactic) {
      var row = create("div", "rank-row");
      var button = create("button", "", localized(tactic));
      button.type = "button";
      button.addEventListener("click", function () {
        document.getElementById("tactic-filter").value = tactic.key;
        renderPosture();
      });
      row.appendChild(button);
      row.appendChild(createBarSvg(
        counts[tactic.key],
        maximum,
        localized(tactic) + ": " + counts[tactic.key]
      ));
      row.appendChild(create("strong", "", formatNumber(counts[tactic.key])));
      return row;
    });
    document.getElementById("tactic-chart").replaceChildren.apply(
      document.getElementById("tactic-chart"),
      rows
    );
  }

  function renderStatusChart(detections) {
    var total = detections.length;
    var production = detections.filter(function (item) {
      return item.status === "production";
    }).length;
    var testing = total - production;
    var circumference = 2 * Math.PI * 45;
    var productionLength = total ? (production / total) * circumference : 0;
    var testingLength = total ? (testing / total) * circumference : 0;

    var wrap = create("div", "donut-wrap");
    var svg = svgElement("svg", {
      class: "donut-svg",
      viewBox: "0 0 120 120",
      role: "img",
      "aria-label": text("production") + " " + production + ", " + text("testing") + " " + testing
    });
    svg.appendChild(svgElement("circle", {
      class: "donut-track",
      cx: 60,
      cy: 60,
      r: 45
    }));
    var productionCircle = svgElement("circle", {
      class: "donut-segment donut-production",
      cx: 60,
      cy: 60,
      r: 45,
      "stroke-dasharray": productionLength + " " + (circumference - productionLength),
      "stroke-dashoffset": 0
    });
    var testingCircle = svgElement("circle", {
      class: "donut-segment donut-testing",
      cx: 60,
      cy: 60,
      r: 45,
      "stroke-dasharray": testingLength + " " + (circumference - testingLength),
      "stroke-dashoffset": -productionLength
    });
    svg.appendChild(productionCircle);
    svg.appendChild(testingCircle);
    wrap.appendChild(svg);

    var center = create("div", "donut-center");
    center.appendChild(create("strong", "", total ? Math.round((production / total) * 100) + "%" : "—"));
    center.appendChild(create("small", "", text("production")));
    wrap.appendChild(center);

    var legend = create("div", "donut-legend");
    var productionLegend = create("span");
    productionLegend.appendChild(create("i", "production"));
    productionLegend.appendChild(document.createTextNode(text("production") + " " + production));
    var testingLegend = create("span");
    testingLegend.appendChild(create("i", "testing"));
    testingLegend.appendChild(document.createTextNode(text("testing") + " " + testing));
    legend.append(productionLegend, testingLegend);

    var container = document.getElementById("status-chart");
    container.replaceChildren(wrap, legend);
  }

  function renderSeverityChart(detections) {
    var severities = ["critical", "high", "medium"];
    var counts = {};
    severities.forEach(function (severity) {
      counts[severity] = detections.filter(function (item) {
        return item.severity === severity;
      }).length;
    });
    var total = detections.length || 1;
    var container = document.getElementById("severity-chart");
    var summary = create("div", "risk-summary");
    summary.appendChild(create("strong", "", detections.length
      ? formatNumber(median(detections.map(function (item) {
        return item.risk;
      })))
      : "—"));
    summary.appendChild(create("span", "", text("kpiMedianRisk")));

    var svg = svgElement("svg", {
      class: "segmented-svg",
      viewBox: "0 0 300 20",
      preserveAspectRatio: "none",
      role: "img",
      "aria-label": severities.map(function (severity) {
        return severityLabel(severity) + " " + counts[severity];
      }).join(", ")
    });
    svg.appendChild(svgElement("rect", { x: 0, y: 0, width: 300, height: 20, fill: "#343c42" }));
    var cursor = 0;
    var colors = { critical: "#d84b55", high: "#d97845", medium: "#55a9db" };
    severities.forEach(function (severity) {
      var width = (counts[severity] / total) * 300;
      svg.appendChild(svgElement("rect", {
        x: cursor,
        y: 0,
        width: width,
        height: 20,
        fill: colors[severity]
      }));
      cursor += width;
    });

    var list = create("div", "severity-list");
    severities.forEach(function (severity) {
      var row = create("div");
      row.appendChild(create("i", severity));
      row.appendChild(create("span", "", severityLabel(severity)));
      row.appendChild(create("b", "", counts[severity]));
      list.appendChild(row);
    });
    container.replaceChildren(summary, svg, list);
  }

  function renderCadenceChart(detections) {
    var cadences = [5, 10, 15];
    var counts = {};
    cadences.forEach(function (minutes) {
      counts[minutes] = detections.filter(function (item) {
        return cadenceMinutes(item) === minutes;
      }).length;
    });
    var maximum = Math.max.apply(Math, cadences.map(function (minutes) {
      return counts[minutes];
    }).concat([1]));

    var rows = cadences.map(function (minutes) {
      var row = create("div", "cadence-row");
      row.appendChild(create("span", "", "*/" + minutes + "m"));
      var progress = create("progress");
      progress.max = maximum;
      progress.value = counts[minutes];
      progress.setAttribute("aria-label", minutes + " " + text("minutes") + ": " + counts[minutes]);
      row.appendChild(progress);
      row.appendChild(create("b", "", counts[minutes]));
      return row;
    });
    rows.push(create("p", "cadence-note", "dispatch.latest_time = -1m@m"));
    document.getElementById("cadence-chart").replaceChildren.apply(
      document.getElementById("cadence-chart"),
      rows
    );
  }

  function renderAttackMatrix(detections) {
    var container = document.getElementById("attack-matrix");
    var columns = data.tacticOrder.map(function (tactic, tacticIndex) {
      var inTactic = detections.filter(function (item) {
        return detectionTactics(item).indexOf(tactic.key) >= 0;
      });
      var techniques = {};
      inTactic.forEach(function (detection) {
        detection.techniques.forEach(function (technique) {
          if ((data.attackTactics[technique] || detection.tactic) !== tactic.key) {
            return;
          }
          if (!techniques[technique]) {
            techniques[technique] = {
              id: technique,
              risk: detection.risk,
              production: detection.status === "production",
              count: 1
            };
          } else {
            techniques[technique].risk = Math.max(techniques[technique].risk, detection.risk);
            techniques[technique].production =
              techniques[technique].production || detection.status === "production";
            techniques[technique].count += 1;
          }
        });
      });

      var column = create("section", "matrix-column matrix-tactic-" + (tacticIndex + 1));
      var header = create("header");
      header.appendChild(create("b", "", localized(tactic)));
      header.appendChild(create("span", "", Object.keys(techniques).length));
      column.appendChild(header);
      var cells = create("div", "matrix-techniques");
      Object.values(techniques).sort(function (a, b) {
        return a.id.localeCompare(b.id);
      }).forEach(function (technique) {
        var riskClass = technique.risk >= 75 ? "risk-high" : technique.risk >= 60 ? "risk-mid" : "risk-low";
        var button = create(
          "button",
          "technique-cell " + riskClass + (technique.production ? " production" : "")
        );
        button.type = "button";
        button.appendChild(create("b", "", technique.id));
        button.appendChild(create("small", "", "risk " + technique.risk));
        button.addEventListener("click", function () {
          document.getElementById("analytic-filter").value = technique.id;
          renderPosture();
          document.querySelector(".analytics-panel").scrollIntoView({ block: "start", behavior: "smooth" });
        });
        cells.appendChild(button);
      });
      if (!Object.keys(techniques).length) {
        cells.appendChild(create("span", "matrix-empty", "—"));
      }
      column.appendChild(cells);
      return column;
    });
    container.replaceChildren.apply(container, columns);
    var techniqueCount = unique(detections.flatMap(function (item) {
      return item.techniques;
    })).length;
    document.getElementById("matrix-scope").textContent =
      techniqueCount + " " + text("matrixTechniques");
  }

  function renderDetectionTable(detections) {
    var body = document.getElementById("detection-table");
    var sorted = detections.slice().sort(function (a, b) {
      return b.risk - a.risk || localized(a.title).localeCompare(localized(b.title));
    });
    var rows = sorted.map(function (detection) {
      var row = create("tr");

      var statusTd = create("td");
      var status = create("span", "status-cell " + detection.status);
      status.appendChild(create("i"));
      status.appendChild(document.createTextNode(
        detection.status === "production" ? text("production").toUpperCase() : text("testing").toUpperCase()
      ));
      statusTd.appendChild(status);

      var titleTd = create("td");
      var titleWrap = create("div", "analytic-title");
      var caseEntry = data.cases.find(function (item) {
        return item.detectionId === detection.id;
      });
      if (caseEntry) {
        var caseButton = create("button", "", localized(detection.title));
        caseButton.type = "button";
        caseButton.addEventListener("click", function () {
          activeCaseKey = caseEntry.key;
          renderCases();
          activateView("investigations", true, true);
        });
        titleWrap.appendChild(caseButton);
      } else {
        var link = create("a", "", localized(detection.title) + " ↗");
        link.href = data.meta.repository + "/blob/main/detections/" + encodeURIComponent(detection.file);
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        titleWrap.appendChild(link);
      }
      titleWrap.appendChild(create("code", "", detection.id));
      titleTd.appendChild(titleWrap);

      var techniquesTd = create("td");
      var techniqueList = create("div", "technique-list");
      detection.techniques.forEach(function (technique) {
        var techniqueButton = create("button", "", technique);
        techniqueButton.type = "button";
        techniqueButton.addEventListener("click", function () {
          document.getElementById("analytic-filter").value = technique;
          renderPosture();
        });
        techniqueList.appendChild(techniqueButton);
      });
      techniquesTd.appendChild(techniqueList);

      var tacticTd = create("td", "", detectionTactics(detection).map(tacticLabel).join(" · "));
      var riskTd = create("td");
      riskTd.appendChild(create("span", "risk-heat " + detection.severity, detection.risk));
      var scheduleTd = create("td");
      scheduleTd.appendChild(create("code", "cron-cell", detection.schedule.cron));
      var validationTd = create("td");
      validationTd.appendChild(create("span", "validation-label", validationLabel(detection)));

      row.append(statusTd, titleTd, techniquesTd, tacticTd, riskTd, scheduleTd, validationTd);
      return row;
    });
    body.replaceChildren.apply(body, rows);
    document.getElementById("detection-empty").hidden = rows.length !== 0;
  }

  function renderPlatformFacts() {
    var definitions = [
      {
        label: text("lifetimeEvents"),
        value: data.provenance.lifetime.totalEvents,
        note: "sysmon + windows"
      },
      {
        label: text("snapshotEvents"),
        value: data.provenance.snapshot.totalEvents,
        note: text("currentSnapshot")
      },
      {
        label: text("sourcetypes"),
        value: data.sources.length,
        note: "390 / 76 / 6 / 1"
      },
      {
        label: text("activeIndexes"),
        value: data.indexes.filter(function (index) {
          return index.state === "searchable";
        }).length,
        note: "risk + notable: 0"
      }
    ];
    var cards = definitions.map(function (definition) {
      var card = create("article", "platform-fact");
      card.appendChild(create("span", "", definition.label));
      card.appendChild(create("strong", "", formatNumber(definition.value)));
      card.appendChild(create("small", "", definition.note));
      return card;
    });
    var container = document.getElementById("platform-facts");
    container.replaceChildren.apply(container, cards);
  }

  function findQueryKey(query) {
    var normalized = normalizeQuery(query);
    return Object.keys(queryDefinitions).find(function (key) {
      return normalizeQuery(queryDefinitions[key]) === normalized;
    }) || null;
  }

  function renderSnapshotQuery(queryKey) {
    var input = document.getElementById("snapshot-query");
    var query = queryKey ? queryDefinitions[queryKey] : input.value;
    var resolvedKey = queryKey || findQueryKey(query);
    var status = document.getElementById("query-status");
    var result = document.getElementById("search-result");

    if (!resolvedKey) {
      status.classList.add("error");
      status.textContent = text("queryRejected") + " " + text("queryHelp");
      var refusal = create("div", "query-refusal");
      refusal.appendChild(create("b", "", text("queryRejected")));
      refusal.appendChild(create("p", "", text("queryHelp")));
      result.replaceChildren(refusal);
      document.querySelectorAll("[data-snapshot-query]").forEach(function (button) {
        button.classList.remove("active");
      });
      return;
    }

    input.value = queryDefinitions[resolvedKey];
    document.querySelectorAll("[data-snapshot-query]").forEach(function (button) {
      button.classList.toggle("active", button.dataset.snapshotQuery === resolvedKey);
    });
    status.classList.remove("error");

    var rowCount = resolvedKey === "sources"
      ? data.sources.length
      : resolvedKey === "eventcodes"
        ? data.eventCodes.length
        : 1;
    status.textContent = text("searchReady") + " · " + rowCount + " " +
      text(rowCount === 1 ? "row" : "rows") +
      " · " + localized(data.provenance.snapshot.source);

    if (resolvedKey === "sources") {
      renderSourceResult(result);
    } else if (resolvedKey === "eventcodes") {
      renderEventCodeResult(result);
    } else {
      renderSavedSearchResult(result);
    }
  }

  function resultHeading(label, total, unit) {
    var header = create("header", "result-heading");
    header.appendChild(create("span", "", label));
    header.appendChild(create("b", "", formatNumber(total) + " " + (unit || text("events"))));
    return header;
  }

  function renderSourceResult(container) {
    var maximum = Math.max.apply(Math, data.sources.map(function (item) {
      return item.count;
    }));
    var bars = create("div", "result-bars");
    data.sources.forEach(function (source) {
      var row = create("div", "result-bar-row");
      var label = create("div", "result-bar-label");
      label.appendChild(create("b", "", source.channel));
      label.appendChild(create("small", "", source.index + " · " + source.sourcetype));
      row.appendChild(label);
      row.appendChild(createBarSvg(
        source.count,
        maximum,
        source.channel + ": " + source.count
      ));
      row.appendChild(create("strong", "", formatNumber(source.count)));
      bars.appendChild(row);
    });
    container.replaceChildren(
      resultHeading(text("presetSources"), data.provenance.snapshot.totalEvents),
      bars
    );
  }

  function renderEventCodeResult(container) {
    var maximum = Math.max.apply(Math, data.eventCodes.map(function (item) {
      return item.count;
    }));
    var bars = create("div", "result-bars");
    data.eventCodes.forEach(function (eventCode) {
      var row = create("div", "result-bar-row");
      var label = create("div", "result-bar-label");
      label.appendChild(create("b", "", "EventCode " + eventCode.code));
      label.appendChild(create("small", "", localized(eventCode)));
      row.appendChild(label);
      row.appendChild(createBarSvg(
        eventCode.count,
        maximum,
        "EventCode " + eventCode.code + ": " + eventCode.count
      ));
      row.appendChild(create("strong", "", formatNumber(eventCode.count)));
      bars.appendChild(row);
    });
    container.replaceChildren(
      resultHeading("Sysmon EventCode", data.provenance.snapshot.sysmonEvents),
      bars
    );
  }

  function renderSavedSearchResult(container) {
    var metric = create("div", "saved-search-result");
    metric.appendChild(create("strong", "", formatNumber(data.detections.length)));
    metric.appendChild(create("span", "", text("configuredDefinitions")));
    metric.appendChild(create("code", "", "disabled = 0"));
    container.replaceChildren(
      resultHeading(text("presetSavedSearches"), data.detections.length, text("definitions")),
      metric
    );
  }

  function renderIndexTable() {
    var rows = data.indexes.map(function (index) {
      var row = create("tr");
      row.appendChild(create("td", "index-name", index.name));
      row.appendChild(create("td", "", localized(index.role)));
      row.appendChild(create("td", "", formatNumber(index.lifetime)));
      row.appendChild(create("td", "", formatNumber(index.snapshot)));
      row.appendChild(create("td", "", formatNumber(index.maxMb) + " MB"));
      row.appendChild(create("td", "", index.retentionDays + (currentLanguage === "fr" ? " j" : " d")));
      var stateTd = create("td");
      var stateClass = index.state === "searchable" ? "searchable" : "inactive";
      var state = create("span", "index-state " + stateClass);
      state.appendChild(create("i"));
      state.appendChild(document.createTextNode(
        index.state === "searchable" ? text("searchable") : text("configuredInactive")
      ));
      stateTd.appendChild(state);
      row.appendChild(stateTd);
      return row;
    });
    var body = document.getElementById("index-table");
    body.replaceChildren.apply(body, rows);
  }

  function caseAndDetection(caseKey) {
    var caseItem = data.cases.find(function (item) {
      return item.key === caseKey;
    });
    return {
      caseItem: caseItem,
      detection: data.detections.find(function (item) {
        return item.id === caseItem.detectionId;
      })
    };
  }

  function renderCases() {
    renderCaseTabs();
    renderCase(activeCaseKey);
  }

  function renderCaseTabs() {
    var tabs = data.cases.map(function (caseItem) {
      var pair = caseAndDetection(caseItem.key);
      var button = create("button", "case-tab" + (caseItem.key === activeCaseKey ? " active" : ""));
      button.type = "button";
      button.role = "tab";
      button.setAttribute("aria-selected", caseItem.key === activeCaseKey ? "true" : "false");
      button.dataset.caseKey = caseItem.key;
      button.appendChild(create("i"));
      var label = create("span");
      label.appendChild(create("strong", "", localized(pair.detection.title)));
      label.appendChild(create("small", "", pair.detection.techniques.join(" · ")));
      button.appendChild(label);
      button.appendChild(create("b", "", pair.detection.risk));
      button.addEventListener("click", function () {
        activeCaseKey = caseItem.key;
        renderCases();
      });
      button.addEventListener("keydown", handleCaseTabKeydown);
      return button;
    });
    var container = document.getElementById("case-tabs");
    container.replaceChildren.apply(container, tabs);
  }

  function handleCaseTabKeydown(event) {
    var tabs = Array.from(document.querySelectorAll(".case-tab"));
    var index = tabs.indexOf(event.currentTarget);
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp" &&
        event.key !== "ArrowRight" && event.key !== "ArrowLeft") {
      return;
    }
    event.preventDefault();
    var forward = event.key === "ArrowDown" || event.key === "ArrowRight";
    var nextIndex = (index + (forward ? 1 : -1) + tabs.length) % tabs.length;
    tabs[nextIndex].focus();
    tabs[nextIndex].click();
  }

  function renderCase(caseKey) {
    var pair = caseAndDetection(caseKey);
    var caseItem = pair.caseItem;
    var detection = pair.detection;
    document.getElementById("case-tactic").textContent = tacticLabel(detection.tactic);
    document.getElementById("case-title").textContent = localized(detection.title);
    document.getElementById("case-id").textContent = detection.id;
    document.getElementById("case-hypothesis").textContent = localized(caseItem.hypothesis);
    document.getElementById("case-tuning").textContent = localized(caseItem.tuning);
    document.getElementById("case-file").textContent = detection.file;
    document.getElementById("case-spl").textContent = detection.spl;
    document.getElementById("case-schedule").textContent =
      detection.schedule.cron + " · " + detection.schedule.earliest + " → " + detection.schedule.latest;
    document.getElementById("case-response").textContent = localized(caseItem.response);

    var badges = [
      create("span", "case-badge validated", text("production").toUpperCase()),
      create("span", "case-badge risk", "RISK " + detection.risk),
      create("span", "case-badge", severityLabel(detection.severity).toUpperCase()),
      create("span", "case-badge", detection.techniques.join(" · "))
    ];
    document.getElementById("case-badges").replaceChildren.apply(
      document.getElementById("case-badges"),
      badges
    );

    var fields = caseItem.fields.map(function (field) {
      var row = create("div");
      row.appendChild(create("dt", "", field[0]));
      row.appendChild(create("dd", "", field[1]));
      return row;
    });
    document.getElementById("case-fields").replaceChildren.apply(
      document.getElementById("case-fields"),
      fields
    );

    var image = document.getElementById("case-evidence-image");
    image.src = caseItem.evidence;
    image.alt = localized(caseItem.evidenceAlt);
    document.getElementById("case-evidence-caption").textContent = localized(caseItem.evidenceAlt);
    document.getElementById("case-evidence").dataset.image = caseItem.evidence;
    document.getElementById("case-evidence").dataset.title = localized(detection.title);
    document.getElementById("case-evidence").dataset.caption = localized(caseItem.evidenceAlt);
  }

  function renderEvidenceGallery() {
    var cards = data.evidence.map(function (evidence) {
      var button = create("button", "evidence-card");
      button.type = "button";
      button.dataset.image = evidence.image;
      button.dataset.title = localized(evidence.title);
      button.dataset.caption = localized(evidence.caption);
      var image = create("img");
      image.src = evidence.image;
      image.alt = localized(evidence.title);
      image.loading = "lazy";
      image.decoding = "async";
      var content = create("span");
      content.appendChild(create("b", "", localized(evidence.title)));
      content.appendChild(create("small", "", localized(evidence.caption)));
      content.appendChild(create("code", "", evidence.claim));
      button.append(image, content);
      button.addEventListener("click", function () {
        openEvidence(button.dataset.image, button.dataset.title, button.dataset.caption);
      });
      return button;
    });
    var container = document.getElementById("evidence-gallery");
    container.replaceChildren.apply(container, cards);
  }

  function renderGaps() {
    var rows = data.gaps.map(function (gap) {
      var row = create("div", "gap-row");
      row.appendChild(create("code", "", gap.technique));
      row.appendChild(create("p", "", localized(gap)));
      row.appendChild(create("span", "", localized(gap.dependency)));
      return row;
    });
    var container = document.getElementById("gap-ledger");
    container.replaceChildren.apply(container, rows);
  }

  function openEvidence(path, title, caption) {
    var modal = document.getElementById("evidence-modal");
    var image = document.getElementById("modal-image");
    image.src = path;
    image.alt = title || text("evidenceModalAlt");
    document.getElementById("modal-title").textContent = title || text("evidenceTitle");
    document.getElementById("modal-caption").textContent = caption || "";
    if (typeof modal.showModal === "function") {
      modal.showModal();
    } else {
      modal.setAttribute("open", "");
    }
  }

  function closeEvidence() {
    var modal = document.getElementById("evidence-modal");
    if (typeof modal.close === "function") {
      modal.close();
    } else {
      modal.removeAttribute("open");
    }
  }

  function showToast(message) {
    var toast = document.getElementById("toast");
    window.clearTimeout(toastTimer);
    toast.textContent = message;
    toast.classList.add("visible");
    toastTimer = window.setTimeout(function () {
      toast.classList.remove("visible");
    }, 2600);
  }

  function copySpl() {
    var value = document.getElementById("case-spl").textContent;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(value).then(function () {
        showToast(text("copied"));
      }).catch(function () {
        fallbackCopy(value);
      });
      return;
    }
    fallbackCopy(value);
  }

  function fallbackCopy(value) {
    var area = create("textarea", "sr-only");
    area.value = value;
    area.setAttribute("readonly", "");
    document.body.appendChild(area);
    area.select();
    try {
      var copied = document.execCommand("copy");
      showToast(copied ? text("copied") : text("copyFailed"));
    } catch (error) {
      showToast(text("copyFailed"));
    }
    area.remove();
  }

  function activateView(view, updateHash, focusPanel) {
    if (["posture", "platform", "investigations", "assurance"].indexOf(view) < 0) {
      view = "posture";
    }
    activeView = view;
    document.querySelectorAll("[data-view-panel]").forEach(function (panel) {
      var isActive = panel.dataset.viewPanel === view;
      panel.hidden = !isActive;
      panel.classList.toggle("active", isActive);
    });
    document.querySelectorAll("[data-view]").forEach(function (button) {
      var isActive = button.dataset.view === view;
      button.classList.toggle("active", isActive);
      button.setAttribute("aria-selected", isActive ? "true" : "false");
      button.tabIndex = isActive ? 0 : -1;
    });
    if (updateHash && window.location.hash !== "#" + view) {
      window.history.pushState(null, "", "#" + view);
    }
    if (focusPanel) {
      document.getElementById(view).scrollIntoView({ block: "start" });
    }
  }

  function handleViewKeydown(event) {
    var tabs = Array.from(document.querySelectorAll("[data-view]"));
    var currentIndex = tabs.indexOf(event.currentTarget);
    var nextIndex;
    if (event.key === "ArrowRight") {
      nextIndex = (currentIndex + 1) % tabs.length;
    } else if (event.key === "ArrowLeft") {
      nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = tabs.length - 1;
    } else {
      return;
    }
    event.preventDefault();
    tabs[nextIndex].focus();
    activateView(tabs[nextIndex].dataset.view, true, false);
  }

  function setLanguage(language) {
    currentLanguage = language === "en" ? "en" : "fr";
    document.documentElement.lang = currentLanguage;
    storeLanguage(currentLanguage);
    document.querySelectorAll("[data-i18n]").forEach(function (element) {
      element.textContent = text(element.dataset.i18n);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(function (element) {
      element.placeholder = text(element.dataset.i18nPlaceholder);
    });
    document.querySelectorAll("[data-i18n-aria-label]").forEach(function (element) {
      element.setAttribute("aria-label", text(element.dataset.i18nAriaLabel));
    });
    document.querySelectorAll("[data-language]").forEach(function (button) {
      var isActive = button.dataset.language === currentLanguage;
      button.classList.toggle("active", isActive);
      button.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
    document.title = currentLanguage === "fr"
      ? "Laboratoire Splunk · Plateforme & ingénierie de détection · A.S"
      : "Splunk Platform & Detection Engineering Lab · A.S";
    document.querySelector('meta[name="description"]').content = currentLanguage === "fr"
      ? "Portfolio Splunk orienté administration de plateforme et ingénierie de détection : données publiques assainies, recherches planifiées, ATT&CK, SPL, validation et preuves."
      : "Splunk platform administration and detection engineering portfolio: sanitized public data, scheduled searches, ATT&CK, SPL, validation, and evidence.";
    populateTacticSelect();
    renderPosture();
    renderPlatformFacts();
    renderSnapshotQuery(findQueryKey(document.getElementById("snapshot-query").value) || "sources");
    renderIndexTable();
    renderCases();
    renderEvidenceGallery();
    renderGaps();
  }

  function bindEvents() {
    document.querySelectorAll("[data-language]").forEach(function (button) {
      button.addEventListener("click", function () {
        setLanguage(button.dataset.language);
      });
    });

    document.querySelectorAll("[data-view]").forEach(function (button) {
      button.id = "tab-" + button.dataset.view;
      button.addEventListener("click", function () {
        activateView(button.dataset.view, true, false);
      });
      button.addEventListener("keydown", handleViewKeydown);
    });

    document.querySelectorAll("[data-view-link]").forEach(function (link) {
      link.addEventListener("click", function (event) {
        event.preventDefault();
        activateView(link.dataset.viewLink, true, true);
      });
    });

    window.addEventListener("popstate", function () {
      activateView(getInitialView(), false, false);
    });

    ["analytic-filter", "status-filter", "tactic-filter", "severity-filter", "cadence-filter"].forEach(
      function (id) {
        var element = document.getElementById(id);
        element.addEventListener(element.tagName === "INPUT" ? "input" : "change", renderPosture);
      }
    );

    document.getElementById("reset-filters").addEventListener("click", function () {
      document.getElementById("analytic-filter").value = "";
      document.getElementById("status-filter").value = "all";
      document.getElementById("tactic-filter").value = "all";
      document.getElementById("severity-filter").value = "all";
      document.getElementById("cadence-filter").value = "all";
      renderPosture();
    });

    document.querySelectorAll("[data-snapshot-query]").forEach(function (button) {
      button.addEventListener("click", function () {
        renderSnapshotQuery(button.dataset.snapshotQuery);
      });
    });
    document.getElementById("run-snapshot-query").addEventListener("click", function () {
      renderSnapshotQuery(null);
    });
    document.getElementById("snapshot-query").addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        renderSnapshotQuery(null);
      }
    });

    document.getElementById("copy-spl").addEventListener("click", copySpl);
    document.getElementById("case-evidence").addEventListener("click", function (event) {
      var button = event.currentTarget;
      openEvidence(button.dataset.image, button.dataset.title, button.dataset.caption);
    });
    document.getElementById("modal-close").addEventListener("click", closeEvidence);
    document.getElementById("evidence-modal").addEventListener("click", function (event) {
      if (event.target === event.currentTarget) {
        closeEvidence();
      }
    });
  }

  bindEvents();
  setLanguage(currentLanguage);
  activateView(activeView, false, false);
}());
