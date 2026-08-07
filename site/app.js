(function () {
  "use strict";

  var data = window.LAB_DATA;
  if (!data || !Array.isArray(data.detections)) {
    return;
  }

  var translations = {
    fr: {
      skip: "Aller au contenu",
      ariaWordmark: "Splunk Engineering Lab",
      ariaLanguage: "Langue",
      ariaSigned: "Signé A.S",
      ariaMainNavigation: "Navigation principale",
      ariaDataContext: "Contexte des données",
      ariaPostureMetrics: "Indicateurs de posture",
      ariaPlatformMetrics: "Indicateurs de plateforme",
      ariaSearchPresets: "Recherches disponibles",
      ariaFooterLinks: "Liens de pied de page",
      ariaClose: "Fermer",
      publicWorkspace: "ADMINISTRATION SPLUNK · INGÉNIERIE DE DÉTECTION",
      snapshotReady: "Upgrade 10.2.1 qualifié",
      repository: "Dépôt",
      appSubtitle: "PLATEFORME · DÉTECTION · PREUVES",
      navPosture: "Posture de détection",
      navPlatform: "Plateforme & données",
      navInvestigations: "Investigations",
      navAssurance: "Administration & preuves",
      snapshotMode: "SNAPSHOT PUBLIC",
      snapshotDescription: "Détection figée le 6 août · qualifications admin du 7 août · aucune connexion à la VM",
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
      esDestinations: "Pipeline RBA compatible Splunk ES",
      configuredNotActive: "Sorties matérialisées, corrélées et versionnées sur la campagne",
      inactive: "VÉRIFIÉ",
      indexedEvents: "modificateurs indexés",
      indexedEventsPlural: "versions du finding",
      currentFinding: "file dédupliquée",
      fiveTechniques: "cinq techniques corrélées",
      esDisclaimer: "RBA ES-compatible vérifié dans les indexes risk/notable ; aucune instance ES native n’est prétendue active.",
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
      platformIntro: "Le snapshot de détection reste figé ; les qualifications d’administration du 7 août sont reliées à leurs preuves publiques.",
      instance: "RUNTIME FINAL",
      license: "APPLICATION",
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
      indexInventory: "Indexes du snapshot de détection",
      indexInventoryDetail: "Inventaire figé du 6 août · capacité et rétention observées",
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
      kvStoreControl: "État après rotation TLS",
      managementApiControl: "Chaîne et nom DNS vérifiés",
      rbacControl: "Tests positifs et négatifs",
      ariaRbaOverview: "Synthèse de corrélation RBA",
      ariaRiskContributions: "Contributions au risque",
      rbaOverviewTitle: "Une attaque multi-technique, un finding exploitable",
      rbaOverviewDetail: "Les signaux unitaires conservent leur contexte ; la corrélation agrège la diversité ATT&CK et déduplique la file analyste.",
      normalizedSignals: "signaux normalisés",
      entityCentered: "centré entité",
      distinctTechniques: "techniques distinctes",
      deduplicatedQueue: "file dédupliquée",
      dispatchPass: "dispatchs sans erreur",
      analystWorkflow: "ANALYST WORKFLOW",
      fieldEvidence: "SURFACES AGRÉGÉES",
      investigationTitle: "Atelier d’investigation",
      investigationIntro: "Trois cas relient l’hypothèse, les champs attendus, le SPL déployé, le tuning et l’action analyste. Les visuels associés restent strictement agrégés.",
      method: "MÉTHODE",
      methodFlow: "Scénario contrôlé → Sysmon → SPL",
      evidence: "VISUELS",
      committed: "Agrégés / revus",
      caseQueue: "FILE D’INVESTIGATION",
      sampleNotice: "Schémas de triage",
      detectionHypothesis: "HYPOTHÈSE DE DÉTECTION",
      precisionControl: "CONTRÔLE DE PRÉCISION",
      deployedSpl: "SPL DÉPLOYÉ",
      copy: "Copier",
      preservedFields: "CHAMPS DE TRIAGE",
      sanitizedSample: "VALEURS ATTENDUES",
      analystAction: "ACTION ANALYSTE",
      openEvidence: "OUVRIR LA SURFACE AGRÉGÉE",
      emulate: "Émuler",
      emulateDetail: "Atomic ou scénario manuel borné.",
      collect: "Collecter",
      collectDetail: "Conserver les champs nécessaires au triage.",
      match: "Détecter",
      matchDetail: "Appliquer le SPL et les exclusions explicites.",
      validate: "Valider",
      validateDetail: "Contrôler les résultats agrégés et consigner la décision.",
      respond: "Répondre",
      respondDetail: "Passer du signal au contexte et à la décision.",
      engineeringAssurance: "ENGINEERING ASSURANCE",
      traceability: "TRAÇABILITÉ",
      assuranceTitle: "Preuves & maîtrise de la livraison",
      assuranceIntro: "Chaque affirmation publique renvoie à une configuration, une spécification ou un artefact agrégé ; les limites restent visibles.",
      deliveryModel: "MODÈLE",
      publicSurface: "SURFACE PUBLIQUE",
      staticReadOnly: "Statique / lecture seule",
      adminQualification: "Qualifications d’administration vérifiables",
      adminQualificationDetail: "Neuf domaines, neuf artefacts publics assainis, aucune dépendance à la VM",
      qualificationClosed: "QUALIFICATION CLOSE",
      publicEvidence: "PREUVE PUBLIQUE",
      openPublicEvidence: "Ouvrir la preuve publique",
      claimLedger: "Registre des affirmations",
      claimLedgerDetail: "De la métrique affichée à l’artefact versionné",
      traceable: "TRAÇABLE",
      publicClaim: "AFFIRMATION PUBLIQUE",
      sourceArtifact: "ARTEFACT SOURCE",
      verification: "VÉRIFICATION",
      claimTelemetry: "Composition des 173 événements",
      frozenAggregate: "Agrégat figé",
      claimDetections: "Recherches planifiées et cadences",
      deployedContent: "Contenu déployé",
      claimCoverage: "Techniques et statuts ATT&CK",
      contentPosture: "Posture du contenu",
      claimEvidence: "Résultats et constats de validation",
      controlledLab: "Snapshot historique",
      claimRetention: "Capacité et rétention",
      localInstance: "Instance locale",
      promotionQueue: "File de promotion",
      promotionQueueDetail: "Une preuve mesurée avant toute promotion de statut",
      promotionFinding: "CONSTAT",
      promotionFindingDetail: "Deux événements Certutil ont franchi la détection lors du replay contrôlé.",
      promotionCandidate: "CANDIDAT",
      promotionBlockerLabel: "CONTRÔLE",
      promotionBlocker: "Conserver Image, OriginalFileName, parent et ligne de commande avant revue du bruit.",
      promotionNextProof: "PROCHAINE ÉTAPE",
      promotionNextProofDetail: "Élargir le dataset bénin, mesurer le taux de faux positifs, puis décider la promotion Production.",
      validationGallery: "Galerie de validation",
      galleryDetail: "Trois captures revues, limitées aux métriques et vues agrégées",
      declaredGaps: "Roadmap d’extension",
      gapsDetail: "Chaque extension est reliée à la source de données qui la rend mesurable",
      boundary: "PÉRIMÈTRE",
      publicSurfaceSecurity: "Surface publique maîtrisée",
      securityDetail: "Propriétés vérifiables du portfolio statique",
      staticOnly: "HTML, CSS et JS statiques",
      staticOnlyDetail: "Aucun backend, formulaire ou compte utilisateur.",
      sameOrigin: "Ressources servies localement",
      sameOriginDetail: "Aucune police, bibliothèque ou télémétrie tierce.",
      cspDetail: "Scripts, styles et images limités à l’origine.",
      noSecrets: "Validation avant publication",
      noSecretsDetail: "Le contrôle CI impose une allowlist PNG et bloque preuves brutes, secrets, adresses privées, identifiants retirés et métadonnées.",
      declaredScope: "Périmètre déclaré",
      scopeDetail: "Ce qui est démontré — et ce qui ne l’est pas",
      scopeYes1: "Runtime final standalone : Splunk Enterprise 10.2.1, app 0.7.3",
      scopeYes2: "Onboarding Windows et Linux, parsing et contrôles CIM",
      scopeYes3: "Detection-as-Code, RBA ES-compatible et validation contrôlée",
      scopeYes4: "Qualification cluster séparée : RF=2/SF=2 et continuité de recherche",
      scopeNo2: "Enterprise Security natif, SOAR et Active Directory non activés dans le runtime final",
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
      atomicEvidence: "Scénario Atomic contrôlé",
      manualEvidence: "Validation manuelle contrôlée",
      implemented: "Implémentée · à promouvoir",
      minutes: "minutes",
      copied: "SPL copié dans le presse-papiers.",
      copyFailed: "Copie automatique indisponible ; sélectionnez le SPL manuellement.",
      severityCritical: "CRITIQUE",
      severityHigh: "ÉLEVÉE",
      severityMedium: "MOYENNE",
      evidenceModalAlt: "Surface Splunk agrégée en pleine résolution",
      matrixTechniques: "techniques",
      sourceLabel: "Source",
      countLabel: "Nombre",
      currentSnapshot: "snapshot public",
      noRows: "Aucun résultat dans ce périmètre."
    },
    en: {
      skip: "Skip to content",
      ariaWordmark: "Splunk Engineering Lab",
      ariaLanguage: "Language",
      ariaSigned: "Signed A.S",
      ariaMainNavigation: "Main navigation",
      ariaDataContext: "Data context",
      ariaPostureMetrics: "Posture metrics",
      ariaPlatformMetrics: "Platform metrics",
      ariaSearchPresets: "Available searches",
      ariaFooterLinks: "Footer links",
      ariaClose: "Close",
      publicWorkspace: "SPLUNK ADMINISTRATION · DETECTION ENGINEERING",
      snapshotReady: "10.2.1 upgrade qualified",
      repository: "Repository",
      appSubtitle: "PLATFORM · DETECTION · EVIDENCE",
      navPosture: "Detection posture",
      navPlatform: "Platform & data",
      navInvestigations: "Investigations",
      navAssurance: "Administration & evidence",
      snapshotMode: "PUBLIC SNAPSHOT",
      snapshotDescription: "Detection frozen August 6 · admin qualifications August 7 · no VM connection",
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
      esDestinations: "Splunk ES-compatible RBA pipeline",
      configuredNotActive: "Materialized, correlated, and versioned campaign outputs",
      inactive: "VERIFIED",
      indexedEvents: "indexed modifiers",
      indexedEventsPlural: "finding versions",
      currentFinding: "deduplicated queue",
      fiveTechniques: "five correlated techniques",
      esDisclaimer: "ES-compatible RBA is verified in the risk/notable indexes; no native ES instance is claimed as active.",
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
      platformIntro: "The detection snapshot remains frozen; the August 7 administration qualifications link to their public evidence.",
      instance: "FINAL RUNTIME",
      license: "APPLICATION",
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
      indexInventory: "Detection snapshot indexes",
      indexInventoryDetail: "Frozen August 6 inventory · observed capacity and retention",
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
      kvStoreControl: "State after TLS rotation",
      managementApiControl: "Chain and DNS name verified",
      rbacControl: "Positive and negative tests",
      ariaRbaOverview: "RBA correlation overview",
      ariaRiskContributions: "Risk contributions",
      rbaOverviewTitle: "One multi-technique attack, one actionable finding",
      rbaOverviewDetail: "Individual signals retain context; correlation aggregates ATT&CK diversity and deduplicates the analyst queue.",
      normalizedSignals: "normalized signals",
      entityCentered: "entity-centered",
      distinctTechniques: "distinct techniques",
      deduplicatedQueue: "deduplicated queue",
      dispatchPass: "error-free dispatches",
      analystWorkflow: "ANALYST WORKFLOW",
      fieldEvidence: "AGGREGATE SURFACES",
      investigationTitle: "Investigation Workbench",
      investigationIntro: "Three cases connect the hypothesis, expected fields, deployed SPL, tuning, and analyst action. Their associated visuals remain strictly aggregate.",
      method: "METHOD",
      methodFlow: "Controlled scenario → Sysmon → SPL",
      evidence: "VISUALS",
      committed: "Aggregate / reviewed",
      caseQueue: "INVESTIGATION QUEUE",
      sampleNotice: "Triage schemas",
      detectionHypothesis: "DETECTION HYPOTHESIS",
      precisionControl: "PRECISION CONTROL",
      deployedSpl: "DEPLOYED SPL",
      copy: "Copy",
      preservedFields: "TRIAGE FIELDS",
      sanitizedSample: "EXPECTED VALUES",
      analystAction: "ANALYST ACTION",
      openEvidence: "OPEN AGGREGATE SURFACE",
      emulate: "Emulate",
      emulateDetail: "Bounded Atomic or manual scenario.",
      collect: "Collect",
      collectDetail: "Preserve fields required for triage.",
      match: "Match",
      matchDetail: "Apply SPL and explicit exclusions.",
      validate: "Validate",
      validateDetail: "Check aggregate results and record the decision.",
      respond: "Respond",
      respondDetail: "Move from signal to context and decision.",
      engineeringAssurance: "ENGINEERING ASSURANCE",
      traceability: "TRACEABILITY",
      assuranceTitle: "Evidence & Delivery Assurance",
      assuranceIntro: "Every public claim points to configuration, specification, or an aggregate artifact; limits remain visible.",
      deliveryModel: "MODEL",
      publicSurface: "PUBLIC SURFACE",
      staticReadOnly: "Static / read-only",
      adminQualification: "Verifiable administration qualifications",
      adminQualificationDetail: "Nine domains, nine sanitized public artifacts, no VM dependency",
      qualificationClosed: "QUALIFICATION CLOSE",
      publicEvidence: "PUBLIC EVIDENCE",
      openPublicEvidence: "Open public evidence",
      claimLedger: "Claim ledger",
      claimLedgerDetail: "From displayed metric to versioned artifact",
      traceable: "TRACEABLE",
      publicClaim: "PUBLIC CLAIM",
      sourceArtifact: "SOURCE ARTIFACT",
      verification: "VERIFICATION",
      claimTelemetry: "Composition of 173 events",
      frozenAggregate: "Frozen aggregate",
      claimDetections: "Scheduled searches and cadences",
      deployedContent: "Deployed content",
      claimCoverage: "ATT&CK techniques and status",
      contentPosture: "Content posture",
      claimEvidence: "Validation results and findings",
      controlledLab: "Historical snapshot",
      claimRetention: "Capacity and retention",
      localInstance: "Local instance",
      promotionQueue: "Promotion queue",
      promotionQueueDetail: "Measured evidence before status promotion",
      promotionFinding: "FINDING",
      promotionFindingDetail: "Two Certutil events crossed the detection during the controlled replay.",
      promotionCandidate: "CANDIDATE",
      promotionBlockerLabel: "CONTROL",
      promotionBlocker: "Preserve Image, OriginalFileName, parent, and command line before noise review.",
      promotionNextProof: "NEXT STEP",
      promotionNextProofDetail: "Expand the benign dataset, measure false-positive rate, then decide Production promotion.",
      validationGallery: "Validation gallery",
      galleryDetail: "Three reviewed screenshots limited to aggregate metrics and views",
      declaredGaps: "Extension roadmap",
      gapsDetail: "Each extension is tied to the data source that makes it measurable",
      boundary: "BOUNDARY",
      publicSurfaceSecurity: "Controlled public surface",
      securityDetail: "Verifiable properties of the static portfolio",
      staticOnly: "Static HTML, CSS, and JS",
      staticOnlyDetail: "No backend, form, or user account.",
      sameOrigin: "Same-origin assets",
      sameOriginDetail: "No third-party font, library, or telemetry.",
      cspDetail: "Scripts, styles, and images are origin-restricted.",
      noSecrets: "Pre-publication validation",
      noSecretsDetail: "CI enforces a PNG allowlist and blocks raw evidence, secrets, private addresses, retired identifiers, and metadata.",
      declaredScope: "Declared scope",
      scopeDetail: "What is demonstrated — and what is not",
      scopeYes1: "Final standalone runtime: Splunk Enterprise 10.2.1, app 0.7.3",
      scopeYes2: "Windows and Linux onboarding, parsing, and CIM controls",
      scopeYes3: "Detection-as-Code, ES-compatible RBA, and controlled validation",
      scopeYes4: "Separate cluster qualification: RF=2/SF=2 and search continuity",
      scopeNo2: "Native Enterprise Security, SOAR, and Active Directory are not active in the final runtime",
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
      atomicEvidence: "Controlled Atomic scenario",
      manualEvidence: "Controlled manual validation",
      implemented: "Implemented · awaiting promotion",
      minutes: "minutes",
      copied: "SPL copied to the clipboard.",
      copyFailed: "Automatic copy is unavailable; select the SPL manually.",
      severityCritical: "CRITICAL",
      severityHigh: "HIGH",
      severityMedium: "MEDIUM",
      evidenceModalAlt: "Full-resolution aggregate Splunk surface",
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
        note: "sysmon + windows + risk + notable"
      },
      {
        label: text("snapshotEvents"),
        value: data.provenance.snapshot.totalEvents,
        note: text("currentSnapshot")
      },
      {
        label: text("sourcetypes"),
        value: data.sources.length,
        note: data.sources.map(function (source) {
          return source.count;
        }).join(" / ")
      },
      {
        label: text("activeIndexes"),
        value: data.indexes.filter(function (index) {
          return index.state === "searchable";
        }).length,
        note: "risk " + data.rba.riskModifiers + " · notable " + data.rba.findingVersions
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
    var cards = data.evidence.map(function (evidence, evidenceIndex) {
      var button = create("button", "evidence-card");
      if (evidenceIndex < 4) {
        button.classList.add("dashboard-evidence");
      }
      button.type = "button";
      button.dataset.image = evidence.image;
      button.dataset.title = localized(evidence.title);
      button.dataset.caption = localized(evidence.caption);
      var image = create("img");
      image.src = evidence.image;
      image.alt = localized(evidence.title);
      image.loading = evidenceIndex < 4 ? "eager" : "lazy";
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

  function publicArtifactUrl(path) {
    var isPublicJson = /^artifacts\/public\/[a-z0-9][a-z0-9._-]*\.json$/.test(path);
    if (!isPublicJson) {
      return data.meta.repository;
    }
    var encodedPath = path.split("/").map(function (segment) {
      return encodeURIComponent(segment);
    }).join("/");
    return data.meta.repository + "/blob/main/" + encodedPath;
  }

  function renderAdminEvidence() {
    var proofs = Array.isArray(data.adminEvidence) ? data.adminEvidence : [];
    var cards = proofs.map(function (proof) {
      var card = create("a", "admin-evidence-card");
      card.href = publicArtifactUrl(proof.artifact);
      card.target = "_blank";
      card.rel = "noopener noreferrer";
      card.dataset.proof = proof.id;
      card.setAttribute(
        "aria-label",
        text("openPublicEvidence") + " : " + localized(proof.title)
      );

      var header = create("header");
      header.appendChild(create("span", "admin-evidence-domain", localized(proof.category)));
      var state = create("span", "admin-evidence-state");
      state.appendChild(create("i"));
      state.appendChild(document.createTextNode(text("publicEvidence")));
      header.appendChild(state);

      var metric = create("div", "admin-evidence-metric");
      metric.appendChild(create("strong", "", proof.metric));
      metric.appendChild(create("small", "", localized(proof.metricLabel)));

      card.appendChild(header);
      card.appendChild(metric);
      card.appendChild(create("b", "admin-evidence-title", localized(proof.title)));
      card.appendChild(create("code", "admin-evidence-reference", localized(proof.reference)));
      card.appendChild(create("p", "admin-evidence-detail", localized(proof.detail)));

      var footer = create("footer");
      footer.appendChild(create("code", "", proof.artifact.replace("artifacts/public/", "")));
      footer.appendChild(create("span", "", text("openPublicEvidence") + " ↗"));
      card.appendChild(footer);
      return card;
    });
    var container = document.getElementById("admin-evidence-grid");
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
      ? "Splunk Administration & Detection Engineering · A.S"
      : "Splunk Administration & Detection Engineering · A.S";
    document.querySelector('meta[name="description"]').content = currentLanguage === "fr"
      ? "Portfolio Splunk Administration et Detection Engineering : upgrade avec rollback, TLS, RBAC, MCO, CIM, RBA et preuves publiques assainies."
      : "Splunk Administration and Detection Engineering portfolio: upgrade with rollback, TLS, RBAC, operations, CIM, RBA, and sanitized public evidence.";
    populateTacticSelect();
    renderPosture();
    renderPlatformFacts();
    renderSnapshotQuery(findQueryKey(document.getElementById("snapshot-query").value) || "sources");
    renderIndexTable();
    renderCases();
    renderAdminEvidence();
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
