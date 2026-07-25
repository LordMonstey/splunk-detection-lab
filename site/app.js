(function () {
  "use strict";

  var data = window.LAB_DATA;
  var currentLanguage = readStoredLanguage();
  var activeFilter = "all";
  var activeCase = "lsass";
  var numberFormatters = {
    fr: new Intl.NumberFormat("fr-FR"),
    en: new Intl.NumberFormat("en-US")
  };

  var english = {
    skip: "Skip to content",
    apps: "Apps",
    messages: "Messages",
    settings: "Settings",
    activity: "Activity",
    help: "Help",
    globalSearch: "Global search",
    find: "Find",
    menu: "Menu",
    navOverview: "Overview",
    navAdmin: "Administration",
    navContent: "Detection content",
    navInvestigate: "Investigation",
    navEvidence: "Evidence",
    snapshotMode: "PUBLIC SNAPSHOT MODE",
    snapshotDetail: "Fixed sanitized data · VM not required · Captured July 25, 2026",
    sourceRepository: "Source repository",
    appName: "Splunk Engineering Lab",
    overview: "Overview",
    overviewSubtitle: "Platform operations, telemetry quality, and detection lifecycle in one operator view.",
    nativeDashboard: "Native dashboard",
    viewSource: "View source",
    newSearch: "New Search",
    snapshotDataset: "Dataset: verified snapshot",
    allTime: "All time",
    search: "Search",
    quickSearches: "Quick searches:",
    searchComplete: "Search completed",
    eventsInWindow: "events in the retention window",
    seconds: "seconds",
    lifetimeEvents: "Lifetime events indexed",
    deployedSearches: "Scheduled searches",
    productionRules: "Production rules",
    searchableEvents: "Searchable telemetry",
    committedEvidence: "Committed evidence",
    retentionWindow: "Current window",
    eventsBySource: "Events by index and sourcetype",
    searchableSnapshot: "Searchable snapshot",
    verified25: "Verified 2026-07-25",
    sysmonMix: "Sysmon telemetry mix",
    eventCodeDistribution: "EventCode distribution",
    searchableEventsLabel: "Searchable events",
    deliveryPipeline: "Telemetry delivery pipeline",
    endToEnd: "End-to-end control",
    windowsEndpoint: "Windows endpoint",
    knowledgeLayer: "Knowledge layer",
    detectionContent: "Detection content",
    platformAdmin: "SPLUNK ADMINISTRATION",
    platformHeading: "The platform is a security dependency.",
    platformIntro: "Ingestion, retention, licensing, and effective configuration are exposed as engineering controls—not installation details.",
    instance: "Instance",
    version: "Version",
    os: "System",
    roles: "Roles",
    indexEngineering: "Index engineering",
    lifetime: "LIFETIME EVENTS",
    retention: "RETENTION",
    state: "STATE",
    effectiveConfig: "Effective configuration",
    storageRetention: "storage + retention",
    parsingFields: "parsing + fields",
    nativePresentation: "native presentation",
    recoveryTitle: "Real incident: search service recovery",
    recoverySubtitle: "Telemetry was present, but every search failed.",
    symptom: "SYMPTOM",
    searchUnavailable: "Search unavailable",
    rootCause: "ROOT CAUSE",
    expiredTrial: "Expired Trial license",
    result: "RESULT",
    eventsRestored: "473 events restored",
    observe: "Observe",
    observeDetail: "REST metadata shows 19,946 events while search jobs return a fatal error.",
    isolate: "Isolate",
    isolateDetail: "The license message separates a control-plane failure from index corruption.",
    protect: "Protect",
    protectDetail: "Archive the app and effective configuration before changing state.",
    recover: "Recover",
    recoverDetail: "Activate Splunk Free for the standalone lab and perform a controlled restart.",
    validate: "Validate",
    validateDetail: "Search green, btool clean, dashboard loaded. Remote login remains disabled.",
    contentHeading: "Scheduled searches with a promotion contract.",
    contentIntro: "Every row is a deployed object with a hypothesis, data dependency, SPL, tuning, validation, risk, and response.",
    deployed: "DEPLOYED",
    filterPlaceholder: "Filter by title, tactic, or technique…",
    all: "All",
    export: "Export ▾",
    results: "results",
    tableTip: "Select a validated rule to open its investigation.",
    status: "STATUS",
    detection: "DETECTION",
    tactic: "TACTIC",
    schedule: "SCHEDULE",
    validation: "VALIDATION",
    empty: "No detection matches this filter.",
    releaseGate: "CONTENT RELEASE GATE",
    releaseIntro: "A rule changes status only when every control has evidence.",
    gate1: "Hypothesis + data source",
    gate2: "SPL + macro abstraction",
    gate3: "Atomic / manual execution",
    gate4: "False-positive tuning",
    gate5: "Evidence + runbook",
    gate6: "Coverage promotion",
    investigation: "INVESTIGATION",
    investigationHeading: "From behavior to analyst evidence.",
    investigationIntro: "Three validated scenarios connect emulation, source fields, SPL logic, precision controls, and response action.",
    caseLsass: "LSASS Access",
    technique: "Technique",
    dataSource: "Data source",
    scheduleLabel: "Schedule",
    precisionControl: "PRECISION CONTROL",
    eventFields: "Retained analyst fields",
    copySpl: "Copy SPL",
    committedProof: "COMMITTED EVIDENCE",
    openFullEvidence: "Open the full-resolution Splunk capture",
    traceability: "EVIDENCE & TRACEABILITY",
    evidenceHeading: "Every metric resolves to an artifact.",
    evidenceIntro: "The site is the presentation layer. Versioned configuration, detections, and lab captures remain the source of truth.",
    nativeCaption: "Simple XML and CSS deployed in Splunk 10.2.1 · data/ui/views/splunk_engineering_command_center.xml",
    openScreenshot: "Open screenshot",
    fullResolution: "Full resolution ↗",
    repositoryAnatomy: "Repository anatomy",
    treeConfig: "deployable application",
    treeSpecs: "content specifications",
    treeResponse: "analyst response",
    validationReport: "Validation report",
    scopeTitle: "Declared scope",
    scopeSubtitle: "What the lab proves—and what it does not claim.",
    scopeYes1: "Standalone Splunk Enterprise, local administration, and search",
    scopeYes2: "Sysmon + Windows channels through a Universal Forwarder",
    scopeYes3: "Detection-as-code and controlled validation",
    scopeNo1: "No Enterprise Security instance presented as active",
    scopeNo2: "No SOAR, indexer cluster, or deployment server",
    footerSnapshot: "Sanitized snapshot · no VM dependency · no public administrator access",
    signedBy: "Designed and maintained by",
    backTop: "Back to top ↑",
    modalCaption: "Committed validation evidence · sanitized lab context"
  };

  function readStoredLanguage() {
    try {
      return window.localStorage.getItem("splunkPortfolioLanguage") === "en" ? "en" : "fr";
    } catch (error) {
      return "fr";
    }
  }

  function storeLanguage(language) {
    try {
      window.localStorage.setItem("splunkPortfolioLanguage", language);
    } catch (error) {
      // The language still changes when storage is unavailable.
    }
  }

  function localized(value) {
    if (typeof value === "string") return value;
    return value[currentLanguage];
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function formatNumber(value) {
    return numberFormatters[currentLanguage].format(value);
  }

  function setLanguage(language) {
    currentLanguage = language === "en" ? "en" : "fr";
    document.documentElement.lang = currentLanguage;
    storeLanguage(currentLanguage);

    document.querySelectorAll("[data-i18n]").forEach(function (element) {
      if (!element.dataset.frText) element.dataset.frText = element.textContent;
      element.textContent = currentLanguage === "fr"
        ? element.dataset.frText
        : (english[element.dataset.i18n] || element.dataset.frText);
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach(function (element) {
      if (!element.dataset.frPlaceholder) element.dataset.frPlaceholder = element.placeholder;
      element.placeholder = currentLanguage === "fr"
        ? element.dataset.frPlaceholder
        : (english[element.dataset.i18nPlaceholder] || element.dataset.frPlaceholder);
    });

    document.querySelectorAll("[data-language]").forEach(function (button) {
      var selected = button.dataset.language === currentLanguage;
      button.classList.toggle("active", selected);
      button.setAttribute("aria-pressed", String(selected));
    });

    document.title = currentLanguage === "fr"
      ? "Splunk Engineering Lab · Administration & Détection"
      : "Splunk Engineering Lab · Platform & Detection";

    document.querySelector('meta[name="description"]').content = currentLanguage === "fr"
      ? "Portfolio Splunk orienté administration de plateforme et detection engineering : onboarding Windows, SPL, détection-as-code et preuves Atomic Red Team."
      : "Splunk platform administration and detection engineering portfolio: Windows onboarding, SPL, detection-as-code, and Atomic Red Team evidence.";

    renderSources();
    renderEventCodes();
    renderIndexes();
    renderDetections();
    renderCase(activeCase);
  }

  function renderSources() {
    var target = document.getElementById("source-chart");
    var maximum = Math.max.apply(null, data.sources.map(function (item) { return item.count; }));

    target.innerHTML = data.sources.map(function (item) {
      var width = Math.max(1.5, (item.count / maximum) * 100);
      return [
        '<div class="horizontal-row">',
        '  <div class="source-name"><strong>' + escapeHtml(item.index) + '</strong><span>' + escapeHtml(item.sourcetype) + "</span></div>",
        '  <div class="source-bar"><i style="width:' + width + '%"></i><b>' + formatNumber(item.count) + "</b></div>",
        "</div>"
      ].join("");
    }).join("");
  }

  function renderEventCodes() {
    var target = document.getElementById("event-chart");
    var maximum = Math.max.apply(null, data.eventCodes.map(function (item) { return item.count; }));

    target.innerHTML = data.eventCodes.map(function (item) {
      var height = Math.max(3, (item.count / maximum) * 100);
      return [
        '<div class="column">',
        '  <div class="column-value">' + formatNumber(item.count) + "</div>",
        '  <div class="column-track"><i style="height:' + height + '%"></i></div>',
        '  <strong>EID ' + escapeHtml(item.code) + "</strong>",
        "  <span>" + escapeHtml(item[currentLanguage]) + "</span>",
        "</div>"
      ].join("");
    }).join("");
  }

  function renderIndexes() {
    document.getElementById("index-table").innerHTML = data.indexes.map(function (item) {
      var state = item.name === "risk" || item.name === "notable"
        ? (currentLanguage === "fr" ? "PRÊT / VIDE" : "READY / EMPTY")
        : (currentLanguage === "fr" ? "ACTIF" : "ACTIVE");
      return [
        "<tr>",
        '  <td><span class="index-name">' + escapeHtml(item.name) + "</span></td>",
        "  <td>" + formatNumber(item.lifetime) + "</td>",
        "  <td>" + item.diskMb + "</td>",
        "  <td>" + formatNumber(item.maxMb) + "</td>",
        "  <td>" + item.retentionDays + "d</td>",
        '  <td><span class="table-state"><i></i>' + state + "</span></td>",
        "</tr>"
      ].join("");
    }).join("");
  }

  function validationText(item) {
    if (item.status === "production") {
      return currentLanguage === "fr" ? "Preuve disponible" : "Evidence available";
    }
    return currentLanguage === "fr" ? "Promotion en attente" : "Promotion pending";
  }

  function renderDetections() {
    var query = document.getElementById("detection-search").value.trim().toLocaleLowerCase(currentLanguage);
    var filtered = data.detections.filter(function (item) {
      var statusMatch = activeFilter === "all" || item.status === activeFilter;
      var searchable = [
        item.fr,
        item.en,
        item.tactic.fr,
        item.tactic.en,
        item.techniques.join(" "),
        item.file
      ].join(" ").toLocaleLowerCase(currentLanguage);
      return statusMatch && searchable.indexOf(query) !== -1;
    });

    document.getElementById("visible-count").textContent = formatNumber(filtered.length);
    document.getElementById("empty-state").hidden = filtered.length !== 0;

    document.getElementById("detection-table").innerHTML = filtered.map(function (item) {
      var statusLabel = item.status === "production" ? "PRODUCTION" : "TESTING";
      var titleControl = item.case
        ? '<button class="rule-link" type="button" data-open-case="' + item.case + '">' + escapeHtml(item[currentLanguage]) + "</button>"
        : '<a class="rule-link" href="https://github.com/LordMonstey/splunk-detection-lab/blob/main/detections/' + encodeURIComponent(item.file) + '" target="_blank" rel="noreferrer">' + escapeHtml(item[currentLanguage]) + " ↗</a>";

      return [
        '<tr class="' + (item.case ? "selectable-row" : "") + '">',
        '  <td><span class="rule-status ' + item.status + '"><i></i>' + statusLabel + "</span></td>",
        "  <td>" + titleControl + '<small class="rule-file">' + escapeHtml(item.file) + "</small></td>",
        '  <td><span class="attack-id">' + item.techniques.map(escapeHtml).join(" / ") + "</span></td>",
        "  <td>" + escapeHtml(item.tactic[currentLanguage]) + "</td>",
        '  <td><span class="risk-badge risk-' + item.severity + '">' + item.risk + "</span></td>",
        '  <td><code class="cron">' + escapeHtml(item.schedule) + "</code></td>",
        '  <td><span class="validation-state ' + item.status + '"><i></i>' + escapeHtml(validationText(item)) + "</span></td>",
        "</tr>"
      ].join("");
    }).join("");
  }

  function renderCase(caseKey) {
    var item = data.cases[caseKey];
    activeCase = caseKey;

    document.getElementById("case-tactic").textContent = item.tactic[currentLanguage];
    document.getElementById("case-title").textContent = item.title[currentLanguage];
    document.getElementById("case-hypothesis").textContent = item.hypothesis[currentLanguage];
    document.getElementById("case-technique").textContent = item.technique;
    document.getElementById("case-source").textContent = item.source;
    document.getElementById("case-risk").textContent = item.risk;
    document.getElementById("case-schedule").textContent = item.schedule;
    document.getElementById("case-tuning").textContent = item.tuning[currentLanguage];
    document.getElementById("case-code-label").textContent = item.codeLabel;
    document.getElementById("case-code").textContent = item.code;

    var severity = document.getElementById("case-severity");
    severity.className = "severity-badge severity-" + item.severity;
    severity.textContent = item.severityLabel[currentLanguage];

    var evidence = document.getElementById("case-evidence");
    evidence.src = item.evidence;
    evidence.alt = currentLanguage === "fr"
      ? "Preuve Splunk pour " + item.title.fr
      : "Splunk evidence for " + item.title.en;
    document.getElementById("case-evidence-button").dataset.openImage = item.evidence;

    document.getElementById("case-fields").innerHTML = item.fields.map(function (field) {
      return '<p><span>' + escapeHtml(field[0]) + '</span><code title="' + escapeHtml(field[1]) + '">' + escapeHtml(field[1]) + "</code></p>";
    }).join("");

    document.getElementById("case-timeline").innerHTML = item.timeline.map(function (step, index) {
      return [
        "<li>",
        "  <span>" + String(index + 1).padStart(2, "0") + "</span>",
        "  <div><strong>" + escapeHtml(step.label[currentLanguage]) + "</strong><p>" + escapeHtml(step.detail[currentLanguage]) + "</p></div>",
        "</li>"
      ].join("");
    }).join("");

    document.querySelectorAll("[data-case]").forEach(function (button) {
      var selected = button.dataset.case === caseKey;
      button.classList.toggle("active", selected);
      button.setAttribute("aria-selected", String(selected));
    });
  }

  function showToast(message) {
    var toast = document.getElementById("toast");
    toast.textContent = message;
    toast.classList.add("show");
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(function () {
      toast.classList.remove("show");
    }, 1800);
  }

  function openImage(path) {
    var modal = document.getElementById("image-modal");
    var image = modal.querySelector("img");
    image.src = path;
    image.alt = currentLanguage === "fr"
      ? "Preuve Splunk en pleine résolution"
      : "Full-resolution Splunk evidence";
    modal.showModal();
  }

  function runSnapshotSearch() {
    var button = document.getElementById("run-search");
    var status = document.getElementById("search-status");
    var defaultLabel = currentLanguage === "fr" ? "Rechercher" : "Search";
    button.disabled = true;
    button.textContent = currentLanguage === "fr" ? "Exécution…" : "Running…";
    status.classList.add("running");

    window.setTimeout(function () {
      button.disabled = false;
      button.textContent = defaultLabel;
      status.classList.remove("running");
      status.classList.add("refreshed");
      window.setTimeout(function () { status.classList.remove("refreshed"); }, 650);
      showToast(currentLanguage === "fr" ? "Snapshot interrogé · 473 événements" : "Snapshot queried · 473 events");
    }, 520);
  }

  document.querySelectorAll("[data-language]").forEach(function (button) {
    button.addEventListener("click", function () {
      setLanguage(button.dataset.language);
    });
  });

  document.getElementById("run-search").addEventListener("click", runSnapshotSearch);
  document.getElementById("spl-search").addEventListener("keydown", function (event) {
    if (event.key === "Enter") runSnapshotSearch();
  });

  document.querySelectorAll("[data-query]").forEach(function (button) {
    button.addEventListener("click", function () {
      document.getElementById("spl-search").value = button.dataset.query;
      document.getElementById("spl-search").focus();
    });
  });

  document.getElementById("detection-search").addEventListener("input", renderDetections);

  document.querySelectorAll("[data-filter]").forEach(function (button) {
    button.addEventListener("click", function () {
      activeFilter = button.dataset.filter;
      document.querySelectorAll("[data-filter]").forEach(function (candidate) {
        candidate.classList.toggle("active", candidate === button);
      });
      renderDetections();
    });
  });

  document.addEventListener("click", function (event) {
    var caseButton = event.target.closest("[data-case], [data-open-case]");
    if (caseButton) {
      var requestedCase = caseButton.dataset.case || caseButton.dataset.openCase;
      renderCase(requestedCase);
      if (caseButton.dataset.openCase) {
        document.getElementById("investigate").scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }

    var imageButton = event.target.closest("[data-open-image]");
    if (imageButton) openImage(imageButton.dataset.openImage);
  });

  document.getElementById("copy-spl").addEventListener("click", function () {
    var code = data.cases[activeCase].code;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(code).then(function () {
        showToast(currentLanguage === "fr" ? "SPL copié" : "SPL copied");
      });
      return;
    }

    var area = document.createElement("textarea");
    area.value = code;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
    showToast(currentLanguage === "fr" ? "SPL copié" : "SPL copied");
  });

  document.querySelector(".modal-close").addEventListener("click", function () {
    document.getElementById("image-modal").close();
  });

  document.getElementById("image-modal").addEventListener("click", function (event) {
    if (event.target === event.currentTarget) event.currentTarget.close();
  });

  var mobileMenu = document.querySelector(".mobile-menu");
  var appNavigation = document.getElementById("app-navigation");
  mobileMenu.addEventListener("click", function () {
    var expanded = mobileMenu.getAttribute("aria-expanded") === "true";
    mobileMenu.setAttribute("aria-expanded", String(!expanded));
    appNavigation.classList.toggle("open", !expanded);
  });

  appNavigation.querySelectorAll("a").forEach(function (link) {
    link.addEventListener("click", function () {
      mobileMenu.setAttribute("aria-expanded", "false");
      appNavigation.classList.remove("open");
    });
  });

  if ("IntersectionObserver" in window) {
    var navigationObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        document.querySelectorAll(".app-navigation a").forEach(function (link) {
          link.classList.toggle("active", link.getAttribute("href") === "#" + entry.target.id);
        });
      });
    }, { rootMargin: "-20% 0px -70% 0px" });

    document.querySelectorAll(".section-anchor").forEach(function (section) {
      navigationObserver.observe(section);
    });
  }

  setLanguage(currentLanguage);
}());
