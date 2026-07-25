(function () {
  "use strict";

  var data = window.PORTFOLIO_DATA;
  var numberFormatter = new Intl.NumberFormat("en-US");
  var activeFilter = "all";
  var activeCase = "lsass";

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function renderIndexes() {
    var target = document.getElementById("index-bars");
    var maxLifetime = Math.max.apply(null, data.indexes.map(function (item) {
      return item.lifetime;
    }));

    target.innerHTML = data.indexes.map(function (item) {
      var width = item.lifetime === 0 ? 1.2 : Math.max(8, (item.lifetime / maxLifetime) * 100);
      return [
        '<div class="index-row">',
        '  <div class="index-label">',
        '    <strong>index=' + escapeHtml(item.name) + "</strong>",
        "    <span>" + numberFormatter.format(item.lifetime) + " lifetime events</span>",
        "  </div>",
        '  <div class="bar-track" aria-label="' + escapeHtml(item.name) + ": " + item.lifetime + ' lifetime events">',
        '    <i style="width:' + width + "%;--bar-color:" + item.color + '"></i>',
        "  </div>",
        '  <div class="index-meta">',
        "    <span>" + item.diskMb + " MB used</span>",
        "    <strong>" + item.retentionDays + "d</strong>",
        "  </div>",
        "</div>"
      ].join("");
    }).join("");
  }

  function renderEventCodes() {
    var target = document.getElementById("event-bars");
    var maxCount = Math.max.apply(null, data.eventCodes.map(function (item) {
      return item.count;
    }));

    target.innerHTML = data.eventCodes.map(function (item, index) {
      var width = (item.count / maxCount) * 100;
      return [
        '<div class="event-row">',
        '  <span class="event-code">EID ' + escapeHtml(item.code) + "</span>",
        '  <div class="event-bar-wrap">',
        '    <div><strong>' + escapeHtml(item.label) + "</strong><span>" + item.count + "</span></div>",
        '    <i class="event-track"><b style="width:' + width + "%;animation-delay:" + (index * 70) + 'ms"></b></i>',
        "  </div>",
        "</div>"
      ].join("");
    }).join("");
  }

  function severityLabel(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
  }

  function renderDetections() {
    var query = document.getElementById("detection-search").value.trim().toLowerCase();
    var grid = document.getElementById("detection-grid");
    var filtered = data.detections.filter(function (item) {
      var statusMatches = activeFilter === "all" || item.status === activeFilter;
      var searchText = [
        item.title,
        item.tactic,
        item.status,
        item.severity,
        item.techniques.join(" ")
      ].join(" ").toLowerCase();
      return statusMatches && searchText.indexOf(query) !== -1;
    });

    grid.innerHTML = filtered.map(function (item) {
      return [
        '<article class="detection-card" data-status="' + item.status + '">',
        '  <div class="detection-card-head">',
        '    <span class="status-badge ' + item.status + '"><i></i>' + escapeHtml(item.status) + "</span>",
        '    <span class="risk-score risk-' + item.severity + '">RISK ' + item.risk + "</span>",
        "  </div>",
        '  <p class="detection-technique">' + item.techniques.map(escapeHtml).join(" / ") + "</p>",
        "  <h3>" + escapeHtml(item.title) + "</h3>",
        '  <div class="detection-footer">',
        "    <span>" + escapeHtml(item.tactic) + "</span>",
        "    <span>" + escapeHtml(item.schedule) + "</span>",
        "  </div>",
        "</article>"
      ].join("");
    }).join("");

    document.getElementById("empty-state").hidden = filtered.length !== 0;
  }

  function renderCase(caseKey) {
    var item = data.cases[caseKey];
    activeCase = caseKey;

    document.getElementById("case-tactic").textContent = item.tactic;
    document.getElementById("case-title").textContent = item.title;
    document.getElementById("case-hypothesis").textContent = item.hypothesis;
    document.getElementById("case-technique").textContent = item.technique;
    document.getElementById("case-source").textContent = item.source;
    document.getElementById("case-risk").textContent = item.risk;
    document.getElementById("case-schedule").textContent = item.schedule;
    document.getElementById("case-tuning").textContent = item.tuning;
    document.getElementById("case-code-label").textContent = item.codeLabel;
    document.getElementById("case-code").textContent = item.code;

    var severity = document.getElementById("case-severity");
    severity.className = "severity-pill severity-" + item.severity;
    severity.textContent = severityLabel(item.severity);

    var evidence = document.getElementById("case-evidence");
    evidence.src = item.evidence;
    evidence.alt = "Splunk validation evidence for " + item.title;
    document.getElementById("case-evidence-button").dataset.openImage = item.evidence;

    document.getElementById("case-timeline").innerHTML = item.timeline.map(function (step, index) {
      return [
        "<li>",
        "  <span>" + String(index + 1).padStart(2, "0") + "</span>",
        "  <div><strong>" + escapeHtml(step.label) + "</strong><p>" + escapeHtml(step.detail) + "</p></div>",
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
    image.alt = "Full-resolution Splunk validation evidence";
    if (typeof modal.showModal === "function") {
      modal.showModal();
    } else {
      modal.setAttribute("open", "");
    }
  }

  function closeImage() {
    var modal = document.getElementById("image-modal");
    if (typeof modal.close === "function") {
      modal.close();
    } else {
      modal.removeAttribute("open");
    }
  }

  function animateCounter(element) {
    var target = Number(element.dataset.counter);
    var startTime = null;
    var duration = Math.min(1400, 650 + Math.log10(target + 1) * 180);

    function step(timestamp) {
      if (!startTime) startTime = timestamp;
      var progress = Math.min(1, (timestamp - startTime) / duration);
      var eased = 1 - Math.pow(1 - progress, 3);
      element.textContent = numberFormatter.format(Math.round(target * eased));
      if (progress < 1) window.requestAnimationFrame(step);
    }

    window.requestAnimationFrame(step);
  }

  function setupObservers() {
    var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var revealItems = document.querySelectorAll(".reveal");

    if (reducedMotion || !("IntersectionObserver" in window)) {
      revealItems.forEach(function (item) { item.classList.add("visible"); });
      document.querySelectorAll("[data-counter]").forEach(function (item) {
        item.textContent = numberFormatter.format(Number(item.dataset.counter));
      });
      return;
    }

    var revealObserver = new IntersectionObserver(function (entries, observer) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var delay = Number(entry.target.dataset.delay || 0);
          window.setTimeout(function () {
            entry.target.classList.add("visible");
          }, delay);
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });

    revealItems.forEach(function (item) { revealObserver.observe(item); });

    var counterObserver = new IntersectionObserver(function (entries, observer) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          animateCounter(entry.target);
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.7 });

    document.querySelectorAll("[data-counter]").forEach(function (item) {
      counterObserver.observe(item);
    });
  }

  renderIndexes();
  renderEventCodes();
  renderDetections();
  renderCase(activeCase);
  setupObservers();

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

  document.querySelectorAll("[data-case]").forEach(function (button) {
    button.addEventListener("click", function () {
      renderCase(button.dataset.case);
    });
  });

  document.getElementById("copy-spl").addEventListener("click", function () {
    var code = data.cases[activeCase].code;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(code).then(function () {
        showToast("SPL copied");
      });
    } else {
      var area = document.createElement("textarea");
      area.value = code;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      showToast("SPL copied");
    }
  });

  document.addEventListener("click", function (event) {
    var trigger = event.target.closest("[data-open-image]");
    if (trigger) openImage(trigger.dataset.openImage);
  });

  document.querySelector(".modal-close").addEventListener("click", closeImage);
  document.getElementById("image-modal").addEventListener("click", function (event) {
    if (event.target === event.currentTarget) closeImage();
  });

  var menuButton = document.querySelector(".menu-button");
  var navigation = document.getElementById("primary-nav");
  menuButton.addEventListener("click", function () {
    var expanded = menuButton.getAttribute("aria-expanded") === "true";
    menuButton.setAttribute("aria-expanded", String(!expanded));
    navigation.classList.toggle("open", !expanded);
  });

  navigation.querySelectorAll("a").forEach(function (link) {
    link.addEventListener("click", function () {
      menuButton.setAttribute("aria-expanded", "false");
      navigation.classList.remove("open");
    });
  });
}());
