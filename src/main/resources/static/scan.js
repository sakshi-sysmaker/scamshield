document.addEventListener("DOMContentLoaded", function () {

    var page = location.pathname.split("/").pop();

    var cfg = {
        "message-scanner.html": { type: "message", btn: /scan message/i },
        "link-scanner.html": { type: "link", btn: /scan link/i },
        "email-scanner.html": { type: "email", btn: /scan email/i },
        "phone-scanner.html": { type: "phone", btn: /check number/i }
    }[page];

    if (!cfg) return;

    var colors = {
        Safe: "#4ade80",
        Low: "#a3e635",
        Medium: "#facc15",
        High: "#fb923c",
        Critical: "#f87171"
    };

    function findButton(re) {
        return Array.from(document.querySelectorAll("button")).find(function (b) {
            return re.test(b.textContent.trim());
        });
    }

    function findInput() {
        var all = Array.from(document.querySelectorAll("textarea, input"));

        var ok = all.filter(function (e) {
            var t = (e.type || "").toLowerCase();

            if (["hidden", "checkbox", "radio", "button", "submit"].includes(t)) {
                return false;
            }

            return !/search/i.test(e.placeholder || "");
        });

        if (cfg.type === "message") {
            return ok.find(function (e) {
                return e.tagName === "TEXTAREA";
            }) || ok[0];
        }

        return ok.find(function (e) {
            return e.tagName === "INPUT";
        }) || ok[0];
    }

    function findTextNode(re) {
        var w = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT
        );

        var n;

        while ((n = w.nextNode())) {
            if (re.test(n.textContent.trim())) return n;
        }

        return null;
    }

    function setRow(label, value) {
        var node = findTextNode(
            new RegExp("^" + label + "\\s*:?", "i")
        );

        if (!node) return null;

        var el = node.parentElement;

        var text = Array.isArray(value)
            ? value.map(function (v) {
                return "• " + v;
            }).join("\n")
            : String(value ?? "Not available");

        var raw = node.textContent.trim();

        if (raw.includes(":")) {
            var name = raw.split(":")[0];
            node.textContent = name + ": " + text;
            el.style.whiteSpace = "pre-line";
            return el;
        }

        var target = el.nextElementSibling;

        if (!target && el.parentElement) {
            target = el.parentElement.nextElementSibling;
        }

        if (!target) {
            target = document.createElement("span");
            el.appendChild(target);
        }

        target.textContent = text;
        target.style.whiteSpace = "pre-line";

        return target;
    }

    function setStatus(msg) {
        var n = findTextNode(
            /your result will appear here|^result$|scan complete|enter something/i
        );

        if (n) n.textContent = msg;
    }




function show(res, input) {
    setStatus("Scan complete");
    if (res && res.result && typeof res.result === "object") res = res.result;

    var level = "";
    Object.keys(res).forEach(function (k) {
        if (!level && /risk|level|label/i.test(k) && typeof res[k] === "string") level = res[k];
    });
    level = String(level).replace(/ risk$/i, "");

    var label = level
        ? level + (res.verdict ? " · " + res.verdict : "") + (res.blocked ? " · Blocked" : "")
        : "Unknown (" + Object.keys(res).join(", ") + ")";
    if (cfg.type === "phone") {
        function formatValue(value) {
            if (Array.isArray(value)) return value.join("\n• ");
            return value || "Not available";
        }

        document.getElementById("riskBadge").textContent =
            "Risk level: " + (level || "Unknown");

        document.getElementById("whyResult").textContent =
            formatValue(res.reasons || res.reason);

        document.getElementById("recommendationText").textContent =
            formatValue(res.recommendations || res.recommendation);

        document.getElementById("metaReportCount").textContent =
            res.reportedLocation || "Not available";

        document.getElementById("metaCity").textContent =
            res.serverLocation || "Not available";

        document.getElementById("resultTitle").textContent =
            "Scan complete: " + input;

        return;
    }

    var r = setRow("Risk level", label);
    if (r) r.style.color = colors[level] || "";
    setRow("Why this result", res.reasons);
    setRow("What to do", res.recommendations);
    setRow("Reported by users", res.reportedLocation || "Not available");
    setRow("Server location", res.serverLocation || "Not available");
    setRow("Scanned link", input);
}

var btn = findButton(cfg.btn);

if (btn) {

    btn.addEventListener("click", function (ev) {

        ev.preventDefault();

        var field = findInput();
        var value = field ? field.value.trim() : "";

        if (!value) {
            setStatus("Enter something to scan");
            return;
        }

        if (cfg.type === "phone" && value.charAt(0) !== "+") {
            var sel = document.querySelector("select");

            if (sel && sel.options.length) {
                var m = sel.options[sel.selectedIndex].text.match(/\+\d+/);
                if (m) value = m[0] + value;
            }
        }

        btn.disabled = true;

        fetch("/api/scan/" + cfg.type, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                input: value
            })
        })
            .then(function (response) {
                return response.json().then(function (data) {
                    if (!response.ok) {
                        throw new Error(data.error || "Scan failed");
                    }
                    return data;
                });
            })
            .then(function (res) {
                show(res, value);
                sessionStorage.setItem("scamshield_latest_scan", JSON.stringify({
                    type: cfg.type,
                    item: value,
                    risk: res.riskLevel || res.risk || "Unknown",
                    why: res.reasons || res.reason || [],
                    whatToDo: res.recommendations || res.recommendation || "Not available",
                    reported: res.reportedLocation || "Not available",
                    location: res.serverLocation || "Not available"
                }));
            })
            .catch(function (error) {
                console.error("Scan error:", error);
                setStatus(error.message || "Could not reach server");
            })
            .finally(function () {
                btn.disabled = false;
            });

    });
}

document.querySelectorAll("button").forEach(function (b) {

    var t = b.textContent.trim();

    if (/^report this scam/i.test(t)) {
        b.addEventListener("click", function () {
            window.location.href = "report-scam.html";
        });
    } else if (/^(clear|scan another)/i.test(t)) {
        b.addEventListener("click", function () {
            window.location.reload();
        });
    }

});

});