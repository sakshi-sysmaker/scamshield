document.addEventListener("DOMContentLoaded", function () {
    var page = location.pathname.split("/").pop();

    function findTextNode(re) {
        var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        var n;
        while ((n = w.nextNode())) {
            if (re.test(n.textContent.trim())) return n;
        }
        return null;
    }

    function button(re) {
        return Array.from(document.querySelectorAll("button")).find(function (b) {
            return re.test(b.textContent.trim());
        });
    }

    function fields() {
        return Array.from(document.querySelectorAll("textarea, input")).filter(function (e) {
            var t = (e.type || "").toLowerCase();
            if (["hidden", "checkbox", "radio", "button", "submit"].indexOf(t) >= 0) return false;
            return !/search/i.test(e.placeholder || "");
        });
    }

    function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ""; }

    /* ---------- Dashboard ---------- */
    function setNumberNear(re, value) {
        var node = findTextNode(re);
        if (!node) return;
        var el = node.parentElement;
        for (var i = 0; i < 3 && el; i++) {
            var t = el.nextElementSibling;
            if (t && /^\d+$/.test(t.textContent.trim())) { t.textContent = String(value); return; }
            el = el.parentElement;
        }
    }

    if (page === "dashboard.html") {
        fetch("/api/dashboard").then(function (r) { return r.json(); }).then(function (d) {
            setNumberNear(/^total scans$/i, d.totalScans);
            setNumberNear(/^safe scans$/i, d.safeScans);
            setNumberNear(/^medium risk$/i, d.mediumRisk);
            setNumberNear(/^high and critical$/i, d.highAndCritical);
            ["Safe", "Low", "Medium", "High", "Critical"].forEach(function (l) {
                setNumberNear(new RegExp("^" + l + "$", "i"), d.byLevel[l]);
            });
        });
    }

    /* ---------- Scan History ---------- */
    if (page === "scan-history.html") {
        var sel = document.querySelector("select");
        var holder = null;

        function render(rows) {
            if (!holder) {
                var n = findTextNode(/^no scans yet$/i);
                if (!n) return;
                holder = n.parentElement.parentElement;
            }
            holder.textContent = "";
            holder.style.cssText = "display:block;width:100%;height:auto;";
            if (!rows.length) {
                var p = document.createElement("p");
                p.style.padding = "24px";
                p.textContent = "No scans yet. Your scans will appear here.";
                holder.appendChild(p);
                return;
            }
            rows.forEach(function (r) {
                var row = document.createElement("div");
                row.style.cssText = "display:grid;grid-template-columns:repeat(5,1fr);gap:8px;padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.08);";
                [r.date, cap(r.type), r.item, r.riskLevel, r.serverLocation].forEach(function (v) {
                    var c = document.createElement("div");
                    c.style.wordBreak = "break-all";
                    c.textContent = v;
                    row.appendChild(c);
                });
                holder.appendChild(row);
            });
        }

        function load() {
            var type = "all";
            if (sel) {
                type = sel.options[sel.selectedIndex].text.toLowerCase();
                if (type.indexOf("phone") >= 0) type = "phone";
            }
            fetch("/api/history?type=" + encodeURIComponent(type))
                .then(function (r) { return r.json(); }).then(render);
        }

        if (sel) sel.addEventListener("change", load);
        var refresh = button(/^refresh/i);
        if (refresh) refresh.addEventListener("click", load);
        var clr = button(/^clear/i);
        if (clr) clr.addEventListener("click", function () { if (sel) sel.selectedIndex = 0; load(); });
        load();
    }

    /* ---------- Report a Scam ---------- */
    if (page === "report-scam.html") {
        var submit = button(/submit report/i);
        var typeSel = document.querySelector("select");
        var msg = document.createElement("div");
        msg.style.cssText = "margin-top:12px;font-weight:600;";
        if (submit) submit.parentElement.insertAdjacentElement("afterend", msg);

        if (submit) submit.addEventListener("click", function (ev) {
            ev.preventDefault();
            var f = fields();
            var inputs = f.filter(function (e) { return e.tagName === "INPUT"; });
            var details = f.find(function (e) { return e.tagName === "TEXTAREA"; });
            var type = typeSel ? typeSel.options[typeSel.selectedIndex].text : "";
            if (/^select/i.test(type)) type = "";
            var body = {
                type: type,
                contact: inputs[0] ? inputs[0].value.trim() : "",
                details: details ? details.value.trim() : "",
                location: inputs[1] ? inputs[1].value.trim() : ""
            };
            fetch("/api/reports", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body)
            })
                .then(function (r) { return r.json(); })
                .then(function (res) {
                    if (res.error) { msg.style.color = "#f87171"; msg.textContent = res.error; return; }
                    msg.style.color = "#4ade80";
                    msg.textContent = "Report sent";
                    f.forEach(function (e) { e.value = ""; });
                    if (typeSel) typeSel.selectedIndex = 0;
                })
                .catch(function () { msg.style.color = "#f87171"; msg.textContent = "Could not reach the server."; });
        });

        var clr2 = button(/^clear/i);
        if (clr2) clr2.addEventListener("click", function () { window.location.reload(); });
    }
});