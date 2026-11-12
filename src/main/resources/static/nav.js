
(function () {
    console.log("nav.js loaded");

    var routes = {
        "home": "home.html",
        "scamshield": "home.html",
        "dashboard": "dashboard.html",
        "message scanner": "message-scanner.html",
        "link scanner": "link-scanner.html",
        "email scanner": "email-scanner.html",
        "phone number scanner": "phone-number-scanner.html",
        "scan results": "scan-results.html",
        "scan history": "scan-history.html",
        "report a scam": "report-scam.html",
        "scam awareness": "scam-awareness.html",
        "get started": "message-scanner.html",
        "start scanning": "message-scanner.html"
    };

    function find(text) {
        var t = text.trim().replace(/\s+/g, " ").toLowerCase();

        if (!t || t.length > 60) return null;

        var keys = Object.keys(routes);

        for (var i = 0; i < keys.length; i++) {
            if (t === keys[i] || t.endsWith(" " + keys[i])) {
                return routes[keys[i]];
            }
        }

        return null;
    }

    document.addEventListener("click", function (e) {
        if (e.target.closest("form")) return;

        var el = e.target;

        for (var i = 0; el && i < 6; i++, el = el.parentElement) {
            var target = find(el.textContent || "");

            if (target) {
                e.preventDefault();
                window.location.href = target;
                return;
            }
        }
    }, false);

})();
