package com.example.scam;

import java.time.LocalDateTime;
import java.util.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ScamController {

    private final ScanHistoryRepository historyRepository;
    private final ScamReportRepository reportRepository;

    public ScamController(ScanHistoryRepository historyRepository,
                          ScamReportRepository reportRepository) {
        this.historyRepository = historyRepository;
        this.reportRepository = reportRepository;
    }
    private final Map<String, Integer> flags = new HashMap<>();

    private static String normalize(String input) {
        String s = input.toLowerCase().trim();
        if (s.matches("[+\\d\\s()\\-]+")) s = s.replaceAll("\\D", "");
        return s;
    }

    private static String verdict(String level) {
        return switch (level) {
            case "High", "Critical" -> "Likely a scam";
            case "Medium" -> "Suspicious";
            default -> "No scam signs found";
        };
    }

    @PostMapping("/scan/{type}")
    @SuppressWarnings("unchecked")
    public synchronized ResponseEntity<Map<String, Object>> scan(
            @PathVariable String type, @RequestBody Map<String, String> body) {
        if (!List.of("message", "link", "email", "phone").contains(type)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Unknown scan type"));
        }
        String input = body.getOrDefault("input", "").trim();
        if (input.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Enter something to scan"));
        }

        Map<String, Object> result = Detector.analyze(input, type);
        String level = (String) result.get("riskLevel");
        String key = normalize(input);

        if (level.equals("High") || level.equals("Critical")) {
            flags.merge(key, 1, Integer::sum);
        }
        int times = flags.getOrDefault(key, 0);
        boolean blocked = times >= 2;
        if (blocked) {
            level = "Critical";
            result.put("riskLevel", level);
            ((List<String>) result.get("reasons"))
                    .add(0, "Flagged " + times + " times, so it is blocked");
        }
        if (times > 0) {
            result.put("reportedLocation", "Flagged " + times + " time(s)");
        }
        result.put("blocked", blocked);
        result.put("verdict", verdict(level));

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("date", LocalDateTime.now().toString().substring(0, 16).replace('T', ' '));
        row.put("type", type);
        row.put("item", input.length() > 60 ? input.substring(0, 60) + "..." : input);
        row.put("riskLevel", level);
        row.put("serverLocation", result.get("serverLocation"));
        ScanHistory saved = new ScanHistory(
                LocalDateTime.now(),
                type,
                (String) row.get("item"),
                level,
                String.valueOf(result.get("serverLocation"))
        );

        historyRepository.save(saved);

        return ResponseEntity.ok(result);
    }

    @GetMapping("/history")
    public List<Map<String, Object>> history(
            @RequestParam(required = false) String type) {

        List<ScanHistory> records = historyRepository.findAll(
                org.springframework.data.domain.Sort.by(
                        org.springframework.data.domain.Sort.Direction.DESC, "id"
                )
        );

        List<Map<String, Object>> out = new ArrayList<>();

        for (ScanHistory h : records) {
            if (type == null || type.isBlank()
                    || type.equals("all") || type.equals(h.getType())) {

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("date", h.getDate().toString().replace('T', ' '));
                row.put("type", h.getType());
                row.put("item", h.getItem());
                row.put("riskLevel", h.getRiskLevel());
                row.put("serverLocation", h.getServerLocation());

                out.add(row);
            }
        }
        return out;
    }


    @GetMapping("/dashboard")
    public Map<String, Object> dashboard() {

        List<ScanHistory> records = historyRepository.findAll();

        Map<String, Integer> levels = new LinkedHashMap<>();

        for (String l : List.of("Safe", "Low", "Medium", "High", "Critical")) {
            levels.put(l, 0);
        }

        for (ScanHistory h : records) {
            levels.merge(h.getRiskLevel(), 1, Integer::sum);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("totalScans", records.size());
        out.put("safeScans", levels.get("Safe") + levels.get("Low"));
        out.put("mediumRisk", levels.get("Medium"));
        out.put("highAndCritical", levels.get("High") + levels.get("Critical"));
        out.put("byLevel", levels);

        return out;
    }

    @PostMapping("/reports")
    public synchronized ResponseEntity<Map<String, Object>> report(
            @RequestBody Map<String, Object> body) {

        String type = String.valueOf(body.getOrDefault("type", "")).trim();
        String contact = String.valueOf(body.getOrDefault("contact", "")).trim();
        String details = String.valueOf(body.getOrDefault("details", "")).trim();
        String location = String.valueOf(body.getOrDefault("location", "")).trim();

        if (type.isEmpty() || contact.isEmpty() || details.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Type, contact and details are required"));
        }

        try {
            ScamReport report = new ScamReport(
                    type, contact, details, location
            );

            reportRepository.save(report);

            flags.merge(normalize(contact), 1, Integer::sum);

            return ResponseEntity.ok(
                    Map.of("status", "Report sent successfully")
            );

        } catch (Exception e) {
            e.printStackTrace();

            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Database error: " + e.getMessage()));
        }
    }}