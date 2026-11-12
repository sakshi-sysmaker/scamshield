package com.example.scam;

import java.util.*;
import java.util.regex.Pattern;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class Detector {

    private static final Pattern IP_HOST =
            Pattern.compile("^(https?://)?\\d{1,3}(\\.\\d{1,3}){3}.*");

    public static Map<String, Object> analyze(String input, String type) {
        String t = input == null ? "" : input.toLowerCase().trim();
        int score = 0;
        List<String> reasons = new ArrayList<>();
        if (type.equals("message")) {

            if (hasAny(t, "upi", "bank account", "debit card",
                    "credit card", "transaction failed")) {
                score += 20;
                reasons.add("Possible banking or UPI fraud");
            }

            if (hasAny(t, "job offer", "work from home",
                    "registration fee", "pay to get job")) {
                score += 25;
                reasons.add("Possible fake job offer");
            }

            if (hasAny(t, "investment", "double your money",
                    "guaranteed profit", "daily returns")) {
                score += 25;
                reasons.add("Possible investment scam");
            }

            if (hasAny(t, "police case", "arrest warrant",
                    "legal action", "pay fine immediately")) {
                score += 25;
                reasons.add("Possible fake authority threat");
            }
        }

        if (hasAny(t, "urgent", "immediately", "turant", "abhi", "24 hours")) {
            score += 15;
            reasons.add("Urgency language used");
        }
        if (hasAny(t, "otp", "pin", "cvv", "password")) {
            score += 30;
            reasons.add("Asks for sensitive information (OTP, PIN or password)");
        }
        if (hasAny(t, "lottery", "winner", "prize", "registration fee", "jeeta")) {
            score += 25;
            reasons.add("Lottery or prize offer");
        }
        if (hasAny(t, "kyc", "account blocked", "account suspend")) {
            score += 20;
            reasons.add("KYC or account block threat");
        }
        if (hasAny(t, "bit.ly", "tinyurl", ".xyz", ".top", "http://")) {
            score += 25;
            reasons.add("Suspicious link detected");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        switch (type) {

            case "link" -> {

                String url = t;

                // URL validation
                try {
                    URI uri = URI.create(
                            url.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")
                                    ? url : "https://" + url
                    );

                    String host = uri.getHost();

                    if (host == null || !host.contains(".")) {
                        score += 25;
                        reasons.add("Invalid or suspicious URL format");
                    } else {

                        // IP address detection
                        if (IP_HOST.matcher(url).matches()) {
                            score += 25;
                            reasons.add("URL uses an IP address instead of a domain");
                        }

                        // Fake domain detection
                        if (hasAny(host, "paypa1", "amaz0n",
                                "g00gle", "micros0ft", "faceb00k")) {
                            score += 30;
                            reasons.add("Possible fake or impersonated domain");
                        }

                        // Punycode detection
                        if (host.contains("xn--")) {
                            score += 20;
                            reasons.add("Domain contains encoded international characters");
                        }
                    }

                    // HTTP check
                    if ("http".equalsIgnoreCase(uri.getScheme())) {
                        score += 10;
                        reasons.add("Website does not use HTTPS");
                    }

                } catch (Exception e) {
                    score += 25;
                    reasons.add("URL could not be validated");
                }

                // @ symbol
                if (t.contains("@")) {
                    score += 20;
                    reasons.add("URL contains @ symbol");
                }

                // Shortened URLs
                if (hasAny(t, "bit.ly", "tinyurl.com", "t.co",
                        "is.gd", "cutt.ly", "rebrand.ly", "rb.gy")) {
                    score += 20;
                    reasons.add("URL uses a shortened link service");
                }

                // Suspicious keywords
                if (hasAny(t, "login", "verify", "secure",
                        "update", "wallet", "password",
                        "payment", "claim", "reward", "otp")) {
                    score += 15;
                    reasons.add("Suspicious login or payment-related words");
                }

                // Dangerous schemes
                if (hasAny(t, "javascript:", "data:")) {
                    score += 30;
                    reasons.add("Potentially dangerous URL scheme");
                }

                // Suspicious extensions
                if (hasAny(t, ".click", ".work", ".support")) {
                    score += 15;
                    reasons.add("Domain extension requires extra verification");
                }

                // Encoded URL detection
                try {
                    String decoded = URLDecoder.decode(
                            t, StandardCharsets.UTF_8
                    );

                    if (!decoded.equals(t) &&
                            hasAny(decoded, "javascript:", "data:", "login=")) {
                        score += 20;
                        reasons.add("URL contains suspicious encoded content");
                    }
                } catch (Exception e) {
                    score += 10;
                    reasons.add("URL encoding could not be validated");
                }

            }
            case "email" -> {
                int at = t.indexOf('@');

                if (at < 1 || at != t.lastIndexOf('@') || at == t.length() - 1) {
                    score += 25;
                    reasons.add("Invalid email address format");
                } else {
                    String name = t.substring(0, at);
                    String domain = t.substring(at + 1);

                    // Email format validation
                    if (!t.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
                        score += 20;
                        reasons.add("Email format appears suspicious");
                    }

                    // Suspicious domain extensions
                    if (hasAny(domain, ".xyz", ".top", ".click",
                            ".icu", ".work", ".support", ".rest")) {
                        score += 20;
                        reasons.add("Suspicious email domain extension");
                    }

                    // Disposable email services
                    if (hasAny(domain, "tempmail", "guerrillamail",
                            "10minutemail", "mailinator", "yopmail")) {
                        score += 25;
                        reasons.add("Temporary or disposable email service");
                    }

                    // Fake brand names
                    if (hasAny(domain, "paypa1", "amaz0n",
                            "g00gle", "micros0ft", "faceb00k")) {
                        score += 30;
                        reasons.add("Possible brand impersonation in email domain");
                    }

                    // Suspicious sender names
                    if (hasAny(name, "support", "verify",
                            "secure", "helpdesk", "admin",
                            "account", "official", "alert")) {
                        score += 10;
                        reasons.add("Sender name uses official-looking keywords");
                    }

                    // Punycode domain
                    if (domain.contains("xn--")) {
                        score += 20;
                        reasons.add("Email domain contains encoded characters");
                    }

                    // Unusual domain structure
                    if (domain.startsWith("-") || domain.contains("..")
                            || domain.matches(".*\\d{5,}.*")) {
                        score += 15;
                        reasons.add("Unusual email domain structure");
                    }
                }
            }
            case "phone" -> {
                String digits = t.replaceAll("\\D", "");

                // Indian number validation
                String number = digits;
                if (number.length() == 10 &&
                        number.charAt(0) >= '6' &&
                        number.charAt(0) <= '9') {

                    String[] states = {
                            "Andhra Pradesh", "Arunachal Pradesh", "Assam",
                            "Bihar", "Chhattisgarh", "Goa", "Gujarat",
                            "Haryana", "Himachal Pradesh", "Jharkhand",
                            "Karnataka", "Kerala", "Madhya Pradesh",
                            "Maharashtra", "Manipur", "Meghalaya", "Mizoram",
                            "Nagaland", "Odisha", "Punjab", "Rajasthan",
                            "Sikkim", "Tamil Nadu", "Telangana", "Tripura",
                            "Uttar Pradesh", "Uttarakhand", "West Bengal",
                            "Delhi"
                    };

                    String[][] cities = {
                            {"Visakhapatnam", "Vijayawada"},
                            {"Itanagar", "Naharlagun"},
                            {"Guwahati", "Dibrugarh"},
                            {"Patna", "Gaya"},
                            {"Raipur", "Bilaspur"},
                            {"Panaji", "Margao"},
                            {"Ahmedabad", "Surat"},
                            {"Gurugram", "Faridabad"},
                            {"Shimla", "Dharamshala"},
                            {"Ranchi", "Jamshedpur"},
                            {"Bengaluru", "Mysuru"},
                            {"Kochi", "Thiruvananthapuram"},
                            {"Bhopal", "Indore"},
                            {"Nagpur", "Mumbai"},
                            {"Imphal", "Thoubal"},
                            {"Shillong", "Tura"},
                            {"Aizawl", "Lunglei"},
                            {"Kohima", "Dimapur"},
                            {"Bhubaneswar", "Cuttack"},
                            {"Amritsar", "Ludhiana"},
                            {"Jaipur", "Jodhpur"},
                            {"Gangtok", "Namchi"},
                            {"Chennai", "Coimbatore"},
                            {"Hyderabad", "Warangal"},
                            {"Agartala", "Udaipur"},
                            {"Lucknow", "Kanpur"},
                            {"Dehradun", "Haridwar"},
                            {"Kolkata", "Howrah"},
                            {"New Delhi", "Dwarka"}
                    };

                    int index = Math.abs(number.hashCode()) % states.length;
                    int cityIndex = Math.abs(number.hashCode() / 31) % 2;

                    result.put("city", cities[index][cityIndex]);
                    result.put("state", states[index]);
                    result.put("country", "India");
                    result.put("locationType", "Simulated Demo Location");
                }

                if (number.length() == 12 && number.startsWith("91")) {
                    number = number.substring(2);
                }

                if (number.length() == 10) {
                    if (number.charAt(0) < '6' || number.charAt(0) > '9') {
                        score += 25;
                        reasons.add("Invalid Indian mobile number prefix");
                    }
                } else if (number.length() < 8 || number.length() > 15) {
                    score += 25;
                    reasons.add("Invalid phone number length");
                }

                // Repeated digit detection
                if (!number.isEmpty() &&
                        number.chars().distinct().count() <= 2) {
                    score += 20;
                    reasons.add("Phone number has a suspicious repeating pattern");
                }

                // Sequential number detection
                if (number.length() >= 6 &&
                        (number.contains("123456") ||
                                number.contains("987654") ||
                                number.contains("012345"))) {
                    score += 15;
                    reasons.add("Phone number contains a predictable sequence");
                }

                // International number indicator
                if (digits.length() > 10 && !digits.startsWith("91")) {
                    reasons.add("International phone number detected");
                }

                reasons.add("Number checked for format and suspicious patterns. Live scam reports are not connected yet.");
            }
            default -> { }
        }

        score = Math.min(score, 100);
        if (reasons.isEmpty()) {
            reasons.add("No known threats found");
        }

        String level;
        if (score == 0) level = type.equals("message") ? "Safe" : "Low";
        else if (score < 30) level = "Low";
        else if (score < 60) level = "Medium";
        else if (score < 80) level = "High";
        else level = "Critical";

        List<String> recs = new ArrayList<>();
        switch (level) {
            case "Safe", "Low" -> {
                recs.add("Still be careful before sharing personal or financial details.");
                recs.add("If something feels wrong, check through an official channel.");
            }
            case "Medium" -> {
                recs.add("Do not click links or reply until you have checked the sender.");
                recs.add("Contact the company through its official website or app.");
            }
            default -> {
                recs.add("Do not click links, call back or reply.");
                recs.add("Never share OTPs, PINs or passwords.");
                recs.add("Report this scam and block the sender.");
            }
        }


        result.put("riskLevel", level);
        result.put("score", score);
        result.put("reasons", reasons);
        result.put("recommendations", recs);
        result.put("reportedLocation",
                result.getOrDefault("city", "Unknown") + ", " +
                        result.getOrDefault("state", "Unknown") + ", India");
        result.put("serverLocation", "Not available");
        return result;
    }

    private static boolean hasAny(String text, String... words) {
        for (String w : words) {
            if (text.contains(w)) return true;
        }
        return false;
    }
}