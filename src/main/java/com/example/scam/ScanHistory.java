package com.example.scam;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scan_history")
public class ScanHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDateTime date;
    private String type;

    @Column(length = 1000)
    private String item;

    private String riskLevel;
    private String serverLocation;

    public ScanHistory() {}

    public ScanHistory(LocalDateTime date, String type,
                       String item, String riskLevel,
                       String serverLocation) {
        this.date = date;
        this.type = type;
        this.item = item;
        this.riskLevel = riskLevel;
        this.serverLocation = serverLocation;
    }

    public Long getId() { return id; }
    public LocalDateTime getDate() { return date; }
    public String getType() { return type; }
    public String getItem() { return item; }
    public String getRiskLevel() { return riskLevel; }
    public String getServerLocation() { return serverLocation; }
}