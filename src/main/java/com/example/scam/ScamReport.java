package com.example.scam;

import jakarta.persistence.*;

@Entity
@Table(name = "scam_reports")
public class ScamReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String type;
    private String contact;

    @Column(length = 2000)
    private String details;

    private String location;

    public ScamReport() {}

    public ScamReport(String type, String contact,
                      String details, String location) {
        this.type = type;
        this.contact = contact;
        this.details = details;
        this.location = location;
    }
}