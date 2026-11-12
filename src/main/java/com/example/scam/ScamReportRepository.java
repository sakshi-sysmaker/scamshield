package com.example.scam;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ScamReportRepository
        extends JpaRepository<ScamReport, Long> {
}