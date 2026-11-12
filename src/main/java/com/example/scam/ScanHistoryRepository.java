package com.example.scam;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanHistoryRepository
        extends JpaRepository<ScanHistory, Long> {
}