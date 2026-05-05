<?php
declare(strict_types=1);

return [
  // Paths
  'db_path' => __DIR__ . '/../data/reviewers.sqlite',
  'audit_log_path' => __DIR__ . '/../data/reviewers.audit.log',

  'cryptodb_cache' => __DIR__ . '/../data/cryptodb_cache',

  'secrets' => __DIR__ . '/../secrets/secrets.php',

  // Taxonomy
  'expertise_taxonomy' => [
    "Applications" => [
      "IoT and cyberphysical",
      "IP protection",
      "Isolation and monitoring hardware",
      "MPC, FHE",
      "Post-quantum security",
      "Reconfigurable hardware",
      "RISC-V security",
      "Secure elements",
      "Secure storage",
      "Trusted platforms",
      "Zero-knowledge proof systems",
    ],
  
    "Attacks and countermeasures" => [
      "Fault attacks",
      "Hardware tampering",
      "Hardware trojans",
      "Reverse engineering",
      "SCA",
      "White-box crypto and code obfuscation",
    ],
  
    "Implementations" => [
      "Coprocessors",
      "Hardware",
      "PUFs",
      "RNGs",
      "Software",
      "Special-purpose hardware for cryptanalysis",
    ],
  
    "Theory vs. implementation" => [
      "Algorithm subversion",
      "Emerging algorithms and protocols",
      "Quantum cryptanalysis",
      "Theoretical models",
    ],
  
    "Tools and methodologies" => [
      "Computer aided engineering",
      "Datasets",
      "Domain-specific languages",
      "Formal methods",
      "FPGA design security",
      "Metrics",
      "Physical assurance",
    ],
  ],
];

