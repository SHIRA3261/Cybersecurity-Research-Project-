# Cybersecurity-Research-Project-
# Secure authentication system with password hashing and active defense mechanisms against brute-force and sprray attacks
# Group Seed  536128351
# Secure Authentication & Defensive Strategies
# Final Project - Cyber Security Course
# Computer Science Course Number 20940

## Overview
This project implements a secure authentication infrastructure focusing on two main vectors:
1. Robust Password Storage: Implementation of industrial-grade hashing algorithms (Argon2id, bcrypt) utilizing Salt & Pepper.
2. Active Defense Mechanisms: Server-side mitigation strategies against brute-force and spray attacks.

## Files Description

1. HashTable_generator.py
   - Purpose: Generates the user database ("usersX.json file").
   - Functionality: Simulates real-world scenarios by creating users with varying password strengths (Weak/Medium/Strong).
   - Supported Algorithms: 
     * SHA-256 (Salted)
     * bcrypt (Cost=12, CPU-bound)
     * Argon2id (Memory-hard, side-channel resistant)

2. defence.py
   - Purpose: The core authentication library implementing four distinct defense classes:
     * RateLimitingAuthSystem: Throttles requests to slow down automated attacks.
     * LockoutAuthSystem: Temporarily locks accounts after N consecutive failures.
     * CaptchaAuthSystem: Simulates CAPTCHA challenges upon suspicious activity.
     * TOTPAuthSystem: Implements 2FA using Time-based One-Time Passwords (pyotp).

## Usage Instructions

1. Prerequisites:
   pip install bcrypt argon2-cffi pyotp psutil

2. Database Generation:
   Run 'python HashTable_generator.py' and select the desired hashing mode (1-3).
   This will generate the corresponding 'usersX.json' file.

3. Execution:
   Import the desired security class from 'defence.py' into your main script to validate login attempts against the generated JSON database.

## Technical Notes
- Security: The system utilizes a hardcoded 'Pepper' secret for additional security against SQLi/DB leaks.
- Forensics: All login attempts (success/failure) are logged to external log files including timestamps and latency metrics.

---
Submitted by: 
Miriam Hager 210029260
Shira Gabay 326132115 
group seed  536128351
Date: 11.01.26
