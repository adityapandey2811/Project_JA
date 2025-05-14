# 🔐 Secure Anonymous WhatsApp-like Chat App

A secure, anonymous, and real-time web chat app inspired by WhatsApp. Built with Java, Spring Boot, and WebSockets.

---

## 📌 Project Overview

- **Name:** *(To be decided)*
- **Type:** Secure, anonymous, WhatsApp-like chat application
- **Platform:** Web
- **Backend:** Java 17+, Spring Boot, WebSocket
- **Frontend:** Minimal UI (optional early), Full SPA (later)
- **Database:** H2 (local), PostgreSQL (production)
- **Deployment Target:** AWS (EC2, RDS, API Gateway, etc.)

---

## 🚧 Development Phases – 4 MTPs (Minimum Testable Products)

### ✅ MTP 1: Real-Time Anonymous Messaging (Core Proof of Concept)

**Goal:** Establish core WebSocket-based communication between anonymous users.

**Features:**
- WebSocket server in Spring Boot
- Anonymous session ID on connect
- 1-on-1 real-time messaging
- In-memory message handling
- Test via simple UI or WebSocket client (Postman)

**Tech Focus:**
- Spring WebSocket
- UUID/nickname generator
- WebSocket session mapping

---

### ✅ MTP 2: Persistent Messaging and Conversation Management

**Goal:** Backend persistence and conversation history.

**Features:**
- User model with unique IDs
- Store messages in H2/PostgreSQL
- 1-on-1 conversation management
- Fetch past messages
- Basic pagination

**Tech Focus:**
- Spring Data JPA
- PostgreSQL or H2
- Message & Conversation entities

---

### ✅ MTP 3: Authentication, Read Receipts, Improved UX

**Goal:** Improve messaging reliability and track user states.

**Features:**
- JWT-based login/auth (optional)
- Message status: sent/delivered/read
- Online/offline presence
- Typing indicators
- Message notifications

**Tech Focus:**
- Spring Security + JWT
- WebSocket protocol enhancements
- Optional Redis cache for online status

---

### ✅ MTP 4: Encryption, Scalability & Final Features

**Goal:** Production readiness with added security and features.

**Features:**
- End-to-end encryption (optional/simulated)
- Scalable WebSocket architecture (STOMP, message broker)
- Optional group messaging
- Rate limiting & abuse protection
- Admin dashboard (optional)

**Tech Focus:**
- Encryption (RSA, AES)
- Spring Security upgrades
- Load testing, AWS setup
- Frontend SPA (React, Angular, or Vue)

---

## 🚀 Rollout Plan

### 🔹 Phase 1: Internal Testing (Post-MTP 2)
- Local/internal deployment
- Feedback on message flow & logic

### 🔹 Phase 2: Pre-Production (Post-MTP 3)
- Deploy on AWS Free Tier (EC2, RDS, S3)
- HTTPS, IAM roles
- Limited beta with access control

### 🔹 Phase 3: Production Launch (Post-MTP 4)
- Enable autoscaling, CloudWatch
- Multi-AZ backups
- Custom domain with SSL

---

## 📁 Backend Folder Structure

src/
└── main/
├── java/com/chatapp/
│ ├── controller/
│ ├── config/
│ ├── service/
│ ├── model/
│ ├── repository/
│ ├── websocket/
│ └── ChatAppApplication.java
└── resources/
├── application.yml
└── static/ (optional frontend)


---

## ✅ Summary

| Phase     | Scope                     | Status  |
|-----------|---------------------------|---------|
| MTP 1     | WebSocket Chat            | 🚧 In Progress |
| MTP 2     | Persistence + History     | 🔜 Coming Soon |
| MTP 3     | Auth + Read Receipts      | 🔜 Planned |
| MTP 4     | Encryption + Scale        | 🔜 Planned |
| Rollout   | AWS Deployment            | 🔜 Planned |

---
