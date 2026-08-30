# ◈ ZeroTrace

<p align="center">
  <strong>Secure Data Erasure · Verification · Recovery · Compliance</strong>
</p>

<p align="center">
  A cybersecurity-focused platform that brings device detection, data sanitization, verification, security, recovery workflows, and compliance-oriented reporting into one application.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Smart%20India%20Hackathon-Round%203%20Cleared-111827?style=for-the-badge" alt="Smart India Hackathon Round 3 Cleared"/>
  <img src="https://img.shields.io/badge/Status-Active%20Development-111827?style=for-the-badge" alt="Active Development"/>
  <img src="https://img.shields.io/badge/Team-6%20Members-111827?style=for-the-badge" alt="6 Member Team"/>
</p>

---

## ✦ The Problem

Deleting a file is not always the same as securely eliminating the data behind it.

For sensitive information, organizations need more than a simple **Delete** button. They need a workflow that can identify the target device, perform appropriate sanitization, verify the result, preserve relevant information, and present the outcome in a clear and auditable way.

**ZeroTrace** is our attempt to bring those ideas together in a single platform.

> **Detect → Sanitize → Verify → Secure → Report**

---

## ⚡ What is ZeroTrace?

ZeroTrace is a project-oriented cybersecurity platform focused on **secure data erasure and compliance workflows**.

The application combines:

- **Device Detection** — identify the device context involved in the workflow.
- **Data Erasure & Sanitization** — support secure data-erasure operations.
- **Verification** — provide a verification layer after sanitization.
- **Security** — apply security-focused controls and handling.
- **Recovery / Retrieval** — support read-only recovery and retrieval-related workflows.
- **Dashboard & Reporting** — present operational and compliance-oriented information.
- **Frontend + Backend Integration** — connect the platform's user interface with its underlying functionality.

---

## 🧭 How the Workflow Fits Together

```text
┌──────────────────┐
│  Device Detection│
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Target Selection │
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Data Sanitization│
│   / Erasure      │
└────────┬─────────┘
         ↓
┌──────────────────┐
│    Verification  │
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Security / Audit │
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Results / Report │
└──────────────────┘
```

Recovery-related workflows are treated separately and include safeguards intended to keep recovery scans **read-only**.

---

## 🖥️ Key Capabilities

| Capability | What it does |
|---|---|
| **Device Detection** | Establishes the target device context |
| **Secure Erasure** | Supports data sanitization workflows |
| **Verification** | Checks and communicates operation results |
| **Security Controls** | Adds security-focused handling to sensitive actions |
| **Recovery** | Provides recovery/retrieval-oriented workflows |
| **Compliance Dashboard** | Organizes operational and compliance information |
| **Confirmation Safeguards** | Adds confirmation gates before destructive actions |
| **Audit-Oriented Flow** | Keeps important workflow information structured |

---

## 🛡️ Safety by Design

Because data erasure is destructive, ZeroTrace includes a confirmation gate before a wipe operation.

The application currently uses a two-step confirmation flow:

```text
Step 1
Type the exact WIPE confirmation
        ↓
Step 2
Enter the security PIN
        ↓
Start destructive operation
```

Recovery is intentionally treated differently:

```text
Recovery Scan
      ↓
READ-ONLY
      ↓
No source-device modification
```

These safeguards are part of the project's design philosophy: **destructive operations should require deliberate confirmation, while recovery workflows should minimize unintended modification.**

---

## 🏆 Smart India Hackathon

### Round 3 — Cleared

ZeroTrace was developed collaboratively for the **Smart India Hackathon**, and our team successfully **cleared Round 3**.

The experience pushed us to work across:

- problem analysis,
- cybersecurity concepts,
- module-level development,
- frontend and backend work,
- integration,
- testing,
- documentation,
- and team coordination under competition constraints.

> **Built as a team. Improved through iteration. Tested under pressure.**

---

# 👥 Team & Contributions

| Member | Contribution |
|---|---|
| **[Anirban Bhowmik](https://github.com/anirban-bhowmik-coder)** | **Team Lead · Project Management · Coordination · Device Detection · Technical Guidance** |
| **[Vedant](https://github.com/VedantKumar-22)** | **Erasure & Data Sanitization · Retrieval** |
| **[Arukansh](https://github.com/arukansh-ux)** | **Verification** |
| **[Pushkar](https://github.com/Pushkhar123-source)** | **Frontend · Backend · Integration** |
| **[Janvi Verma](https://github.com/JahnviVerma5395)** | **Frontend · Backend** |
| **[Ayush](https://github.com/kumar-ayushsingh)** | **Security · Retrieval · Integration** |

> Individual contribution attribution is intended to be supported by each member's Git history and pull requests as the team continues development.

---

## 🛠️ Technology

### Frontend

- React
- JavaScript / JSX
- TypeScript / TSX
- Tailwind CSS
- Vite
- Lucide React

### Backend / Application Logic

- Python
- Device detection modules
- Sanitization workflows
- Verification and recovery modules
- Dataset-backed project components

### Testing

The repository includes dedicated test files covering areas such as:

```text
Verification
Recovery
Confirmation Safeguards
```

---

## 📁 Repository Structure

```text
ZeroTrace/
│
├── data_erasure_compliance_platform.tsx
├── main.jsx
├── index.html
├── index.css
├── vite.config.js
├── package.json
│
├── zerotrace 1/
│   ├── app.jsx
│   ├── main.py
│   └── zerotrace/
│       ├── device_profile.py
│       └── detection/
│
├── recovery/
│   ├── engine.py
│   ├── carver.py
│   └── models.py
│
├── sih26149_dataset/
│   └── ...
│
├── zerotrace_backend_core_service.py
├── zerotrace_unified_full_stack_application.py
│
├── test_verification.py
├── test_recovery.py
├── test_confirmation_safeguard.py
│
├── README.md
├── TEAM.md
├── COPYRIGHT.md
└── .gitignore
```

---

## 🚀 Getting Started

### Prerequisites

- Node.js
- npm
- Python 3.x

### Frontend

Install the Node dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Create a production build:

```bash
npm run build
```

### Python Components

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

Run the relevant Python modules or tests according to the component you are working on.

> Some project components are prototype/demo implementations and may require additional environment configuration depending on the workflow being tested.

---

## 🔐 Responsible Use

ZeroTrace is a **project-oriented cybersecurity application** created for development, learning, demonstration, and authorized testing.

Only use data-erasure, recovery, device-detection, or security functionality on:

- devices you own,
- systems you administer,
- or systems for which you have explicit authorization.

> **Never use destructive or recovery capabilities against systems or data without permission.**

---

## 📌 Project Status

**Active Development**

The current project represents a working collaborative prototype and continues to evolve.

### Completed / Present

- [x] Device detection
- [x] Data sanitization workflow
- [x] Verification workflow
- [x] Security-focused functionality
- [x] Recovery / retrieval workflow
- [x] Frontend and backend components
- [x] Module integration
- [x] Confirmation safeguards
- [x] Smart India Hackathon Round 3 clearance

### Next

- [ ] Expand device support
- [ ] Strengthen verification depth
- [ ] Improve security controls
- [ ] Improve compliance reporting
- [ ] Expand automated testing
- [ ] Improve reliability and documentation
- [ ] Refine deployment and production readiness

---

## ◇ Why "ZeroTrace"?

The name represents the project's central goal:

> **When sensitive data is intended to be erased, the aim is to minimize recoverable traces while providing a trustworthy way to verify the operation.**

The name is a project concept—not a claim that every possible digital trace can universally be eliminated.

---

## 📜 Copyright

**© 2026 ZeroTrace Team. All Rights Reserved.**

ZeroTrace is a collaborative project created by the ZeroTrace team.

No open-source license is granted by this notice. Any permission to copy, modify, distribute, publish, or commercially reuse the source code must be explicitly provided by the project owners/team.

See [`COPYRIGHT.md`](./COPYRIGHT.md) for the full notice.

---

## ✦ Project Philosophy

```text
Learn
  ↓
Build
  ↓
Test
  ↓
Break
  ↓
Fix
  ↓
Integrate
  ↓
Verify
  ↓
Improve
```

> **Build something you can explain, test, and improve.**

---

<p align="center">
  <strong>ZERO TRACE</strong><br/>
  <sub>Secure data workflows · Verifiable operations · Built collaboratively</sub>
</p>

<p align="center">
  🏆 <strong>Smart India Hackathon · Round 3 Cleared</strong>
</p>
