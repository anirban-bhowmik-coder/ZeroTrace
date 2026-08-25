# ZeroTrace

**Advanced Data Sanitization, Forensic Recovery, and Compliance Platform**

ZeroTrace is an enterprise-grade platform designed to securely sanitize storage media, verify data destruction using forensic analysis, and maintain a rigorous cryptographic chain of custody. Built to meet stringent compliance standards, ZeroTrace ensures that once data is erased, it is mathematically and physically irrecoverable.

![ZeroTrace Dashboard](https://img.shields.io/badge/UI-React_&_TailwindCSS-09090b?style=for-the-badge&logo=react)
![Backend API](https://img.shields.io/badge/Backend-FastAPI_&_Python-059669?style=for-the-badge&logo=fastapi)

## 🚀 Key Features

### 🛡️ Data Sanitization (Erasure Engine)
Supports industry-standard erasure protocols for HDDs, SSDs, NVMes, and external flash media:
*   **NIST 800-88 Clear & Purge (3-pass)**
*   **DoD 5220.22-M (3-pass)**
*   **Crypto Erase (Key Destruction) / SED Purge**
*   **NVMe Sanitize & Block Erase**

### 🔍 Forensic Recovery & Verification (Erasure Validation)
A dedicated `recovery/` module with block-level carvers and entropy analysis capabilities ensures erasure success.
*   **Post-Erasure Verification:** Scans drive sectors to guarantee 0% data entropy and ensure no file fragments remain.
*   **Read-Only Safeguards:** Forensic scans operate strictly in read-only mode to prevent tampering with source evidence.

### 📜 Cryptographic Chain of Custody & Audit Logging
ZeroTrace automatically documents the entire lifecycle of a storage device:
*   Generates **Immutable Audit Logs** tracking job authorization, timestamps, technician IDs, and device pathways.
*   Issues **Cryptographic Certificates of Erasure** (e.g., `CERT-0042-A9F3`) upon successful verification.
*   Generates **Downloadable PDF Certificates** for compliance reporting.

### 🔒 Operational Safeguards & 2FA
Erasure is a destructive and irreversible action. ZeroTrace employs a rigorous **Multi-Step Confirmation Gate**:
1. **Device Verification:** Technician reviews target device ID, capacity, and erasure method.
2. **Typed Confirmation:** Requires explicitly typing `WIPE <DEVICE_ID>` to proceed.
3. **Security PIN / 2FA:** A strict fallback 2FA Security PIN (e.g., `TECH-03` / `803003`) is required before the job starts.

## 🛠️ Tech Stack

*   **Frontend:** React, Vite, Tailwind CSS, Lucide Icons (Running on port `5173`)
*   **Backend:** Python 3, FastAPI, Uvicorn, Pydantic (Running on port `8000`)
*   **Tooling:** `uv` (Fast Python package manager)

## 📦 Installation & Setup

### Prerequisites
Ensure you have Node.js (`npm`) and Python (`uv`) installed on your system.

### 1. Clone the repository
```bash
git clone https://github.com/kumar-ayushsingh/Zerotrace.git
cd Zerotrace
```

### 2. Start the Backend Server
The backend handles device state, job execution, forensic engines, and API endpoints.
```bash
uv pip install -r requirements.txt  # Install dependencies
uv run zerotrace_backend_core_service.py
```
> The backend will launch at `http://localhost:8000`

### 3. Start the Frontend UI
Open a new terminal window in the project root and launch the Vite development server.
```bash
npm install
npm run dev
```
> The frontend dashboard will launch at `http://localhost:5173`

---

## 📊 Dashboard Overview

The ZeroTrace dashboard provides a command-center view of all operations:

1. **Overview / KPIs:** Real-time metrics on total registered devices, successful sanitizations, verification failures, and pending queued jobs.
2. **Jobs Pipeline:** Monitor active block erasure operations, view entropy results, and download compliance certificates.
3. **Device Inventory:** Manage queued, active, completed, and quarantined devices.
4. **Forensic Recovery:** Execute read-only evidence carving and post-erasure validation scans.

## 👥 Technician PINs (Development/Testing)

For testing the confirmation safeguards, the following fallback 2FA PINs are available:

| Technician | PIN |
|---|---|
| `ZT-OPERATOR-01` | `801001` |
| `TECH-03` | `803003` |
| `TECH-07` | `807007` |


