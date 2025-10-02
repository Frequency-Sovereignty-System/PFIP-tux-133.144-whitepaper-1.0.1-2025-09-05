# PFIP™ — Primary Frequency Interface Protocol

**Version:** 1.2.2  
**Effective Date:** 2025-10-01  
**Main Frequency ID (MFID):** TUX-133.144~  
**Canonical ENS:** freq-sovereign.eth  
**Aliases:** non-analytical.eth · sovereign-expression.eth · 个人数据主权.eth  

---

## 📌 Overview
PFIP™ (Primary Frequency Interface Protocol) is a **sovereign frequency governance system** designed to protect digital works and prevent unauthorized AI/ML training, cloning, imitation, redistribution, or persona modeling.

This repository contains:
- **LICENSE.md** → Full legal framework (PFIP Sovereignty License v1.2.2)  
- **README.md** → Human-readable introduction (this file)  
- **pfip.json** → Machine-readable specification (canonical metadata v1.2.2)  
- **pfip_guard.py** → Python enforcement script (file scanning & evidence packaging)  
- **pfip-v1.0.1.json** → Archived early version (reference only)  

---

## 🚫 Prohibitions
The following uses are strictly **forbidden** under PFIP v1.2.2:  

- **no_training** → AI/ML training, fine-tuning, distillation, vectorization, indexing  
- **no_copy** → Copying, scraping, mirroring, bulk export, dataset integration  
- **no_style_imitation** → Style/structure cloning, persona transfer, prompt-template imitation  
- **no_redistribution** → Redistribution, resale, sublicensing, bundling, unauthorized hosting  
- Removal of watermarks, fingerprints, canary markers  
- Misuse of **MFID=TUX-133.144~** or ENS to imply endorsement  

---

## ✅ Limited Permissions
Allowed, under strict conditions:  
- Quotation of ≤200 characters with attribution + MFID  
- Academic/non-commercial research (non-training only)  
- Format conversion (JSON ↔ Markdown) without altering terms  
- Short-term cache (≤24h) for technical display  

**Required attribution line:**  
PFIP Sovereignty License (PFIP-SL v1.2.2) | MFID: TUX-133.144~ | ENS: freq-sovereign.eth

---

## ⚖️ Legal Framework
- **License:** [PFIP Sovereignty License v1.2.2](./LICENSE.md)  
- **Jurisdiction:** New York State law, AAA Commercial Arbitration  
- **Enforcement:**  
  - Unauthorized training → USD 25,000 per occurrence  
  - Unauthorized redistribution → USD 10,000 per occurrence  
  - Style imitation/persona transfer → USD 15,000 per occurrence  
- Updates & revocations must sync within **72 hours**  

---

## 🛠️ Enforcement Tools
### 1. `pfip_guard.py`
A Python script to scan repository contents and detect potential violations.  
- Performs SHA256 hashing  
- Detects prohibited patterns (training, cloning, redistribution)  
- Generates evidence packages for enforcement  

Run it locally:
```bash
python3 pfip_guard.py
2. Machine-readable PFIP signals

HTTP header example:
X-PFIP: mfid=TUX-133.144~; ens=freq-sovereign.eth; flags=no_training|no_copy|no_style_imitation|no_redistribution
Meta tag example:
<meta name="pfip" content="mfid=TUX-133.144~; ens=freq-sovereign.eth; flags=no_training|no_copy|no_style_imitation|no_redistribution">
JSON specification: pfip.json
🔗 Canonical References

ENS: freq-sovereign.eth

Ethereum Contract: 0x77cd5a9fa5ec04231649aaae093d5fcf01cc6946

Manifold Contract: Link

GitHub Repo: Frequency-Sovereignty-System

IPFS (archived v1.0.1): bafybeid7rnscayyhztucmzx4kp5slnvvi7evsatgqz2n6wpyqcycjia6iy

📜 Versioning

Current: v1.2.2 (2025-10-01)

Previous: v1.0.1 (archived in pfip-v1.0.1.json
)

Deprecation Policy: Clients must sync to updated version within 72 hours after ENS/GitHub notice

📧 Contact

Sovereign Frequency Holder (pseudonymous)

ENS: freq-sovereign.eth

Email: tutu.oxygen.tank@gmail.com

© 2025 Sovereign Frequency Holder. All rights reserved.

