# ⚔️ BORG: Transitional Authentication Framework for 5G Networks

> **Hierarchical Identity-Based • Threshold & Fail-Stop • Transitional Post-Quantum Security**

<p align="center">
  <img src="https://img.shields.io/badge/network-5G%20Authentication-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/security-Post--Quantum%20Detection-success?style=for-the-badge" />
  <img src="https://img.shields.io/badge/trust-Distributed%20%26%20Accountable-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/status-Research%20Prototype-brightgreen?style=for-the-badge" />
</p>

---

## 📄 Paper Reference

This repository implements and benchmarks the **BORG** framework described in the paper:

> **BORG: Authentication Against Insecure Bootstrapping for 5G Networks — Feasibility, Resiliency, and Transitional Solutions in Post-Quantum Era**  
> **Authors:** Saleh Darzi, Mirza Masfiqur Rahman, Imtiaz Karim, Rouzbeh Behnia, Attila Altay Yavuz, Elisa Bertino  
> **Submitted to:** *IEEE Transactions on Dependable and Secure Computing (TDSC)*  
> **Contact:** ✉️ salehdarzi@usf.edu · rahman75@purdue.edu · imtiaz.karim@utdallas.edu · behnia@usf.edu · attilaayavuz@usf.edu · bertino@purdue.edu

🔗 [Paper PDF (TDSC submission)](./BORG_TDSC_Manuscript_Oct_20.pdf)

---

## 🧠 Abstract

The 5G protocol lacks a robust base station authentication mechanism during the initial bootstrapping phase, leaving it susceptible to threats such as fake base station attacks. Conventional solutions, including digital signatures based on Public Key Infrastructures (PKIs) and identity-based signatures, are inadequate against quantum-capable adversaries. While integrating NIST’s Post-Quantum Cryptography (PQC) standards is a leading approach for quantum resistance, their suitability for 5G base station authentication remains unexplored. Moreover, current solutions are predominantly centralized and lack security features such as distributed authentication.
This work presents, to our knowledge, the first comprehensive network-level performance characterization of integrating NISTPQC standards and conventional digital signatures (including threshold and identity-based schemes) into 5G base station authentication. Our findings reveal significant feasibility concerns, with direct PQC adoption hindered by protocol constraints and large signature sizes. We also highlight the performance limitations of conventional methods due to the overhead of certificate chains. To mitigate these challenges, we propose BORG, a transitional authentication solution based on a Hierarchical IdentityBased Threshold Signature scheme with a Fail-Stop property.BORG offers post-mortem post-quantum forgery detection and distributed trust via threshold and compact signatures, wellsuited for 5G’s stringent requirements. Our performance analysis underscores an important warning on the infeasibility of direct PQC integration and positions BORG as an effective transitional solution toward future quantum-resilient 5G authentication.
> 🧩 BORG achieves distributed trust, forgery accountability, and post-mortem post-quantum forgery detection — all within native 5G constraints.

---

## 🌐 Overview

**BORG** serves as an **intermediate step** toward full PQC migration in 5G networks by providing:

✅ **Hierarchical Identity-Based Trust** — eliminates certificate chains  
✅ **Threshold Signing (t, n)** — distributed base-station cooperation  
✅ **Fail-Stop Security** — provable post-mortem PQ forgery detection  
✅ **Audit Logging** — PQ-secure threshold-signed logs for accountability  
✅ **Real 5G Integration** — implemented on **srsRAN** with **open5GS**

---

## 🔬 Implementation Layers

BORG includes two main implementations:

1️⃣ **Cryptographic Core** — Implements the Hierarchical Identity-Based Threshold Fail-Stop Signature (HITFS) and PQ threshold audit logging.  
2️⃣ **5G Testbed Integration** — Realistic deployment using srsRAN and open5GS for BS–UE bootstrapping and signature verification.

---

## ⚙️ System Requirements

### 🖥️ Hardware

BORG was tested on an SDR-based 5G testbed:

- **CPU:** Intel Core i9-11900K @ 3.50 GHz  
- **RAM:** 64 GB  
- **Radio:** 2× USRP B210 + GPSDO (10 MHz external clock)  
- **OS:** Ubuntu 22.04 LTS  

---

### 🧩 Software Stack

- **5G Stack:** [`srsRAN`](https://github.com/srsran/srsRAN) + [`open5GS`](https://github.com/open5gs/open5gs)  
- **Languages:** C / C++ (core), Python (test & automation)  
- **Crypto Libraries:**  
  - [`OpenSSL`](https://www.openssl.org/) — ECC & hash primitives  
  - [`liboqs`](https://github.com/open-quantum-safe/liboqs) — PQC baseline (comparison)  
  - [`GMP`](https://gmplib.org/) & [`PBC`](https://crypto.stanford.edu/pbc/) — pairing & finite-field arithmetic  
- **Parallelization:** OpenMP / AVX2 vectorization for multi-signer operations  

---

## 🚀 Implementation Structure

```
BORG-Scheme/
│
├── BORG/          # Cryptographic implementation of the BORG digital signature 
│   ├── Centralized_BORG/           # Centralized version of BORG
│   ├── Threshold_BORG/          # Threshold signing (t,n) via BORG
│
├── OTA/                  # Over-The-Air Integration (srsRAN + open5GS) for BORG
│   ├── srsRAN_4G/        # UE integration
│   └── srsRAN_Project/   # gNB and Core integration
|   └── README.md         # OTA installation and running instructions
│
└── README.md
```

---

## 📊 Performance Highlights

| Scheme | Comm. Overhead (Bytes) | E2E Delay (ms) | Security Features |
|:--------|:-----------------------:|:---------------:|:------------------|
| ML-DSA (PQC) | 12276 | 5282 | PQ-secure only |
| Schnorr-HIBS | 144 | 1.61 | Classical IBS |
| **BORG (t,n = 2,3)** | **144** | **2.99** | PQ fail-stop + threshold + distributed trust |

> 🧩 *BORG maintains 5G-compatible packet sizes (≤ 372 B) while achieving PQ-aware forgery detection and distributed authentication.*

---

## 🧪 Experimental Testbed

**Setup:**  
- 5G UE ↔ BS over srsRAN (USRP B210)  
- AMF & Core via open5GS  
- Cold-storage logs maintained on distributed BS nodes  

**Results:**  
- ⚡ 85× lower comm. overhead than NIST PQC  
- ⚡ Up to 1767× faster than ML-DSA  
- 📶 Seamless integration with unmodified 5G SIB1 flow  

---

## 🧾 Citation

If you use this repository or its results, please cite:

```
@article{darzi2025borg,
  title={Authentication Against Insecure Bootstrapping for 5G Networks:
         Feasibility, Resiliency, and Transitional Solutions in Post-Quantum Era},
  author={Darzi, Saleh and Rahman, Mirza Masfiqur and Karim, Imtiaz
          and Behnia, Rouzbeh and Yavuz, Attila Altay and Bertino, Elisa},
  journal={IEEE Transactions on Dependable and Secure Computing},
  year={2025},
  note={Submitted}
}
```

---

## 🤝 Acknowledgments

This work was conducted at the **University of South Florida (USF)**,  
in collaboration with **Purdue University** and **University of Texas at Dallas**.

> Supported by the NSF-SNSF (2444615), NSF Grant No. 2112471, the University of Texas System Rising STARs Award (No. 40071109), and the startup funding from the University of Texas at Dallas.

---

## 🧩 License

This code and manuscript are made available for **academic, research, and reproducibility purposes** only.  
© 2025 Saleh Darzi et al. All rights reserved.
