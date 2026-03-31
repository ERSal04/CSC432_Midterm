# Network Traffic Anomaly Detection with ML

**CSC432 Midterm Project** | Elijah Salgado | Dr. Benjamin Knisely

Binary classification of network traffic (BENIGN vs. ATTACK) using Random Forest and SVM trained on the CICIDS2017 dataset.

📄 [Read the full report (PDF)](./CSC432_Midterm_Report.pdf)

🗂️ [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)

---

## Overview

Network traffic anomaly detection monitors and identifies unusual patterns in a computer network. Anomalies are deviations from normal behavior that may indicate cyberattacks or unauthorized access. This project trains two machine learning models to distinguish benign traffic from attack traffic, achieving up to **99.92% accuracy**.

---

## Dataset

**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection System 2017

- Generated in a controlled lab environment simulating a real enterprise network over 5 days
- ~80 features extracted from raw pcap files using CICFlowMeter
- Labeled benign traffic + common attack types (DoS, DDoS, Brute Force, etc.)
- Modern protocols: HTTP, HTTPS, FTP, SSH, email

### Files Used

| File | Traffic Type |
|---|---|
| `Monday-WorkingHours.pcap_ISCX.csv` | Benign baseline |
| `Wednesday-workingHours.pcap_ISCX.csv` | DoS (Hulk, Slowloris, GoldenEye) |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | DDoS |

### Preprocessing

- Dropped Heartbleed class (only 11 samples — statistically unlearnable)
- Removed rows with negative values (CICFlowMeter calculation artifacts)
- Dropped NaN values and duplicate rows
- Applied binary label encoding: `BENIGN = 0`, `ATTACK = 1`
- **Final dataset: 1,333,264 rows** — 75.9% benign / 24.1% attack

---

## Features (15 Total)

| # | Feature | Category | Why It Detects Attacks |
|---|---|---|---|
| 1 | Flow Bytes/s | Volume | DoS floods produce extreme byte rates |
| 2 | Flow Packets/s | Volume | Flood attacks spike packets per second |
| 3 | Fwd Packet Length Max | Packet Size | Attack packets are abnormally small or uniform |
| 4 | Fwd Packet Length Mean | Packet Size | Average size drops during automated attacks |
| 5 | Bwd Packet Length Max | Packet Size | Server responses degrade under attack — **#1 most important feature** |
| 6 | Bwd Packet Length Mean | Packet Size | Server responses degrade under attack — **#2 most important feature** |
| 7 | Flow IAT Mean | Timing | Floods near-zero; slow attacks very high |
| 8 | Flow IAT Std | Timing | Attacks have unnaturally consistent timing |
| 9 | SYN Flag Count | TCP Flags | SYN floods abuse the TCP handshake |
| 10 | RST Flag Count | TCP Flags | Mass resets indicate scan/flood behavior |
| 11 | PSH Flag Count | TCP Flags | Abnormal push patterns in attack flows |
| 12 | Flow Duration | Connection | Slow attacks hold connections unusually long |
| 13 | Total Fwd Packets | Connection | Floods send massive unidirectional packet counts — **#3 most important** |
| 14 | Active Mean | Connection | Active time differs between normal and attack flows |
| 15 | Init_Win_bytes_forward | TCP Window | Attackers advertise tiny or zero window sizes |

> `Fwd IAT Total` was dropped after correlation analysis revealed a 1.00 correlation with `Flow Duration`. `Init_Win_bytes_forward` was added as a replacement for its unique TCP behavioral signal.

---

## Methodology

### Train/Test Split
- **80/20 stratified split** — preserves the 24.1% attack rate in both sets
- Training: 1,066,582 rows | Test: 266,646 rows

### Feature Scaling
- `StandardScaler` applied **after** splitting (fit on train only)
- Prevents data leakage — test data must not influence the scaler

### Models

**Random Forest**
- 100 decision trees, `max_depth=20`, `min_samples_leaf=10`
- `class_weight='balanced'` to handle class imbalance
- Trained on full training set

**SVM (RBF Kernel)**
- Radial Basis Function kernel for non-linear decision boundary
- Trained on a stratified 100,000-row sample (memory/compute constraint)
- `class_weight='balanced'`

---

## Results

| Metric | Random Forest | SVM |
|---|---|---|
| Accuracy | **99.92%** | 96.02% |
| ROC-AUC | **99.92%** | 94.92% |
| Precision (Attack) | **99.78%** | 90.94% |
| Recall (Attack) | **99.90%** | 92.78% |
| F1 (Attack) | **99.84%** | 91.85% |
| False Negative Rate | **0.10%** | 7.22% |

> In a real IDS, the false negative rate is the most critical metric — a missed attack is far more dangerous than a false alarm. RF's 0.10% vs SVM's 7.22% represents a significant operational difference.

---

## Feature Importance (Random Forest)

| Rank | Feature | Importance |
|---|---|---|
| 1 | Bwd Packet Length Mean | 0.1989 |
| 2 | Bwd Packet Length Max | 0.1966 |
| 3 | Total Fwd Packets | 0.1304 |
| 4 | Flow IAT Std | 0.0797 |
| 5 | Init_Win_bytes_forward | 0.0675 |
| 6 | Fwd Packet Length Max | 0.0642 |
| 7 | Flow Packets/s | 0.0581 |
| 8 | Flow IAT Mean | 0.0530 |
| 9 | Fwd Packet Length Mean | 0.0502 |
| 10 | Flow Duration | 0.0463 |
| 11 | Active Mean | 0.0240 |
| 12 | Flow Bytes/s | 0.0225 |
| 13 | PSH Flag Count | 0.0070 |
| 14 | SYN Flag Count | 0.0016 |
| 15 | RST Flag Count | ~0.0000 |

**Key insight:** The two most important features were backward packet length metrics — not raw volume. When a DoS attack overwhelms a server, the server's ability to send normal replies degrades. The model learned to detect this degradation more reliably than incoming traffic volume.

**Why SYN Flag Count ranked last:** The attacks in this dataset (DoS Hulk, DDoS, Slowloris) do not primarily use SYN flooding. Hulk sends legitimate-looking HTTP GET requests; Slowloris holds connections open with partial HTTP headers. SYN Flag Count would rank much higher on a dataset with port scan or SYN flood traffic.

---

## Limitations

- **Unfair comparison:** SVM was trained on ~10% of available data. A fair comparison would require more compute.
- **Dataset age:** CICIDS2017 is from 2017. Modern attack signatures (encrypted malicious traffic, adversarial evasion) may not be captured.
- **Binary classification:** Collapsing all attack types into one label hides which type of attack is occurring.
- **Benchmark gap:** High accuracy on CICIDS2017 does not guarantee equivalent real-world performance.

---

## Future Work

- Multiclass classification to distinguish specific attack types
- Real-time detection pipeline for live traffic scoring
- Evaluation on newer datasets beyond 2017

---

## Project Structure

```
├── data/
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   ├── Wednesday-workingHours.pcap_ISCX.csv
│   └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
├── anomaly_detection.ipynb
├── models/
│   ├── random_forest_model.pkl
│   ├── svm_model.pkl
│   └── scaler.pkl
└── outputs/
    ├── feature_distributions.png
    ├── correlation_heatmap.png
    ├── confusion_matrices.png
    ├── feature_importance.png
    └── model_comparison.png
```

---

## Requirements

```
pandas
numpy
matplotlib
seaborn
scikit-learn
joblib
```

Install with:
```bash
pip install pandas numpy matplotlib seaborn scikit-learn joblib
```

---

## References

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) — Canadian Institute for Cybersecurity
