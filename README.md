[![Open in MATLAB Online](https://www.mathworks.com/images/responsive/global/open-in-matlab-online.svg)](https://matlab.mathworks.com/open/github/v1?repo=dnafinder/crypto)

# Crypto (Classical Ciphers in MATLAB)

A compact MATLAB collection of classical, hand-cipher-era algorithms implemented for study, teaching, and experimentation.  
The repository prioritizes clarity, consistent I/O structures, and faithful algorithmic behavior over modern security.

## 📘 Overview
**Crypto** collects historical ciphers spanning substitution, transposition, and fractionating hybrids, implemented as MATLAB functions with a broadly consistent interface (typically returning structured outputs such as plaintext, ciphertext, and key-related fields).

Where applicable, the implementations are aligned with the conventions and descriptions found in **ACA references** (American Cryptogram Association) as a practical and widely used standard for hobbyist and educational cryptography.  
This is not intended as a strict scholarly critical edition of each cipher variant; instead, the goal is a coherent, usable MATLAB interpretation that matches common ACA-style formulations and terminology.

Primary reference hub:
- https://www.cryptogram.org/resource-area/cipher-types/

## ✨ Features
- Coverage of major classical cipher families:
  - **Polyalphabetic** systems
  - **Monoalphabetic and keyed substitutions**
  - **Polybius-square-based** methods and hybrids
  - **Fractionating** ciphers
  - **Columnar and route-style transpositions**
  - **Mixed substitution-transposition** constructions
- Input sanitization and uppercase normalization
- Key handling designed to be explicit and reproducible
- Emphasis on reversible designs when padding is required
- Self-contained functions intended for both quick exploration and scripted use

## ⚙️ Requirements
- MATLAB (recent versions recommended)

### Optional toolboxes
Some functions may rely on specialized MATLAB functions that belong to optional toolboxes.  
If you prefer zero-toolbox dependencies, those calls can be replaced with deterministic or base-MATLAB alternatives.

## 🧠 Notes
- These algorithms are **not** secure for modern cryptographic purposes.
- Many historical systems assume reduced alphabets (e.g., 25-letter conventions with I/J merged).  
  Functions typically normalize inputs accordingly.
- When padding is used, the implementation aims to preserve clean **decryptability** and to document the convention in the help section of the relevant function.
- The codebase is being progressively refined to improve robustness, consistency of edge-case handling, and documentation quality.

## 🧾 Citation
If you use this repository in teaching, research, or publications, please cite:

Cardillo G. (2014–2025). Crypto: Classical ciphers in MATLAB.  
Available at: https://github.com/dnafinder/crypto

## 👤 Author
Giuseppe Cardillo  
Email: giuseppe.cardillo.75@gmail.com  
GitHub: https://github.com/dnafinder

## 📄 License
The code is provided as-is, without any explicit warranty.  
Please refer to the repository for licensing details if a LICENSE file is present.
