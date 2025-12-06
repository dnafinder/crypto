[![Open in MATLAB Online](https://www.mathworks.com/images/responsive/global/open-in-matlab-online.svg)](https://matlab.mathworks.com/open/github/v1?repo=dnafinder/crypto)

# Crypto (Classical Ciphers in MATLAB)

A compact MATLAB collection of classical, hand-cipher-era algorithms implemented for study, teaching, and experimentation.  
This repository focuses on clear, practical implementations with consistent I/O patterns and examples you can run immediately.

## 📘 Overview
Crypto gathers a curated set of historical ciphers—substitution, transposition, and fractionating hybrids—implemented as MATLAB functions.  
Most functions return a structured output (e.g., out.plain, out.encrypted, and key-related fields) to keep usage consistent across the collection.

The main goal is educational: to explore how classical ciphers work, how keys shape the transformation, and how related families of methods differ in practice.

## ✨ Features
- Broad coverage of classical cipher families:
  - Polybius-based substitutions and hybrids
  - Fractionating ciphers (e.g., Bifid/Trifid families)
  - Columnar and route-style transpositions
  - Polyalphabetic systems (Vigenère family and variants)
- Consistent functional style across files
- Input sanitation and uppercase normalization
- Reproducible examples in each function help section
- Designed for both quick interactive exploration and scripted workflows

## 🧩 Included Ciphers (non-exhaustive)
This repo currently includes functions such as:
- Substitution / Polybius family
  - polybius (if present in repo)
  - playfair (if present)
  - foursquares
  - checkerboard1
  - checkerboard2
  - nihilist (substitution)
  - bazeries
  - chaocipher
- Fractionation + Transposition
  - bifid
  - cmbifid
  - trifid
  - adfgx
  - adfgvx
- Transposition
  - cct
  - railfence
  - nihilist2 (double transposition)
  - amsco
  - cadenus
  - swagman
- Polyalphabetic
  - vigenere
  - beaufort
  - autokey
  - gronsfeld
  - trithemius
  - dellaporta
  - gromark
  - condi
  - ragbaby

Names may evolve as the collection is refined.

## 📥 Installation
1. Download or clone the repository:
   https://github.com/dnafinder/crypto

2. Add the folder to your MATLAB path:
   addpath('path_to_crypto')

3. Verify availability:
   which vigenere
   which adfgx

## ⚙️ Requirements
- MATLAB (recent versions recommended)

### Optional toolboxes
Some functions may rely on specialized functions.
For example, the Statistics and Machine Learning Toolbox may be required if a cipher uses functions like binornd.

If you prefer zero-toolbox dependencies, you can replace such calls with deterministic or basic-random alternatives.

## 🚀 Usage

### General pattern
Most functions follow:
- direction = 1 for encryption
- direction = -1 for decryption

Example (Vigenère):
   out = vigenere('Hide the gold into the tree stump','leprachaun',1);
   out = vigenere(out.encrypted,'leprachaun',-1);

Example (ADFGX with explicit matrix):
   M = ['BTALP';'DHOZK';'QFVSN';'GICUX';'MREWY'];
   out = adfgx('Hide the gold into the tree stump','leprachaun',1,M);
   out = adfgx(out.encrypted,'leprachaun',-1,M);

Example (Bifid with period):
   out = bifid('Hide the gold into the tree stump','leprachaun',7,1);
   out = bifid(out.encrypted,'leprachaun',7,-1);

## 🧠 Notes
- These are historical ciphers and are not secure for modern cryptographic use.
- The implementations aim for clarity and faithful behavior over modern security.
- Many algorithms assume a 25-letter alphabet (I/J merged).  
  Inputs are typically sanitized accordingly.
- When padding is used, logic is designed to remain reversible under decryption whenever feasible.

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
