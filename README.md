<p align="center">
  <h1 align="center">Miser</h1>
  <h4 align="center">Automated Binary Evasion through AI-driven Instruction Refactoring</h4>
</p>

<p align="center">

  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/license-MIT-red.svg">
  </a>

  <a href="https://github.com/RaghavanSV/miser">
    <img src="https://img.shields.io/badge/maintained%3F-yes-brightgreen.svg">
  </a>

  <a href="https://github.com/RaghavanSV/miser/issues">
    <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat">
  </a>

</p>

<p align="center">
  <a href="#introduction">Introduction</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#patching-strategies">Patching Strategies</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

# Introduction

**Miser** is an automated tool designed to produce evasive variants of input binaries by pinpointing YARA-detected byte sequences and refactoring them using a **Double-LLM verification loop**. Most mutation engines rely on static instruction swaps; Miser uses AI to understand the context of the surrounding instructions (prologue/epilogue) to generate logically equivalent but bytecode-distinct alternatives. This "context-aware" approach ensures that mutated binaries remain functional even after significant instruction substitution.

# Features

- **Automated Signature Scanning**: Integrated with `yara-python` to identify precise detection offsets.
- **Context-Aware Disassembly**: Automatically extracts ±64 bytes of context around every detection to preserve register and stack integrity.
- **Double-LLM Refactoring Loop**:
    - **Generator**: Produces creative, functionally equivalent assembly alternatives.
    - **Auditor**: A second LLM pass that verifies logical consistency and flags potential side effects before patching.
- **Hybrid Patching Engine**:
    - **Option A (In-place)**: Efficient overwriting with `NOP` padding for same-size or smaller mutations.
    - **Option B (Code Cave)**: Redirects execution to unused "caves" for larger, more complex refactors.
- **Iterative Evasion**: Continues mutating the binary until the YARA detection count hits zero.

# Installation

Clone the repository and set up the Python environment:

```sh
git clone https://github.com/RaghavanSV/miser.git
cd miser
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> **Prerequisites**: Python 3.10+ and a valid LLM API key (Generic interface provided).

# Usage

> Prepare your rules
Place your `.yar` or `.yara` rules in the `rules/` directory.

> Run the evasion loop
```sh
python miser.py <target_binary.exe>
```

The tool will create a `variants/` folder containing the mutated versions produced in each iteration.

# Architecture

| Module | Responsibility |
|---|---|
| `scanner.py` | Loads YARA rules and identifies detection offsets/bytes. |
| `refactor_engine.py` | Handles disassembly (Capstone), AI prompting, and assembly (Keystone). |
| `patcher.py` | Manages binary modification (pefile), codecaves, and JMP redirections. |
| `miser.py` | Orchestrates the end-to-end loop and variant management. |

# Patching Strategies

### Option A: In-place Substitution
Used when the refactored instruction set is smaller than or equal to the original byte length. Remaining space is automatically padded with `NOP` (0x90) instructions to maintain offset alignment.

### Option B: Code Cave Redirection
Used for complex mutations that increase the instruction size. Miser:
1. Finds an executable null-byte region (Code Cave).
2. Writes the new logic into the cave.
3. Inserts a `JMP` at the original site.
4. Appends a `JMP` back to the return address at the end of the cave.

# Project Structure

```
miser/
├── rules/               # Your YARA rules here (.yar)
├── variants/            # Output folder for mutated binaries
├── .venv/               # Virtual environment
├── scanner.py           # YARA integration
├── refactor_engine.py   # AI & Disassembly logic
├── patcher.py           # PE patching & Code Cave management
├── miser.py             # Main loop & orchestration
├── requirements.txt     # Project dependencies
└── README.md            # This file
```

# Disclaimer

Use this project under your own responsibility! This tool is intended for **authorized penetration testing and security research only**. The author is not responsible for any misuse. Mutating binaries can lead to instability; always verify variants in an isolated environment.

# License

This project is under [MIT](https://opensource.org/licenses/MIT) license

Copyright © 2026, *RaghavanSV*
