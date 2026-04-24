# Authentic Image Inspector by JLV

**AI Image Forensic & Authenticity Analyzer** — April 2026
*Design & Concept by JLV — Jean-Louis Viretti*

A premium, forensic-grade web application that estimates whether an image is
**probably authentic**, **probably AI-generated**, **possibly edited**, or
**inconclusive**. Analysis runs **entirely in your browser** — no file ever
leaves your machine.

> ⚠️ This tool is **probabilistic**, not judicial. It provides an *estimation*
> based on technical indices and visual heuristics. The absence of metadata is
> **not** proof of AI generation.

---

## ✨ Features

### v1.0 (shipped)
- 🖼️ **Drag & drop upload** — JPG, JPEG, PNG, WEBP, AVIF (≤ 30 MB)
- 🔎 **File & metadata panel** — name, MIME, size, dimensions, ratio, timestamps
- 🏷️ **Light EXIF parser (JPEG)** — make, model, software, capture date
- 🪪 **C2PA / JUMBF signal detection** — best-effort byte signature probe
- 📊 **Visual heuristic engine** — 12 real pixel-level features across:
  - Face / body proxies (skin smoothness, symmetry…)
  - Scene (background, shadows, lighting homogeneity)
  - Technical (noise, compression, overly clean zones, color bias)
- 🎯 **AI Probability Score (0–100)** + Confidence & Risk levels
- 🌡️ **Forensic heatmap** — tile-based luma-variance anomaly map on canvas
- 📄 **Expert report** — fully formatted, copy to clipboard or print/PDF
- 🎨 **Premium dark UI** — forensic-lab aesthetic, responsive, print-ready

---

## 🚀 How to run

This is a **pure standalone web app** — no build, no server.

### Option A — Double-click
Just open `index.html` in Chrome, Edge, or Firefox.

### Option B — Local web server (recommended for file:// restrictions)
```bash
# Python 3
python -m http.server 8000

# Node
npx serve .
```
Then open <http://localhost:8000>.

---

## 📁 Project structure

```
Authentic Image Inspector by JLV/
├── index.html        # Semantic markup, sections 01–08
├── styles.css        # Design tokens, premium dark theme, responsive & print
├── app.js            # IIFE app: upload → metadata → heuristics → report
├── assets/
│   └── logo_JLV.jpg  # Brand logo
├── reports/          # Reserved for future report exports
├── docs/             # Reserved for technical documentation
├── prompt.txt        # Original mission brief
└── README.md
```

### `app.js` — main functions
| Function | Role |
|---|---|
| `initApp()` | Wire DOM events |
| `handleFileUpload(file)` | Orchestrate the full pipeline with progress UI |
| `readImageMetadata(file, buf)` | Parse JPEG APP1/EXIF + probe C2PA signature |
| `analyzeImageHeuristics(img)` | Extract luma, noise, tile variance, color bias |
| `computeAIScore(features, meta)` | Combine features + metadata into the verdict |
| `generateForensicMap(img, f)` | Paint the tile-based heatmap overlay |
| `renderResults()` | Populate every card from state |
| `generateExpertReport()` | Produce the text report |
| `copyReport()` / `printReport()` / `resetAnalysis()` | Report utilities |

---

## 🧠 How the score is built

The engine is **heuristic, transparent, and auditable** — no black-box model.
It extracts real pixel statistics (downscaled to 512 px), builds three category
sub-scores and combines them with a metadata penalty:

```
global ≈ face · 0.32  +  scene · 0.28  +  technical · 0.40  +  metaPenalty · 0.6
```

| Range | Verdict |
|---|---|
| 0 – 30 | Probably Authentic |
| 31 – 60 | Possibly Edited |
| 61 – 80 | Probably AI-Generated |
| 81 – 100 | Strong AI Signature |

Confidence downgrades to `Low` when signals diverge strongly or when metadata
is missing and the score lands in the ambiguous 30–70 band.

---

## 🗺️ Roadmap

### v2 — Server-assisted provenance
- ExifTool (backend) for full metadata parsing
- Real C2PA / Content Credentials validation
- High-fidelity PDF export
- Local history of past analyses

### v3 — True forensic backend
- FastAPI + OpenCV + PyTorch
- ELA (Error Level Analysis), PRNU, block-variance forensics
- Fine-tuned detection models (diffusion artifacts, GAN fingerprints)
- Real heatmap from model attribution

### v4 — Beyond still images
- Video authenticity & deepfake detection
- Audio synthesis detection
- Multi-file batch dashboard
- Professional API

---

## ⚠️ Important limitations

**Authentic Image Inspector by JLV** provides a probabilistic estimation based
on technical and visual indices. A compressed, cropped, edited, or
screenshot-captured image can significantly reduce analysis reliability.
**The absence of metadata is not proof of AI generation.** Only reliable
provenance signatures — such as certain C2PA or Content Credentials mechanisms
— can provide stronger evidence of origin or modification.

This application:

- ❌ does **not** perform facial recognition
- ❌ does **not** identify individuals
- ❌ does **not** upload your images anywhere
- ✅ runs **entirely client-side** in your browser

---

## 📜 License & credits

Design & Concept by **JLV — Jean-Louis Viretti**.
Forensic aesthetic inspired by cybersecurity cockpits and financial analytics dashboards.

Probabilistic tool · Not a judicial proof.
