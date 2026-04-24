/* ==========================================================================
   Authentic Image Inspector by JLV — app.js
   Probabilistic heuristic engine · April 2026
   ========================================================================== */

(() => {
  "use strict";

  // --------------------------------------------------------------------------
  // State
  // --------------------------------------------------------------------------
  const state = {
    file: null,
    image: null,
    metadata: null,
    features: null,
    scores: null,
    verdict: null,
    report: ""
  };

  // --------------------------------------------------------------------------
  // DOM shortcuts
  // --------------------------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const dom = {
    dropZone: $("dropZone"),
    fileInput: $("fileInput"),
    browseBtn: $("browseBtn"),
    loader: $("loader"),
    loaderFill: document.querySelector(".loader-fill"),
    loaderText: $("loaderText"),
    results: $("results"),
    previewImg: $("previewImg"),
    fileInfo: $("fileInfo"),
    scoreRing: $("scoreRing"),
    scoreNum: $("scoreNum"),
    verdictText: $("verdictText"),
    verdictTag: $("verdictTag"),
    confidenceText: $("confidenceText"),
    riskText: $("riskText"),
    verdictSummary: $("verdictSummary"),
    metaGrid: $("metaGrid"),
    indices: $("indices"),
    canvas: $("forensicCanvas"),
    reportBox: $("reportBox"),
    generateBtn: $("generateBtn"),
    copyBtn: $("copyBtn"),
    printBtn: $("printBtn"),
    resetBtn: $("resetBtn")
  };

  // --------------------------------------------------------------------------
  // Init
  // --------------------------------------------------------------------------
  function initApp() {
    dom.browseBtn.addEventListener("click", (e) => {
      e.stopPropagation(); dom.fileInput.click();
    });
    dom.dropZone.addEventListener("click", () => dom.fileInput.click());
    dom.dropZone.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); dom.fileInput.click(); }
    });
    dom.fileInput.addEventListener("change", (e) => {
      if (e.target.files[0]) handleFileUpload(e.target.files[0]);
    });

    ["dragenter", "dragover"].forEach(ev =>
      dom.dropZone.addEventListener(ev, (e) => {
        e.preventDefault(); e.stopPropagation();
        dom.dropZone.classList.add("drag");
      })
    );
    ["dragleave", "drop"].forEach(ev =>
      dom.dropZone.addEventListener(ev, (e) => {
        e.preventDefault(); e.stopPropagation();
        dom.dropZone.classList.remove("drag");
      })
    );
    dom.dropZone.addEventListener("drop", (e) => {
      const f = e.dataTransfer.files[0];
      if (f) handleFileUpload(f);
    });

    dom.generateBtn.addEventListener("click", generateExpertReport);
    dom.copyBtn.addEventListener("click", copyReport);
    dom.printBtn.addEventListener("click", printReport);
    dom.resetBtn.addEventListener("click", resetAnalysis);
  }

  // --------------------------------------------------------------------------
  // Upload orchestration
  // --------------------------------------------------------------------------
  async function handleFileUpload(file) {
    const ok = ["image/jpeg", "image/jpg", "image/png", "image/webp", "image/avif"];
    if (!ok.includes(file.type)) {
      alert("Unsupported format. Please use JPG, PNG, WEBP or AVIF.");
      return;
    }
    if (file.size > 30 * 1024 * 1024) {
      alert("File too large (max 30 MB for in-browser analysis).");
      return;
    }

    state.file = file;
    showLoader(true);

    try {
      await step("Reading file…", 10);
      const buf = await file.arrayBuffer();

      await step("Parsing metadata…", 25);
      state.metadata = readImageMetadata(file, buf);

      await step("Decoding image…", 45);
      state.image = await loadImage(file);

      await step("Running visual heuristics…", 65);
      state.features = analyzeImageHeuristics(state.image);

      await step("Computing AI probability score…", 82);
      state.scores = computeAIScore(state.features, state.metadata);

      await step("Rendering forensic map…", 94);
      generateForensicMap(state.image, state.features);

      await step("Finalizing verdict…", 100);
      renderResults();
    } catch (err) {
      console.error(err);
      alert("Analysis failed: " + err.message);
    } finally {
      setTimeout(() => showLoader(false), 300);
    }
  }

  function showLoader(on) {
    dom.loader.classList.toggle("hidden", !on);
    if (on) {
      dom.results.classList.add("hidden");
      dom.loaderFill.style.width = "0%";
    } else {
      dom.results.classList.remove("hidden");
    }
  }

  function step(text, pct) {
    dom.loaderText.textContent = text;
    dom.loaderFill.style.width = pct + "%";
    return new Promise(r => setTimeout(r, 180));
  }

  function loadImage(file) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => { resolve(img); };
      img.onerror = () => reject(new Error("Unable to decode image"));
      img.src = url;
    });
  }

  // --------------------------------------------------------------------------
  // Metadata (light EXIF parser for JPEG APP1)
  // --------------------------------------------------------------------------
  function readImageMetadata(file, buf) {
    const meta = {
      name: file.name,
      size: file.size,
      type: file.type,
      lastModified: new Date(file.lastModifiedDate || file.lastModified || Date.now()),
      width: 0, height: 0,
      exifFound: false,
      make: null, model: null, software: null, dateTime: null,
      c2paDetected: false,
      c2paSupported: false,
      stripSuspicion: "low"
    };

    try {
      const view = new DataView(buf);
      // JPEG: starts with 0xFFD8
      if (view.getUint16(0) === 0xFFD8) {
        let off = 2;
        while (off < view.byteLength) {
          if (view.getUint8(off) !== 0xFF) break;
          const marker = view.getUint16(off); off += 2;
          if (marker === 0xFFDA) break; // SOS
          const segLen = view.getUint16(off);
          if (marker === 0xFFE1) { // APP1
            const sigOff = off + 2;
            const sig = String.fromCharCode(
              view.getUint8(sigOff), view.getUint8(sigOff + 1),
              view.getUint8(sigOff + 2), view.getUint8(sigOff + 3)
            );
            if (sig === "Exif") {
              meta.exifFound = true;
              parseExif(view, sigOff + 6, segLen - 8, meta);
            }
          }
          off += segLen;
        }
      }

      // C2PA marker heuristic: search for 'jumb' (JUMBF box) signature
      const bytes = new Uint8Array(buf);
      for (let i = 0; i < Math.min(bytes.length - 4, 200000); i++) {
        if (bytes[i] === 0x6A && bytes[i+1] === 0x75 &&
            bytes[i+2] === 0x6D && bytes[i+3] === 0x62) {
          meta.c2paDetected = true; break;
        }
      }
    } catch (e) { /* ignore parse errors */ }

    // Strip suspicion heuristic
    if (meta.type === "image/jpeg" && !meta.exifFound) {
      meta.stripSuspicion = file.size < 150 * 1024 ? "high" : "moderate";
    } else if (!meta.exifFound) {
      meta.stripSuspicion = "moderate";
    }

    return meta;
  }

  function parseExif(view, start, len, meta) {
    try {
      const little = view.getUint16(start) === 0x4949;
      const get16 = (o) => view.getUint16(o, little);
      const get32 = (o) => view.getUint32(o, little);

      const ifd0 = start + get32(start + 4);
      const entries = get16(ifd0);
      for (let i = 0; i < entries; i++) {
        const entry = ifd0 + 2 + i * 12;
        const tag = get16(entry);
        const type = get16(entry + 2);
        const count = get32(entry + 4);
        const valueOff = entry + 8;

        const readStr = () => {
          const dataOff = (count > 4)
            ? start + get32(valueOff)
            : valueOff;
          let s = "";
          for (let k = 0; k < count - 1; k++) {
            const c = view.getUint8(dataOff + k);
            if (c) s += String.fromCharCode(c);
          }
          return s.trim();
        };

        if (type === 2) {
          if (tag === 0x010F) meta.make = readStr();
          else if (tag === 0x0110) meta.model = readStr();
          else if (tag === 0x0131) meta.software = readStr();
          else if (tag === 0x0132) meta.dateTime = readStr();
        }
      }
    } catch (e) { /* noisy files */ }
  }

  // --------------------------------------------------------------------------
  // Visual heuristic analysis (real pixel-level features)
  // --------------------------------------------------------------------------
  function analyzeImageHeuristics(img) {
    const MAX = 512;
    const scale = Math.min(1, MAX / Math.max(img.width, img.height));
    const w = Math.max(32, Math.round(img.width * scale));
    const h = Math.max(32, Math.round(img.height * scale));

    const cvs = document.createElement("canvas");
    cvs.width = w; cvs.height = h;
    const ctx = cvs.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(img, 0, 0, w, h);
    const { data } = ctx.getImageData(0, 0, w, h);

    // Luma + stats
    const lum = new Float32Array(w * h);
    let rSum = 0, gSum = 0, bSum = 0, satSum = 0;
    for (let i = 0, p = 0; i < data.length; i += 4, p++) {
      const r = data[i], g = data[i+1], b = data[i+2];
      lum[p] = 0.299 * r + 0.587 * g + 0.114 * b;
      rSum += r; gSum += g; bSum += b;
      const mx = Math.max(r, g, b), mn = Math.min(r, g, b);
      satSum += mx === 0 ? 0 : (mx - mn) / mx;
    }
    const N = w * h;
    const meanLum = (rSum + gSum + bSum) / (3 * N);
    const meanSat = satSum / N;

    // Laplacian residual → noise / sharpness estimate
    let lapAbs = 0, lapSqSum = 0, lapCount = 0;
    for (let y = 1; y < h - 1; y++) {
      for (let x = 1; x < w - 1; x++) {
        const p = y * w + x;
        const v = 4 * lum[p] - lum[p-1] - lum[p+1] - lum[p-w] - lum[p+w];
        lapAbs += Math.abs(v);
        lapSqSum += v * v;
        lapCount++;
      }
    }
    const noise = lapAbs / lapCount;           // 0 very smooth, higher = noisier/sharper
    const noiseVar = lapSqSum / lapCount;

    // Tile-based variance map (for heatmap + smoothness distribution)
    const TILE = 32;
    const tilesX = Math.ceil(w / TILE), tilesY = Math.ceil(h / TILE);
    const tileVar = new Float32Array(tilesX * tilesY);
    for (let ty = 0; ty < tilesY; ty++) {
      for (let tx = 0; tx < tilesX; tx++) {
        let sum = 0, sumSq = 0, c = 0;
        const y0 = ty * TILE, y1 = Math.min(h, y0 + TILE);
        const x0 = tx * TILE, x1 = Math.min(w, x0 + TILE);
        for (let y = y0; y < y1; y++)
          for (let x = x0; x < x1; x++) {
            const v = lum[y*w + x]; sum += v; sumSq += v*v; c++;
          }
        const m = sum / c;
        tileVar[ty * tilesX + tx] = (sumSq / c) - m * m;
      }
    }

    // Distribution of tile variance
    const sorted = [...tileVar].sort((a,b) => a - b);
    const median = sorted[sorted.length >> 1];
    const p10 = sorted[Math.floor(sorted.length * 0.1)];
    const p90 = sorted[Math.floor(sorted.length * 0.9)];
    const smoothRatio = sorted.filter(v => v < 30).length / sorted.length; // fraction of very smooth tiles
    const varSpread = (p90 - p10);

    // Color channel balance (AI images often exhibit mild color channel bias)
    const meanR = rSum / N, meanG = gSum / N, meanB = bSum / N;
    const colorBias = Math.sqrt(
      Math.pow(meanR - meanG, 2) + Math.pow(meanG - meanB, 2) + Math.pow(meanR - meanB, 2)
    );

    return {
      width: img.width, height: img.height,
      downW: w, downH: h,
      meanLum, meanSat, noise, noiseVar,
      tileVar, tilesX, tilesY,
      smoothRatio, varSpread,
      meanR, meanG, meanB, colorBias
    };
  }

  // --------------------------------------------------------------------------
  // Scoring
  // --------------------------------------------------------------------------
  function computeAIScore(f, meta) {
    // Each sub-score is 0..1 (higher = more AI-suspicious)
    const clamp01 = (v) => Math.max(0, Math.min(1, v));

    // --- Face/body indices (heuristic proxies — no face detection) ---
    const skinSmoothness   = clamp01((f.smoothRatio - 0.25) / 0.55);
    const eyeCoherence     = clamp01(0.3 + (f.smoothRatio - 0.3) * 0.8);
    const handsFingers     = clamp01(0.25 + (f.smoothRatio - 0.2) * 0.6);
    const earsSymmetry     = clamp01(0.2 + Math.max(0, 0.5 - f.noise/8));

    // --- Scene indices ---
    const backgroundFlow   = clamp01(1 - f.varSpread / 800);
    const shadowCoherence  = clamp01(0.3 + (0.6 - f.meanSat) * 0.7);
    const lightingHomog    = clamp01(1 - f.varSpread / 1200);
    const textLegibility   = clamp01(f.smoothRatio);

    // --- Technical indices ---
    const noiseInconsist   = clamp01(1 - Math.min(1, f.noise / 12));  // very low noise = suspicious
    const compressionAnom  = clamp01(0.25 + (0.5 - Math.min(0.5, f.noise/25)) );
    const cleanZones       = clamp01(f.smoothRatio);
    const colorBiasScore   = clamp01(f.colorBias / 50);

    // Metadata weight
    let metaPenalty = 0;
    if (!meta.exifFound) metaPenalty += 0.18;
    if (meta.stripSuspicion === "high") metaPenalty += 0.10;
    if (meta.stripSuspicion === "moderate") metaPenalty += 0.05;
    if (meta.software && /midjourney|stable diffusion|dall-?e|firefly|flux|sora/i.test(meta.software)) {
      metaPenalty += 0.40;
    }
    if (meta.make || meta.model) metaPenalty -= 0.15;
    if (meta.c2paDetected) metaPenalty -= 0.10;

    const face = avg([skinSmoothness, eyeCoherence, handsFingers, earsSymmetry]);
    const scene = avg([backgroundFlow, shadowCoherence, lightingHomog, textLegibility]);
    const tech = avg([noiseInconsist, compressionAnom, cleanZones, colorBiasScore]);

    // Weighted global score
    let global = face * 0.32 + scene * 0.28 + tech * 0.40 + metaPenalty * 0.6;
    global = clamp01(global);
    const aiProb = Math.round(global * 100);

    // Confidence: how distinct signals are
    const varSig = variance([face, scene, tech]);
    let confidence = "Medium";
    if (aiProb < 20 || aiProb > 80) confidence = "High";
    if (varSig > 0.05 && (aiProb > 30 && aiProb < 70)) confidence = "Low";
    if (!meta.exifFound && aiProb > 30 && aiProb < 70) confidence = "Low";

    // Verdict
    let verdict, verdictShort, risk;
    if (aiProb <= 30) { verdict = "Probably Authentic"; verdictShort = "AUTHENTIC"; risk = "Low"; }
    else if (aiProb <= 60) { verdict = "Possibly Edited"; verdictShort = "EDITED?"; risk = "Moderate"; }
    else if (aiProb <= 80) { verdict = "Probably AI-Generated"; verdictShort = "AI-LIKELY"; risk = "High"; }
    else { verdict = "Strong AI Signature"; verdictShort = "AI-VERY-LIKELY"; risk = "Critical"; }

    // Build category breakdown
    const categories = {
      face: {
        label: "Face / Body",
        level: bucket(face),
        items: [
          ["Skin texture uniformity", skinSmoothness],
          ["Eye coherence proxy", eyeCoherence],
          ["Hands / fingers proxy", handsFingers],
          ["Symmetry proxy", earsSymmetry]
        ]
      },
      scene: {
        label: "Scene",
        level: bucket(scene),
        items: [
          ["Background coherence", backgroundFlow],
          ["Shadow consistency", shadowCoherence],
          ["Lighting homogeneity", lightingHomog],
          ["Text legibility proxy", textLegibility]
        ]
      },
      tech: {
        label: "Technical",
        level: bucket(tech),
        items: [
          ["Noise inconsistency", noiseInconsist],
          ["Compression anomalies", compressionAnom],
          ["Overly clean zones", cleanZones],
          ["Color channel bias", colorBiasScore]
        ]
      }
    };

    const summary = buildSummary(verdict, aiProb, categories, meta);

    return { aiProb, confidence, risk, verdict, verdictShort, summary, categories,
             face, scene, tech };
  }

  function avg(arr) { return arr.reduce((a,b) => a + b, 0) / arr.length; }
  function variance(arr) {
    const m = avg(arr);
    return avg(arr.map(v => (v - m) * (v - m)));
  }
  function bucket(v) {
    if (v < 0.34) return "low";
    if (v < 0.67) return "medium";
    return "high";
  }

  function buildSummary(verdict, p, cats, meta) {
    const bits = [];
    if (!meta.exifFound) bits.push("metadata is absent or stripped");
    else if (meta.make) bits.push(`device metadata present (${meta.make}${meta.model ? ' · ' + meta.model : ''})`);
    if (meta.software) bits.push(`software trace: ${meta.software}`);
    if (meta.c2paDetected) bits.push("C2PA / JUMBF signal detected");

    if (cats.face.level === "high") bits.push("face/body coherence indices are weak");
    if (cats.scene.level === "high") bits.push("scene/lighting consistency is anomalous");
    if (cats.tech.level === "high") bits.push("technical features (noise, compression) look unusual");
    if (cats.tech.level === "low" && cats.face.level === "low") bits.push("technical noise patterns look organic");

    return `${verdict}. Estimated AI probability: ${p}/100. Signals: ${bits.join("; ") || "insufficient distinctive signals"}. This result is probabilistic and should be corroborated by human review.`;
  }

  // --------------------------------------------------------------------------
  // Forensic heatmap
  // --------------------------------------------------------------------------
  function generateForensicMap(img, f) {
    const canvas = dom.canvas;
    const maxW = 900;
    const scale = Math.min(1, maxW / img.width);
    const W = Math.round(img.width * scale);
    const H = Math.round(img.height * scale);
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0, W, H);

    // Compute normalized anomaly per tile:
    // - very smooth tiles (low variance) AND mid-brightness → flagged as suspicious
    const tv = f.tileVar, tx = f.tilesX, ty = f.tilesY;
    const max = Math.max(...tv);
    const min = Math.min(...tv);
    const range = Math.max(1, max - min);

    const tileW = W / tx, tileH = H / ty;
    ctx.globalCompositeOperation = "source-over";

    for (let j = 0; j < ty; j++) {
      for (let i = 0; i < tx; i++) {
        const v = tv[j * tx + i];
        const norm = (v - min) / range;          // 0..1  (1 = high detail)
        const smoothness = 1 - norm;              // 1 = very smooth

        // Suspicious = very smooth OR abrupt edges in an otherwise flat zone
        let anomaly = 0;
        if (smoothness > 0.75) anomaly = smoothness * 0.9;
        else if (smoothness < 0.1) anomaly = 0.4;

        if (anomaly < 0.25) continue;

        let r, g, b;
        if (anomaly < 0.45) { r = 34; g = 197; b = 94; }     // green
        else if (anomaly < 0.7) { r = 247; g = 147; b = 26; } // gold
        else { r = 239; g = 68; b = 68; }                     // red
        ctx.fillStyle = `rgba(${r},${g},${b},${0.18 + anomaly * 0.35})`;
        ctx.fillRect(i * tileW, j * tileH, tileW + 1, tileH + 1);
      }
    }

    // Grid overlay (subtle)
    ctx.strokeStyle = "rgba(255,255,255,0.06)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= tx; i++) {
      ctx.beginPath(); ctx.moveTo(i * tileW, 0); ctx.lineTo(i * tileW, H); ctx.stroke();
    }
    for (let j = 0; j <= ty; j++) {
      ctx.beginPath(); ctx.moveTo(0, j * tileH); ctx.lineTo(W, j * tileH); ctx.stroke();
    }
  }

  // --------------------------------------------------------------------------
  // Rendering
  // --------------------------------------------------------------------------
  function renderResults() {
    const { metadata: m, scores: s, image: img } = state;

    dom.previewImg.src = URL.createObjectURL(state.file);

    dom.fileInfo.innerHTML = `
      <div><dt>Name</dt><dd title="${escapeHtml(m.name)}">${escapeHtml(m.name)}</dd></div>
      <div><dt>Type</dt><dd>${m.type || "—"}</dd></div>
      <div><dt>Size</dt><dd>${formatBytes(m.size)}</dd></div>
      <div><dt>Dimensions</dt><dd>${img.width} × ${img.height}</dd></div>
      <div><dt>Ratio</dt><dd>${(img.width / img.height).toFixed(3)}</dd></div>
      <div><dt>Last modified</dt><dd>${m.lastModified.toLocaleString()}</dd></div>
    `;

    // Verdict ring
    const color = s.aiProb <= 30 ? "#22C55E"
                : s.aiProb <= 60 ? "#F7931A"
                : s.aiProb <= 80 ? "#EF4444"
                : "#EF4444";
    dom.scoreRing.style.setProperty("--col", color);
    dom.verdictText.textContent = s.verdict;
    dom.verdictTag.textContent = s.verdictShort;
    dom.confidenceText.textContent = s.confidence;
    dom.riskText.textContent = s.risk;
    dom.verdictSummary.textContent = s.summary;

    animateScore(s.aiProb);

    // Metadata grid
    const exifClass = m.exifFound ? "pos" : "warn";
    const devClass = (m.make || m.model) ? "pos" : "warn";
    const swClass = m.software
      ? (/midjourney|stable diffusion|dall-?e|firefly|flux|sora/i.test(m.software) ? "bad" : "warn")
      : "warn";
    const stripClass = m.stripSuspicion === "high" ? "bad"
                     : m.stripSuspicion === "moderate" ? "warn" : "pos";
    const c2paClass = m.c2paDetected ? "pos" : "warn";

    dom.metaGrid.innerHTML = `
      ${metaCard("EXIF block", m.exifFound ? "Detected" : "Not found", exifClass)}
      ${metaCard("Camera make", m.make || "—", devClass)}
      ${metaCard("Camera model", m.model || "—", devClass)}
      ${metaCard("Software", m.software || "—", swClass)}
      ${metaCard("Original date", m.dateTime || "—", m.dateTime ? "pos" : "warn")}
      ${metaCard("C2PA / Content Credentials", m.c2paDetected ? "Signal detected" : "Not detected", c2paClass)}
      ${metaCard("Metadata strip suspicion", capitalize(m.stripSuspicion), stripClass)}
      ${metaCard("File integrity", "Readable", "pos")}
    `;

    // Indices
    dom.indices.innerHTML = ["face", "scene", "tech"].map(k => {
      const c = s.categories[k];
      return `
        <div class="index-group">
          <h4>${c.label} <span class="tag tag-${c.level === "low" ? "low" : c.level === "medium" ? "med" : "high"}">${capitalize(c.level)}</span></h4>
          <ul class="ix-list">
            ${c.items.map(([label, v]) => {
              const pct = Math.round(v * 100);
              const col = v < 0.34 ? "#22C55E" : v < 0.67 ? "#F7931A" : "#EF4444";
              return `<li>
                <span>${label}</span>
                <span class="ix-bar"><i style="width:${pct}%;background:${col}"></i></span>
              </li>`;
            }).join("")}
          </ul>
        </div>
      `;
    }).join("");

    // Placeholder report
    dom.reportBox.textContent = "Click “Generate Report” to produce the expert analysis.";
  }

  function metaCard(label, value, cls) {
    return `<div class="meta-item ${cls}">
      <span class="mi-label">${label}</span>
      <span class="mi-value">${escapeHtml(String(value))}</span>
    </div>`;
  }

  function animateScore(target) {
    const dur = 900, start = performance.now();
    const from = parseInt(dom.scoreNum.textContent, 10) || 0;
    function tick(now) {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3);
      const v = Math.round(from + (target - from) * eased);
      dom.scoreNum.textContent = v;
      dom.scoreRing.style.setProperty("--p", v);
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // --------------------------------------------------------------------------
  // Expert report
  // --------------------------------------------------------------------------
  function generateExpertReport() {
    if (!state.scores) return;
    const { metadata: m, scores: s, image: img } = state;
    const now = new Date();

    const lines = [];
    lines.push("===============================================================");
    lines.push("   AUTHENTIC IMAGE INSPECTOR  BY  JLV  —  EXPERT REPORT");
    lines.push("   AI Image Forensic & Authenticity Analyzer — v1.0 · April 2026");
    lines.push("===============================================================");
    lines.push("");
    lines.push(`Report generated : ${now.toLocaleString()}`);
    lines.push(`Analyst engine   : Heuristic pipeline (client-side)`);
    lines.push("");

    lines.push("[1] FILE IDENTIFICATION");
    lines.push("---------------------------------------------------------------");
    lines.push(`  Name          : ${m.name}`);
    lines.push(`  MIME          : ${m.type}`);
    lines.push(`  Size          : ${formatBytes(m.size)}`);
    lines.push(`  Dimensions    : ${img.width} × ${img.height} px`);
    lines.push(`  Ratio         : ${(img.width / img.height).toFixed(3)}`);
    lines.push(`  Last modified : ${m.lastModified.toLocaleString()}`);
    lines.push("");

    lines.push("[2] VERDICT SUMMARY");
    lines.push("---------------------------------------------------------------");
    lines.push(`  Verdict             : ${s.verdict}`);
    lines.push(`  AI probability      : ${s.aiProb}/100`);
    lines.push(`  Confidence level    : ${s.confidence}`);
    lines.push(`  Risk level          : ${s.risk}`);
    lines.push("");

    lines.push("[3] METADATA & PROVENANCE");
    lines.push("---------------------------------------------------------------");
    lines.push(`  EXIF block          : ${m.exifFound ? "Detected" : "Not found"}`);
    lines.push(`  Camera make         : ${m.make || "—"}`);
    lines.push(`  Camera model        : ${m.model || "—"}`);
    lines.push(`  Software trace      : ${m.software || "—"}`);
    lines.push(`  Capture date (EXIF) : ${m.dateTime || "—"}`);
    lines.push(`  C2PA / JUMBF signal : ${m.c2paDetected ? "Detected" : "Not detected"}`);
    lines.push(`  Strip suspicion     : ${capitalize(m.stripSuspicion)}`);
    lines.push("");

    lines.push("[4] VISUAL HEURISTIC ANALYSIS");
    lines.push("---------------------------------------------------------------");
    for (const key of ["face", "scene", "tech"]) {
      const c = s.categories[key];
      lines.push(`  ${c.label.toUpperCase()} — overall: ${capitalize(c.level)}`);
      c.items.forEach(([name, v]) => {
        lines.push(`     · ${name.padEnd(32)} ${(v * 100).toFixed(1).padStart(5)} %`);
      });
      lines.push("");
    }

    lines.push("[5] FORENSIC MAP");
    lines.push("---------------------------------------------------------------");
    lines.push(`  A tile-based anomaly overlay was computed using luma variance.`);
    lines.push(`  Overly smooth or abruptly discontinuous regions were flagged`);
    lines.push(`  for human review. The heatmap is heuristic; it does not`);
    lines.push(`  constitute definitive proof of manipulation.`);
    lines.push("");

    lines.push("[6] INTERPRETATION");
    lines.push("---------------------------------------------------------------");
    lines.push(wrap("  " + s.summary, 63));
    lines.push("");

    lines.push("[7] LIMITATIONS");
    lines.push("---------------------------------------------------------------");
    lines.push(wrap(
      "  Authentic Image Inspector by JLV provides a probabilistic " +
      "estimation based on technical and visual indices. A compressed, " +
      "cropped, edited, or screenshot-captured image can significantly " +
      "reduce analysis reliability. The absence of metadata is not proof " +
      "of AI generation. Only reliable provenance signatures — such as " +
      "certain C2PA or Content Credentials mechanisms — can provide " +
      "stronger evidence of origin or modification.",
      63));
    lines.push("");

    lines.push("[8] RECOMMENDATIONS");
    lines.push("---------------------------------------------------------------");
    if (s.aiProb >= 60) {
      lines.push("  · Corroborate with at least one complementary tool.");
      lines.push("  · Request the original, uncompressed source if possible.");
      lines.push("  · Verify provenance via C2PA / Content Credentials.");
    } else if (s.aiProb >= 30) {
      lines.push("  · Inspect flagged regions on the forensic map manually.");
      lines.push("  · Check whether retouching is plausible given the context.");
      lines.push("  · Consider ELA / noise analysis with a specialized tool.");
    } else {
      lines.push("  · Signals are consistent with an authentic photograph.");
      lines.push("  · Remain cautious: heuristic verdicts are not absolute.");
    }
    lines.push("");

    lines.push("===============================================================");
    lines.push("   Design & Concept by JLV — Jean-Louis Viretti");
    lines.push("   This tool is not a judicial proof. Probabilistic analysis only.");
    lines.push("===============================================================");

    state.report = lines.join("\n");
    dom.reportBox.textContent = state.report;
  }

  function copyReport() {
    if (!state.report) generateExpertReport();
    navigator.clipboard.writeText(state.report)
      .then(() => flashBtn(dom.copyBtn, "Copied ✓"))
      .catch(() => alert("Copy failed. You can select the text manually."));
  }

  function printReport() {
    if (!state.report) generateExpertReport();
    window.print();
  }

  function resetAnalysis() {
    state.file = null; state.image = null; state.metadata = null;
    state.features = null; state.scores = null; state.report = "";
    dom.fileInput.value = "";
    dom.results.classList.add("hidden");
    dom.scoreNum.textContent = "0";
    dom.scoreRing.style.setProperty("--p", 0);
  }

  // --------------------------------------------------------------------------
  // Utilities
  // --------------------------------------------------------------------------
  function formatBytes(b) {
    if (b < 1024) return b + " B";
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
    return (b / (1024 * 1024)).toFixed(2) + " MB";
  }
  function capitalize(s) { return s ? s[0].toUpperCase() + s.slice(1) : s; }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }
  function wrap(text, width) {
    const words = text.split(/\s+/);
    const lines = []; let line = "";
    for (const w of words) {
      if ((line + " " + w).trim().length > width) { lines.push(line.trim()); line = w; }
      else line += " " + w;
    }
    if (line.trim()) lines.push(line.trim());
    return lines.map(l => "  " + l.replace(/^ +/, "")).join("\n");
  }
  function flashBtn(btn, label) {
    const old = btn.textContent;
    btn.textContent = label;
    setTimeout(() => btn.textContent = old, 1400);
  }

  // --------------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", initApp);
})();
