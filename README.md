# PromptGuard

PromptGuard is a browser-based prototype for detecting sensitive information before an AI prompt is submitted.

## Demo capabilities

- Email detection
- Phone-number detection
- Card-number pattern detection
- Credential/API-key pattern detection
- Simple name heuristic for demo input
- Low / Medium / High risk indicator
- One-click redaction
- Safe-to-send output

## Run locally

No build step is required.

1. Download or clone the repository.
2. Open `index.html` in a browser.

For GitHub Pages, enable Pages from:
**Settings → Pages → Deploy from branch → main → /(root)**

## Important prototype note

This version uses browser-side regular expressions and lightweight heuristics so it can run as a static demo. It does **not** implement a full spaCy NER backend yet.

## Project

SYNK SOLVE • AI-02 — Personal Data Exposure Detector

GitHub:
https://github.com/Swayam5128/PromptGuard
