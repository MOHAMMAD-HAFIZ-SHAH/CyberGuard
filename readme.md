# 🛡️ CyberGuard

### AI-Assisted Digital Forensics and Cyber Incident Investigation

CyberGuard is an AI-assisted digital forensics project designed to help investigate suspicious cyber activities by combining forensic disk-image examination, rule-based log analysis, local large language model (LLM) analysis, and automated report generation.

The system uses The Sleuth Kit (TSK) to inspect supported forensic images and extract available file contents. It uses Qwen 2.5 3B through Ollama to assist in interpreting extracted text artifacts and explaining their potential significance.

> Project status: Educational project under development. Findings require human verification and are not definitive proof of malicious activity.

## ✨ Features

- 🔍 Forensic image examination — supports `.E01`, `.dd`, `.img`, and `.raw` extensions.
- 💽 Filesystem inspection — uses The Sleuth Kit to inspect partition layouts, filesystem information, and file entries.
- 📄 File content extraction — extracts available file contents from supported forensic images.
- 🚨 Suspicious log analysis — applies rule-based checks to identify recognized suspicious patterns in supplied logs.
- 🧠 Local AI-assisted analysis — uses Qwen 2.5 3B through Ollama to interpret extracted text artifacts.
- 🕒 Investigation timeline — organizes available events chronologically.
- 🧩 Hypothesis generation — helps formulate possible explanations based on available findings.
- 📝 Investigation reporting — generates structured reports with findings, hypotheses, and limitations.
- 📥 Report export — downloads investigation reports as HTML documents.
- 🖥️ Web interface — provides an interactive React frontend connected to a Python backend.

## 🧰 Technology Stack

| Technology | Purpose |
| --- | --- |
| Python | Backend development and investigation logic |
| FastAPI | REST API and backend services |
| React | Frontend user interface |
| Vite | Frontend development and build tooling |
| The Sleuth Kit | Forensic filesystem inspection and file extraction |
| Ollama | Local language model runtime |
| Qwen 2.5 3B | AI-assisted artifact interpretation |
| HTML, CSS, JavaScript | User interface and report presentation |

## 🏗️ Architecture

```text
                    CyberGuard
                         |
                  React Frontend
                         |
                    FastAPI API
                         |
              Investigation Orchestrator
                         |
            +------------+------------+
            |                         |
      Log Analysis              Forensic Analysis
      Rule-Based                 The Sleuth Kit
            |                         |
            |                 Disk Image Examination
            |                         |
            |                  File Content Extraction
            |                         |
            +------------+------------+
                         |
                  Ollama / Qwen
               AI-Assisted Analysis
                         |
               Investigation Results
                         |
             Evidence, Timeline, Report
```

The orchestrator coordinates the investigation workflow. Depending on the supplied inputs, the system processes logs and/or forensic images, analyzes available evidence, and produces investigation results.

## 🔬 The Sleuth Kit Tools

CyberGuard integrates the following forensic utilities:

- `mmls` — examines the partition layout of a disk image.
- `fls` — lists filesystem entries, including deleted entries when identifiable.
- `fsstat` — displays filesystem information and layout details.
- `icat` — extracts file contents using a filesystem metadata address.

> Deleted-file recovery is not yet implemented as a complete automated workflow. Identifying a deleted entry does not guarantee that its contents can be recovered.

## 🤖 AI Model

CyberGuard uses Qwen 2.5 3B, running locally through Ollama.

The model assists with:

- Interpreting extracted text artifacts.
- Describing their potential forensic significance.
- Suggesting alternative explanations.
- Recommending additional verification steps.
- Supporting investigation report preparation.

The AI output is advisory. It may contain errors or unsupported interpretations and must be checked against the original evidence.

## ⚙️ Requirements

Before running CyberGuard, install or configure:

- Python 3.10 or a compatible version supported by your dependencies.
- Node.js and npm.
- Git.
- Ollama.
- The Sleuth Kit for Windows.
- The Qwen 2.5 3B model.

You should also have sufficient disk space and memory for the forensic images you intend to examine.

## 🚀 Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/MOHAMMAD-HAFIZ-SHAH/CyberGuard.git
cd CyberGuard
```

### 2. Set up the Python backend

Create and activate a virtual environment.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install backend dependencies:

```bash
pip install -r requirements.txt
```

If the repository does not contain `requirements.txt`, install the dependencies listed in the project's backend configuration instead.

### 3. Configure environment variables

Create a `.env` file in the project root and configure the path to your local Sleuth Kit binaries.

Example:

```env
TSK_BIN_DIR=G:\sleuthkit-4.14.0-win32\bin
```

Update this path to match your own installation.

> Never commit `.env` files, credentials, private evidence, or other sensitive data to GitHub.

### 4. Install and start Ollama

Install Ollama from: https://ollama.com/

Download the model:

```bash
ollama pull qwen2.5:3b
```

Verify that the model is available:

```bash
ollama list
```

Ensure Ollama is running before performing AI-assisted analysis.

### 5. Install frontend dependencies

Open a terminal in the frontend directory:

```bash
cd frontend
npm install
```

### 6. Start the backend

From the project root, with the virtual environment activated:

```bash
python -m uvicorn backend.app.main:app --reload
```

The API documentation should be available at:

- http://127.0.0.1:8000/docs

### 7. Start the frontend

In a separate terminal:

```bash
cd frontend
npm run dev
```

Open the local URL displayed by Vite, usually:

- http://localhost:5173/

## 🧪 How to Use CyberGuard

1. Open the CyberGuard web interface.
2. Enter an incident title and description.
3. Paste relevant log text into the log input field, if applicable.
4. Optionally upload a supported forensic disk image or provide an image path supported by the backend.
5. Submit the investigation.
6. Review the returned evidence, hypotheses, timeline, and report.
7. Download the HTML investigation report for further review.

Results depend on the available evidence, supported image formats, and implemented detection rules.

## 📁 Supported Forensic Image Formats

CyberGuard is configured to accept the following image extensions:

- `.E01`
- `.dd`
- `.img`
- `.raw`

An extension alone does not establish that a file is a valid forensic image. The actual image structure must be supported by the forensic tools.

## 🔐 Responsible Use

CyberGuard is intended for educational, authorized, and lawful digital forensic investigations.

- Obtain appropriate authorization before examining devices or data.
- Preserve original evidence and perform analysis on forensic copies.
- Avoid uploading sensitive evidence to public repositories.
- Validate AI-generated conclusions against the original evidence.
- Treat missing evidence as inconclusive rather than proof that an incident did not occur.
- Document limitations and uncertainty in investigation reports.

## 🛣️ Future Improvements

Potential future enhancements include:

- Automated deleted-file recovery using appropriate Sleuth Kit utilities.
- Expanded log-format support and detection rules.
- Improved correlation of events across multiple evidence sources.
- Stronger validation of AI-generated findings.
- Evidence integrity verification and hashing.
- More comprehensive test cases and automated tests.
- Additional forensic artifact parsers and report formats.

These are planned enhancements and should not be interpreted as currently implemented features.

## 🧭 Project Overview

CyberGuard combines a FastAPI backend with a React frontend to help analysts upload forensic images, inspect filesystem artifacts, run investigations, and review AI-generated findings.

The project is designed to support digital forensics and incident response workflows, including:

- Uploading forensic disk images (`.dd`, `.img`, `.raw`, `.e01`)
- Inspecting partitions and filesystem structure
- Reviewing deleted entries and extracted file content
- Running AI analysis over evidence text
- Tracking investigation steps across suspicious artifacts and timeline data

## 📦 Repository Structure

```text
Cyber Guard/
├── backend/
│   └── app/
│       ├── agents/
│       ├── api/
│       ├── config/
│       ├── core/
│       ├── database/
│       ├── graph/
│       ├── models/
│       ├── services/
│       ├── tools/
│       └── main.py
├── data/
│   ├── samples/
│   └── uploads/
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── vite.config.*
├── .gitignore
├── requirements.txt
├── readme.md
├── .env
└── README.md (optional if added later)
```

## 🧪 Main API Endpoints

- `GET /` — root status message
- `GET /api/health` — backend health
- `GET /api/health/dependencies` — dependency status
- `POST /api/ai/analyze` — analyze evidence text
- `POST /api/investigations` — create an investigation run
- `POST /api/forensics/upload` — upload forensic image
- `POST /api/forensics/partitions` — inspect forensic partitions
- `POST /api/forensics/filesystem` — inspect filesystem contents
- `POST /api/forensics/deleted` — list deleted entries
- `POST /api/forensics/extract` — extract file content

## 👨‍💻 Author

**Mohammad Hafiz Shah**

GitHub: [@MOHAMMAD-HAFIZ-SHAH](https://github.com/MOHAMMAD-HAFIZ-SHAH)

## 📜 Disclaimer

CyberGuard is an educational and investigative assistance project. It does not guarantee the detection of every cyberattack, the recovery of every deleted file, or the accuracy of every AI-generated conclusion. A qualified investigator should validate findings before taking investigative or operational action.

---

**Built to support digital forensic investigations through traditional forensic tools, rule-based analysis, and locally running AI.**
