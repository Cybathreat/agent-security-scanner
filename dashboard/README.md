# Singularity Dashboard

Web dashboard for the Singularity security scanner.

## Tech Stack

- **Frontend:** Next.js 16, React 19, Tailwind CSS 4, React Query 5, React Flow
- **Backend:** FastAPI, aiosqlite, WebSocket
- **Language:** TypeScript, Python 3.10+

## Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

The dashboard runs on `http://localhost:3000` and connects to the FastAPI backend on `http://localhost:8000`.

## Pages

| Page | Description |
|------|-------------|
| `/` | Dashboard — KPI cards, recent scans, recent findings |
| `/scans` | New scan form — target, module selection, quality gate config |
| `/scans/[id]` | Scan detail — findings, severity breakdown, live progress, quality gate result |
| `/findings` | Finding explorer — filter by severity/category, search, annotate |
| `/comparison` | Scan comparison — side-by-side diff with severity breakdown |
| `/attack-surface` | Attack surface map — interactive React Flow graph |
| `/replay` | Replay console — re-run findings with editable parameters |
| `/reports` | Report builder — drag-and-drop sections, PDF/HTML/JSON export |
| `/settings` | Settings — quality gate config, module toggles, CI/CD snippets |

## Backend API

Start the backend separately:

```bash
# From the project root
SINGULARITY_DATA_DIR=/tmp/ass-data uvicorn singularity.web.app:create_app --factory --host 0.0.0.0 --port 8000
```

API endpoints are available at `http://localhost:8000/api/`.