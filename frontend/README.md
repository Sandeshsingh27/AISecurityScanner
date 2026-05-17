# AI Security Scanner Frontend

React + TypeScript dashboard for exploring `SecurityScanReport` data from the backend API.

## Features

- Trigger scans from UI
- SonarQube-style risk overview cards and charts
- Findings table with severity/category/keyword/LLM filters
- Detailed finding inspector (evidence, taint chain, fix, suggested code)
- Dependency CVE and complexity hotspot tables
- JSON export and local request persistence

## Run

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

By default, Vite proxies `/api/*` to `http://localhost:8080`.

## Build

```powershell
cd frontend
npm run build
npm run preview
```

