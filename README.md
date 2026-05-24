# DSPM Project

DSPM prototype for discovering sensitive files on an AD/SMB file server, scoring risk, and preparing DLP rule recommendations.

## Run

```powershell
python main.py serve --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

If no SMB server is provided, the scanner uses `test_data` as sample data.

## CLI scan

```powershell
python main.py scan --local-path test_data --output report.json
```
