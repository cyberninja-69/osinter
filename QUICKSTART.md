# QUICKSTART — osinter (5 minutes)

## 1. Install

```bash
cd osinter_project
pip install -r requirements.txt
```

Optional: copy environment template

```bash
cp .env.example .env
```

## 2. Run a first scan

```bash
python -m osinter.cli scan 8.8.8.8
python -m osinter.cli scan example.com
python -m osinter.cli scan github
python -m osinter.cli scan user@example.com
```

## 3. Batch scan

Create `targets.txt`:

```text
8.8.8.8
example.com
github
user@example.com
```

Run:

```bash
python -m osinter.cli scan -f targets.txt --threads 10
```

## 4. Export results

```bash
python -m osinter.cli scan example.com --export-json results.json --export-csv results.csv
```

## 5. List modules

```bash
python -m osinter.cli modules
```

## Notes

- Some modules require internet access.
- `haveibeenpwned` requires `HIBP_API_KEY` in `.env`.
- Always get permission before scanning targets and respect ToS/rate limits.
