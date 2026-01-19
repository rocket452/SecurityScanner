# How Scope Fetcher Fits Into Your Pipeline

Let me map this out visually, then explain each stage:

## 📊 New Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    STAGE 0: SCOPE DISCOVERY (NEW!)              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  HackerOne Scope Fetcher                                        │
│  ├─ Fetch program metadata                                      │
│  ├─ Extract all in-scope assets                                 │
│  ├─ Filter by: bounty-eligible, severity, type                  │
│  └─ Output: Refined target list                                 │
│                                                                 │
│  Input: Program handle (github, gitlab, etc)                    │
│  Output: [*.github.com, github.com/api/*, ...]                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              STAGE 1: SUBDOMAIN DISCOVERY (EXISTING)            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • Subfinder → Passive DNS enumeration                          │
│  • Amass     → Certificate transparency, web scraping           │
│  • Dedup     → Remove duplicate subdomains                      │
│                                                                 │
│  Input: example.com (or *.example.com from scope)               │
│  Output: Unique list of subdomains                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                STAGE 2: DOMAIN PROBING (EXISTING)               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • httpx → Test HTTP/HTTPS connectivity                         │
│  • Filter → Keep only live, accessible domains                  │
│                                                                 │
│  Input: Subdomain list                                          │
│  Output: [(url, status_code), ...]                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│            STAGE 3: VULNERABILITY SCANNING (EXISTING)           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────┐      ┌──────────────────────┐        │
│  │   ZAP SCANNER        │      │  TRADITIONAL SCANS   │        │
│  ├──────────────────────┤      ├──────────────────────┤        │
│  │ • Spider (crawl)     │      │ • Admin panels       │        │
│  │ • Passive scan       │      │ • Backup files       │        │
│  │ • Active scan (opt)  │      │ • XSS injection      │        │
│  │ • AJAX spider        │      │ • Storage exposure   │        │
│  └──────────────────────┘      │ • Directory fuzzing  │        │
│            │                   │ • Nuclei templates   │        │
│            │                   └──────────────────────┘        │
│            └──────────┬──────────────────┘                     │
│                       ↓                                        │
│              Merge all findings                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              STAGE 4: DEDUPLICATION (EXISTING)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • Fingerprint → Create MD5 hash from (type|desc|url)          │
│  • Detect      → Identify duplicate findings                    │
│  • Track       → Record which scanners found each issue         │
│                                                                 │
│  Input: All vulnerabilities from Stage 3                        │
│  Output: Deduplicated vulnerabilities with sources              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│        STAGE 5: REPORT GENERATION (EXISTING)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • Console   → Terminal output with severity levels             │
│  • JSON      → Machine-readable structured data                 │
│  • HTML      → Styled web report with severity colors           │
│  • Markdown  → Documentation-friendly format                    │
│  • CSV       → Spreadsheet-compatible tabular data              │
│                                                                 │
│  Input: Deduplicated findings                                   │
│  Output: Reports in multiple formats                            │
└─────────────────────────────────────────────────────────────────┘
```

## 🔄 How Stage 0 Changes Your Workflow

### BEFORE (Current Approach)
```bash
# User provides target manually
docker-compose run scanner example.com --zap

# Scanner has NO context about what's actually in scope
# Might scan out-of-scope assets
# Wastes time on areas program doesn't care about
```

### AFTER (With Scope Fetcher)
```bash
# User specifies HackerOne program instead
docker-compose run scanner \
  --fetch-scope \
  --h1-username myuser \
  --h1-token mytoken \
  --h1-program github \
  --scope-filter bounty-eligible

# Scope Fetcher → Retrieves EXACTLY what GitHub program cares about
# Filters to only bounty-eligible assets
# Passes refined targets to Stages 1-5
```

## 📍 Three Integration Modes

### Mode 1: Manual Target (Existing)
```
User Input: "example.com"
    ↓
[Skip Stage 0]
    ↓
Stage 1: Subdomain Discovery
    ↓
Stages 2-5: Normal pipeline
```

### Mode 2: Fetch Scope (New - Recommended)
```
User Input: "--h1-program github"
    ↓
Stage 0: HackerOne Scope Fetcher
    ├─ Fetch GitHub program scope
    ├─ Filter bounty-eligible assets
    └─ Extract targets: [*.github.com, github.com/api/v3, ...]
    ↓
Stage 1: Subdomain Discovery
    ├─ For each target from scope
    ├─ Run Subfinder/Amass
    └─ Only enumerate what's actually in scope
    ↓
Stages 2-5: Normal pipeline
```

### Mode 3: Scope File (Manual Review)
```
User Input: "--export-scope github github_scope.txt"
    ↓
Stage 0: HackerOne Scope Fetcher
    └─ Exports to file for review
    ↓
User reviews: "Does this match the program's scope?"
    ↓
User manually runs scanner with reviewed targets
```

## 🔧 Integration Points in Your Code

### Your Current scanner.py Flow:
```python
def main():
    # 1. Parse arguments (target = "example.com")
    args = parser.parse_args()
    
    # 2. Load config
    config = load_config('config.yaml')
    
    # 3. Initialize scanners
    subdomains = run_subdomain_discovery(args.target)
    
    # 4. Probe live hosts
    live_hosts = probe_hosts(subdomains)
    
    # 5. Vulnerability scanning
    vulns = run_vuln_scans(live_hosts)
    
    # 6. Deduplicate
    unique_vulns = dedup(vulns)
    
    # 7. Generate reports
    generate_reports(unique_vulns)
```

### With Scope Integration:
```python
def main():
    args = parser.parse_args()
    config = load_config('config.yaml')
    
    # ✅ NEW STAGE 0: Resolve target(s)
    if args.fetch_scope:
        # NEW: Get targets from HackerOne
        fetcher = HackerOneAPIScopeFetcher(args.h1_username, args.h1_token)
        program = fetcher.get_program_by_handle(args.h1_program)
        assets = ScopeFilter.filter_in_scope(program.assets)
        targets = ScopeFilter.extract_targets(assets)
        print(f"✓ Fetched {len(targets)} targets from HackerOne")
    else:
        # EXISTING: User provided target
        targets = [args.target]
    
    # ✅ EXISTING PIPELINE (Stages 1-5)
    for target in targets:  # Now we might have multiple targets!
        print(f"\n[*] Scanning: {target}")
        
        # Stage 1
        subdomains = run_subdomain_discovery(target)
        
        # Stage 2
        live_hosts = probe_hosts(subdomains)
        
        # Stage 3
        vulns = run_vuln_scans(live_hosts)
        
        # Stage 4
        unique_vulns = dedup(vulns)
    
    # Stage 5: Generate combined reports for all targets
    generate_reports(all_unique_vulns)
```

## 💡 Concrete Example

### Before Scope Fetcher:
```bash
$ docker-compose run scanner github.com --zap

# Scanner assumes user wants to scan just "github.com"
# Might miss: api.github.com, ghe.github.com, other subdomains
# Wastes time on: out-of-scope internal services
# Result: Incomplete scanning, missed opportunities
```

### After Scope Fetcher:
```bash
$ docker-compose run scanner \
    --fetch-scope \
    --h1-username alice \
    --h1-token xxxxx \
    --h1-program github

# Stage 0 fetches GitHub's HackerOne program scope:
# ├─ *.github.com (WILDCARD - huge!)
# ├─ github.githubassets.com
# ├─ github.io
# ├─ github.community
# ├─ github.blog
# └─ [10 more assets...]
#
# Filters to bounty-eligible only (removes out-of-scope)
# 
# Then Stages 1-5 scan EXACTLY what GitHub wants scanned
# Result: Focused, efficient scanning aligned with program scope
```

## 🎯 Key Benefits of This Integration

| Aspect | Before | After |
|--------|--------|-------|
| Target Discovery | Manual (user guesses) | Automated (API-driven) |
| Scope Accuracy | Incomplete | Complete (official program scope) |
| Out-of-Scope Waste | High (scans wrong things) | Low (filtered) |
| Multiple Assets | Single target only | Handles wildcards, multiple domains |
| Time to Scan | User researches scope first | Immediate (program fetched) |
| Competitive Edge | Standard approach | First-mover (scan immediately when program launches) |

## 📋 Your Pipeline Now Looks Like:

```
┌─────────────────────────────────────────────────┐
│  User chooses: Manual or HackerOne program?    │
└─────────────────────────────────────────────────┘
         │                          │
         ↓ (Manual)                 ↓ (HackerOne)
    args.target             Stage 0: Fetch Scope
         │                          │
         └──────────────┬───────────┘
                        ↓
                    target(s)
                        ↓
        ┌───────────────────────────────┐
        │  Stage 1: Subdomain Discovery │
        └───────────────────────────────┘
                        ↓
        ┌───────────────────────────────┐
        │   Stage 2: Domain Probing     │
        └───────────────────────────────┘
                        ↓
        ┌───────────────────────────────┐
        │  Stage 3: Vuln Scanning       │
        └───────────────────────────────┘
                        ↓
        ┌───────────────────────────────┐
        │    Stage 4: Deduplication     │
        └───────────────────────────────┘
                        ↓
        ┌───────────────────────────────┐
        │   Stage 5: Report Generation  │
        └───────────────────────────────┘
```

## ✅ Next Steps

1. Add `hackerone_scope_fetcher.py` to your `scanners/` directory
2. Update `scanner.py` to accept `--fetch-scope`, `--h1-username`, `--h1-token`, `--h1-program` arguments
3. Modify the main scanning loop to handle multiple targets (if scope returns multiple assets)
4. Test it:

```bash
docker-compose run scanner \
  --fetch-scope \
  --h1-username your_username \
  --h1-token your_token \
  --h1-program github \
  --zap
```

## Why This Integration is Perfect

This is the perfect addition to your existing pipeline because:

✅ Doesn't replace any existing stages  
✅ Adds intelligent target selection BEFORE Stage 1  
✅ Makes your scanner program-aware (huge competitive edge)  
✅ Enables automated hunting (run scheduler to scan new programs)
