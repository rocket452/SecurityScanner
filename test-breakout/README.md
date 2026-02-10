# Breakout XSS Test Files

These PHP files are designed to test the enhanced breakout XSS detection capabilities of SecurityScanner.

## Setup

### Quick Start (Docker CLI)

```bash
# From the SecurityScanner root directory
cd test-breakout

# Run PHP server in Docker
docker run -d --name php-test -p 8080:80 -v "$(pwd):/var/www/html" php:8.2-apache

# Go back to SecurityScanner root
cd ..

# Scan the test page
docker-compose run scanner "http://host.docker.internal:8080/breakout-test.php?search=test" --xss-deep --skip-nuclei -f html

# Cleanup when done
docker stop php-test
docker rm php-test
```

## Test Files

### breakout-test.php
Comprehensive test page with multiple contexts:
- JavaScript string with single quotes
- Template literal context
- JSON context

**Test URL:**
```
http://host.docker.internal:8080/breakout-test.php?search=test
```

**Expected Detections:**
- ✅ JavaScript String Context (js_string_single)
- ✅ Template Literal Context (js_template_literal)
- ✅ JSON Context (json_context)

### js-string.php
Tests JavaScript string context with `addslashes()` protection.

**Test URL:**
```
http://host.docker.internal:8080/js-string.php?q=test
```

**Expected Detection:**
- ✅ Payload: `';alert(1);//`

### template.php
Tests template literal injection.

**Test URL:**
```
http://host.docker.internal:8080/template.php?q=test
```

**Expected Detection:**
- ✅ Payload: `${alert(1)}`

### json.php
Tests JSON context breakout.

**Test URL:**
```
http://host.docker.internal:8080/json.php?q=test
```

**Expected Detection:**
- ✅ Payload: `"};alert(1);//`

## Manual Testing

You can test the vulnerabilities manually in your browser:

```bash
# JavaScript String - simple payload blocked
http://localhost:8080/js-string.php?q=<script>alert(1)</script>

# But breakout payload works
http://localhost:8080/js-string.php?q=%27;alert(1);//

# Template literal - simple HTML blocked
http://localhost:8080/template.php?q=<script>alert(1)</script>

# But template injection works
http://localhost:8080/template.php?q=${alert(1)}
```

## Scan All Test Files

```bash
# Scan each test individually
docker-compose run scanner "http://host.docker.internal:8080/js-string.php?q=test" --xss-deep --skip-nuclei -f html
docker-compose run scanner "http://host.docker.internal:8080/template.php?q=test" --xss-deep --skip-nuclei -f html
docker-compose run scanner "http://host.docker.internal:8080/json.php?q=test" --xss-deep --skip-nuclei -f html
docker-compose run scanner "http://host.docker.internal:8080/breakout-test.php?search=test" --xss-deep --skip-nuclei -f html
```

## Troubleshooting

### PHP Container Not Accessible

```bash
# Check if container is running
docker ps | grep php-test

# View logs
docker logs php-test

# Restart container
docker restart php-test
```

### Test PHP Server Directly

```bash
# From your host machine
curl http://localhost:8080/breakout-test.php?search=test
```

### Scanner Can't Reach PHP Server

Make sure you're using `host.docker.internal` instead of `localhost` when running from the scanner container.

## Notes

- These files intentionally contain XSS vulnerabilities for testing purposes
- Never deploy these files to production environments
- Use only in isolated testing environments
- The `addslashes()` function demonstrates why context-aware detection is necessary
