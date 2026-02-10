<?php
/**
 * Vulnerable XSS Test Page for Breakout Detection Testing
 * 
 * WARNING: This file is INTENTIONALLY VULNERABLE for testing purposes only!
 * DO NOT deploy this to a production server!
 * 
 * This test page demonstrates various XSS injection contexts that the
 * breakout XSS detector should identify:
 * 
 * 1. HTML text context
 * 2. HTML attribute contexts (single quote, double quote, unquoted)
 * 3. JavaScript string contexts
 * 4. JSON data contexts
 * 5. Template literal contexts
 * 6. Event handler contexts
 * 7. URL contexts
 * 
 * Usage:
 *   docker-compose run scanner "host.docker.internal:8888/test-pages/breakout-test-vulnerable.php?search=test" --xss-deep -f html
 */

// Get user input (intentionally no sanitization for testing)
$search = $_GET['search'] ?? '';
$name = $_GET['name'] ?? '';
$id = $_GET['id'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Breakout Test Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }
        .test-section {
            margin: 30px 0;
            padding: 20px;
            background: #f9f9f9;
            border-left: 4px solid #2196F3;
        }
        .test-section h2 {
            color: #2196F3;
            margin-top: 0;
        }
        .code {
            background: #263238;
            color: #aed581;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        .warning {
            background: #fff3cd;
            color: #856404;
            padding: 15px;
            border-left: 4px solid #ffc107;
            margin: 20px 0;
        }
        input[type="text"] {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 300px;
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 XSS Breakout Detection Test Page</h1>
        
        <div class="warning">
            <strong>⚠️ WARNING:</strong> This page is intentionally vulnerable for testing purposes only!
            Do not deploy to production servers.
        </div>

        <p><strong>Current Parameters:</strong></p>
        <ul>
            <li>search: <?php echo htmlspecialchars($search); ?> (safe display)</li>
            <li>name: <?php echo htmlspecialchars($name); ?> (safe display)</li>
            <li>id: <?php echo htmlspecialchars($id); ?> (safe display)</li>
        </ul>

        <!-- Test 1: HTML Text Context -->
        <div class="test-section">
            <h2>Test 1: HTML Text Context</h2>
            <p>Your search: <?php echo $search; ?></p>
            <div class="code">
                &lt;p&gt;Your search: &lt;?php echo $search; ?&gt;&lt;/p&gt;
            </div>
            <p><strong>Expected Payload:</strong> <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
        </div>

        <!-- Test 2: HTML Attribute - Double Quotes -->
        <div class="test-section">
            <h2>Test 2: HTML Attribute Context (Double Quotes)</h2>
            <input type="text" value="<?php echo $search; ?>" placeholder="Search...">
            <div class="code">
                &lt;input type="text" value="&lt;?php echo $search; ?&gt;"&gt;
            </div>
            <p><strong>Expected Payload:</strong> <code>"&gt;&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
        </div>

        <!-- Test 3: HTML Attribute - Single Quotes -->
        <div class="test-section">
            <h2>Test 3: HTML Attribute Context (Single Quotes)</h2>
            <input type='text' value='<?php echo $name; ?>' placeholder='Name...'>
            <div class="code">
                &lt;input type='text' value='&lt;?php echo $name; ?&gt;'&gt;
            </div>
            <p><strong>Expected Payload:</strong> <code>'&gt;&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
        </div>

        <!-- Test 4: JavaScript String Context -->
        <div class="test-section">
            <h2>Test 4: JavaScript String Context</h2>
            <script>
                var searchQuery = "<?php echo $search; ?>";
                console.log("Search query: " + searchQuery);
            </script>
            <div class="code">
                var searchQuery = "&lt;?php echo $search; ?&gt;";
            </div>
            <p><strong>Expected Payload:</strong> <code>";alert(1);//</code></p>
        </div>

        <!-- Test 5: JSON Context -->
        <div class="test-section">
            <h2>Test 5: JSON Context</h2>
            <script>
                var userData = {
                    "search": "<?php echo $search; ?>",
                    "name": "<?php echo $name; ?>"
                };
                console.log(userData);
            </script>
            <div class="code">
                var userData = {"search": "&lt;?php echo $search; ?&gt;"};
            </div>
            <p><strong>Expected Payload:</strong> <code>","xss":alert(1),"x":"</code></p>
        </div>

        <!-- Test 6: Template Literal Context -->
        <div class="test-section">
            <h2>Test 6: Template Literal Context</h2>
            <script>
                var message = `Search results for: <?php echo $search; ?>`;
                console.log(message);
            </script>
            <div class="code">
                var message = `Search results for: &lt;?php echo $search; ?&gt;`;
            </div>
            <p><strong>Expected Payload:</strong> <code>${alert(1)}</code></p>
        </div>

        <!-- Test 7: Event Handler Context -->
        <div class="test-section">
            <h2>Test 7: Event Handler Context</h2>
            <button onclick="search('<?php echo $search; ?>')">Search</button>
            <div class="code">
                &lt;button onclick="search('&lt;?php echo $search; ?&gt;')"&gt;
            </div>
            <p><strong>Expected Payload:</strong> <code>');alert(1);//</code></p>
        </div>

        <!-- Test 8: URL Context -->
        <div class="test-section">
            <h2>Test 8: URL/HREF Context</h2>
            <a href="https://example.com/?redirect=<?php echo $search; ?>">Click here</a>
            <div class="code">
                &lt;a href="https://example.com/?redirect=&lt;?php echo $search; ?&gt;"&gt;
            </div>
            <p><strong>Expected Payload:</strong> <code>javascript:alert(1)</code></p>
        </div>

        <!-- Test 9: Multiple Encoding Layers -->
        <div class="test-section">
            <h2>Test 9: URL Encoded Context</h2>
            <?php 
            $encodedSearch = urlencode($search);
            ?>
            <input type="text" value="<?php echo $encodedSearch; ?>">
            <div class="code">
                $encodedSearch = urlencode($search);<br>
                &lt;input value="&lt;?php echo $encodedSearch; ?&gt;"&gt;
            </div>
            <p><strong>Note:</strong> This tests URL encoding detection</p>
        </div>

        <!-- Test 10: HTML Entity Encoded -->
        <div class="test-section">
            <h2>Test 10: Partially HTML Entity Encoded</h2>
            <?php 
            // Simulate partial encoding (common WAF bypass scenario)
            $partialEncoded = str_replace(['<', '>'], ['&lt;', '&gt;'], $search);
            ?>
            <p>Result: <?php echo $partialEncoded; ?></p>
            <div class="code">
                $partialEncoded = str_replace(['&lt;', '&gt;'], ['&amp;lt;', '&amp;gt;'], $search);<br>
                &lt;p&gt;&lt;?php echo $partialEncoded; ?&gt;&lt;/p&gt;
            </div>
            <p><strong>Note:</strong> Tests HTML entity encoding detection</p>
        </div>

        <!-- Testing Instructions -->
        <div class="test-section">
            <h2>🧪 How to Test</h2>
            <p>Run the security scanner with the following command:</p>
            <div class="code">
                docker-compose run scanner "host.docker.internal:8888/test-pages/breakout-test-vulnerable.php?search=test&name=john&id=123" --xss-deep -f html
            </div>
            
            <p><strong>Expected Results:</strong></p>
            <ul>
                <li>✅ Detect 8-10 XSS vulnerabilities</li>
                <li>✅ Identify correct context for each (HTML attribute, JavaScript, JSON, etc.)</li>
                <li>✅ Detect encoding layers (URL encoding, HTML entities)</li>
                <li>✅ Generate context-specific payloads</li>
                <li>✅ Provide code snippets showing injection point</li>
                <li>✅ Calculate CVSS scores</li>
                <li>✅ Include exploitation details in HTML report</li>
            </ul>
        </div>

        <div class="warning">
            <strong>🛡️ Security Note:</strong> This page demonstrates common XSS vulnerabilities.
            In production, always use proper output encoding:
            <ul>
                <li>HTML context: <code>htmlspecialchars($var, ENT_QUOTES, 'UTF-8')</code></li>
                <li>JavaScript context: <code>json_encode($var, JSON_HEX_TAG | JSON_HEX_AMP)</code></li>
                <li>URL context: <code>urlencode($var)</code></li>
                <li>Attribute context: <code>htmlspecialchars($var, ENT_QUOTES)</code></li>
            </ul>
        </div>
    </div>

    <script>
        // Demo function for event handler test
        function search(query) {
            console.log('Searching for: ' + query);
        }
    </script>
</body>
</html>
