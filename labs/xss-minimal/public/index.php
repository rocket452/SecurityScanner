<?php
$q = $_GET['q'] ?? '';
$safe = htmlspecialchars($q, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Minimal XSS Lab</title>
</head>
<body>
  <h1>Minimal XSS Lab</h1>

  <h2>Reflected (vulnerable)</h2>
  <p>Search: <?php echo $q; ?></p>

  <h2>Reflected (escaped)</h2>
  <p>Search (safe): <?php echo $safe; ?></p>

  <h2>Attribute (vulnerable)</h2>
  <img src="/assets/logo.png" alt="<?php echo $q; ?>">

  <h2>JavaScript string (vulnerable)</h2>
  <script>
    const query = '<?php echo $q; ?>';
    document.write('<p>JS query: ' + query + '</p>');
  </script>
</body>
</html>
