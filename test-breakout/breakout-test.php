<?php
$search = $_GET['search'] ?? '';
?>
<!DOCTYPE html>
<html>
<head><title>Breakout XSS Test</title></head>
<body>
<h1>Search Results</h1>

<!-- JavaScript String Context - Single Quote -->
<script>
var searchTerm = '<?php echo addslashes($search); ?>';
document.write('<p>Search: ' + searchTerm + '</p>');
</script>

<!-- Template Literal Context -->
<script>
const query = `<?php echo $search; ?>`;
console.log('Query:', query);
</script>

<!-- JSON Context -->
<script>
var data = {"search": "<?php echo addslashes($search); ?>"};
console.log('Data:', data);
</script>

</body>
</html>