<?php
$input = $_GET['q'] ?? '';
?>
<script>
var userInput = '<?php echo addslashes($input); ?>';
alert('Search: ' + userInput);
</script>