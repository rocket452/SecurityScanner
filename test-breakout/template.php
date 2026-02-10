<?php
$input = $_GET['q'] ?? '';
?>
<script>
const msg = `User typed: <?php echo $input; ?>`;
console.log(msg);
</script>