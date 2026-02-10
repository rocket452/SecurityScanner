<?php
$input = $_GET['q'] ?? '';
header('Content-Type: application/json');
echo json_encode(['query' => $input]);
?>