<?php
$where = php_sapi_name();
if ($where === false || $where !== 'cli') { exit(0); }

function algo_length ($algo) {
    switch ($algo) {
        default: return 0;
        case 'sha256': return 256;
        case 'sha384': return 384;
        case 'sha512': return 512;
    }
}

function algo_js_name ($algo) {
    switch($algo) {
        case 'sha256': return 'SHA-256';
        case 'sha384': return 'SHA-384';
        case 'sha512': return 'SHA-512';
    }
}

if (!isset($argv[1]) || empty($argv[1])) {
    echo "Derive a key to be used with javascript Web Crypto API PBKDF2 with HMAC algorithm.\n";
    echo 'Usage: ' . $argv[0] . ' password [algo]' ."\n";
    echo "\tpassword: <string> Password to be derived\n";
    echo "\talgo: <optional,string> One of sha256, sha384, sha512\n\n";
    echo "\tResult : <iterations> <random salt (base64)> <algo name (web crypto)> <derived key>\n";
    exit(0);
}

$algo = 'sha384';
if (isset($argv[2]) && !empty($argv[2])) {
    $algo = strtolower($argv[2]);
}
if (algo_length($algo) === 0) { $algo = 'sha384'; }

$salt = random_bytes(algo_length($algo) / 8);
$iter = random_int(100000, 200000);
$result = hash_pbkdf2($algo, $argv[1], $salt, $iter, 0, true);

echo $iter . ' ' . base64_encode($salt) . ' ' . algo_js_name($algo) . ' ' . base64_encode($result) . "\n";