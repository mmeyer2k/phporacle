<?php

// Include bad encryption libraries
require 'badCrypt.php';
require 'badPad.php';
require 'badHash.php';

function _out($msg, $eol = true)
{
    echo $msg;
    if ($eol) {
        echo PHP_EOL;
    }
}

// Create a key to use for encryption operations...
$key = str_repeat('0', 32);

// Create the secret that we want to crack...
$secret = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH';

_out('Secret (plaintext): ' . $secret);

$encrypted = badCrypt::encrypt($secret, $key);

_out('Secret: (encrypted as hex): ' . bin2hex($encrypted));

_out('# of blocks in cypher text: ' . (strlen($encrypted) / 32));
