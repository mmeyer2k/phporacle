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

function _blocks($data)
{
    $data = str_split($data);
    $blocks = array_chunk($data, 32);
    foreach ($blocks as $b) {
        echo bin2hex(implode($b)) . PHP_EOL;
    }
}

// Create a key to use for encryption operations...
$key = str_repeat('0', 32);

// Create the secret that we want to crack...
$secret = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHAAAABBBBCCCCDDDD';

_out('Secret (plaintext): ' . $secret);

$encrypted = badCrypt::encrypt($secret, $key);

_out('Secret: (encrypted as hex): ' . PHP_EOL . _blocks($encrypted));

_out('# of blocks in cypher text: ' . (strlen($encrypted) / 32));

for ($x = 1; $x <= 32; $x++) {
    for ($i = 0; $i <= 255; $i++) {

        $nth = 32 + $x;

        $test = $encrypted;

        $test[strlen($encrypted) - $nth] = chr($i);

        $orig_byte = bin2hex($encrypted[strlen($encrypted) - $nth]);

        #_out("orig: $orig_byte  new: " . bin2hex(chr($i)));

        if ($orig_byte == bin2hex(chr($i))) {
            continue;
        }

        $bx = str_pad($x, 2, '0', STR_PAD_LEFT);
        $out = "byte #$bx:" . bin2hex(chr($i)) . ' : ';

        try {
            // Check padding...
            $decrypted = badCrypt::decrypt($test, $key);
            $out .= bin2hex($decrypted);
        } catch (Exception $ex) {
            continue;
        }
        _out($out);
    }
}

#_out('Secret: (decrypted as hex): ' . $decrypted);
