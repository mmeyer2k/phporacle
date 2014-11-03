<?php

header('Content-Type: text/plain');

// Include bad encryption libraries
require 'badCrypt.php';
require 'badPad.php';
require 'badHash.php';

// Create a key to use for encryption operations...
$key = str_repeat('A', 32);

// Create the secret that we want to crack...
$secret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbb';

$encrypted = badCrypt::encrypt($secret, $key);

$blocks = str_split($encrypted, 32);
$count = count($blocks);
$head = $blocks[0] . $blocks[1];
$padbytes = null;
for ($nblock = $count - 1; $nblock > 2; $nblock--) {
    $badblock = str_repeat("\xFF", 32);
    for ($nbyte = 31; $nbyte >= 0; $nbyte--) {
        for ($tbyte = 0; $tbyte < 256; $tbyte++) {
            $badblock[$nbyte] = chr($tbyte);

            echo "blk# $nblock | byte# $nbyte | byteval $tbyte : ";

            try {
                badCrypt::decrypt($head . $badblock . $blocks[$nblock], $key);
            } catch (Exception $ex) {
                echo 'BAD ' . bin2hex($badblock) . PHP_EOL;
                continue;
            }

            $pos = 32 - $nbyte;

            $derp = ord($blocks[$nblock - 1][$nbyte]);
            $boop = $pos ^ $derp ^ $tbyte;

            if ($padbytes === null) {
                $padbytes = $boop;
            }

            echo "GOOD [stolen: $boop !]" . bin2hex($badblock) . PHP_EOL;

            // Fix char
            // count processed bytes and adjust historic bytes
            for ($fixpos = 31; $fixpos >= $nbyte; $fixpos--) {
                $new = ($pos + 1) ^ $padbytes ^ ord($blocks[$nblock - 1][$fixpos]);
                $badblock[$fixpos] = chr($new);
            }

            break;
        }
    }
}
