<?php
/*
 * This is a PHP POC of a padding oracle attack. It works with local exceptions
 * instead of interacting with a server for the sake of simplicity.
 * 
 * @link https://blog.skullsecurity.org/2013/a-padding-oracle-example/comment-page-1#comment-39128
 */

/*
 * Include a few neutered encryption libraries
 */
require 'badCrypt.php';
require 'badPad.php';
require 'badHash.php';

// Create a key to use for encryption operations...
$key = str_repeat('A', 32);

// Create the secret that we want to crack...
$secret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbcc';

$encrypted = badCrypt::encrypt($secret, $key);

$blocks = str_split($encrypted, 32);
$count = count($blocks);
$head = $blocks[0] . $blocks[1];
for ($nblock = $count - 1; $nblock > 2; $nblock--) {
    $badblock = str_repeat("\xFF", 32);
    $secretblock = array();
    for ($nbyte = 31; $nbyte >= 0; $nbyte--) {
        for ($tbyte = 0; $tbyte < 256; $tbyte++) {
            $badblock[$nbyte] = chr($tbyte);
            
            try {
                $d = badCrypt::decrypt($head . $badblock . $blocks[$nblock], $key);
            } catch (Exception $ex) {
                continue;
            }

            $pos = 32 - $nbyte;

            $derp = ord($blocks[$nblock - 1][$nbyte]);
            $stolen = $pos ^ $derp ^ $tbyte;
            
            $secretblock[$nbyte] = $stolen;

            // Loop through the previous bytes of the bad block to fix each
            // byte for the next round.
            for ($fixpos = 31; $fixpos >= $nbyte; $fixpos--) {
                $new = ($pos + 1) ^ $secretblock[$fixpos] ^ ord($blocks[$nblock - 1][$fixpos]);
                $badblock[$fixpos] = chr($new);
            }

            break;
        }
    }
    
    echo bin2hex(implode($secretblock));
    
}
