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
// The first 32 byte block will always be undecryptable
//         |--- will decrypt to garbage --|
$secret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXabcdefghijklmnopqrstuvwxyz';
$encrypted = badCrypt::encrypt($secret, $key);

$blocks = str_split($encrypted, 32);

// Count the numner of blocks
// The first 2 blocks are always IV + checksum
$count = count($blocks);
$head = $blocks[0] . $blocks[1];

// Create a place holder array for decrypted blocks
$secretblocks = array();

// Begin looping through the blocks of cypher text in reverse order
// Ignore the first 2 blocks, because those are the IV and check sum
// used by the encryption library.
for ($nblock = $count - 1; $nblock > 1; $nblock--) {

    // Create a single 32 byte block of FF bytes
    $badblock = str_repeat("\xFF", 32);

    // Secret block will hold our stolen information
    $secretblock = array();

    // Lets start decoding from the last byte first
    for ($nbyte = 31; $nbyte >= 0; $nbyte--) {

        // Begin looping through every possible value for the byte
        for ($tbyte = 0; $tbyte < 256; $tbyte++) {
            $badblock[$nbyte] = chr($tbyte);

            // Here is where the magic happens...
            // Bad padding will result in an exception which is caught and skipped
            try {
                $d = badCrypt::decrypt($head . $badblock . $blocks[$nblock], $key);
            } catch (Exception $ex) {
                continue;
            }

            // Create a position pointer which is an offset from the end of the
            // block of the byte we are operating on. This integer corresponds
            // to the amount of padding that MUST be being used for the oracle attack
            $padlen = 32 - $nbyte;

            // Here we will grab the byte of cypher text in the block before our
            // target block.
            $prev = ord($blocks[$nblock - 1][$nbyte]);

            // Decrypt the stolen byte
            $stolen = $padlen ^ $prev ^ $tbyte;

            // Add stolen byte to the block of secrets
            $secretblock[$nbyte] = $stolen;

            // Loop through the previous bytes of the bad block to fix each
            // byte for the next round.
            for ($fixpos = 31; $fixpos >= $nbyte; $fixpos--) {
                $new = ($padlen + 1) ^ $secretblock[$fixpos] ^ ord($blocks[$nblock - 1][$fixpos]);
                $badblock[$fixpos] = chr($new);
            }

            break;
        }
    }

    $secretblocks[$nblock] = $secretblock;
}


// Reverse the secret blocks
$secretblocks = array_reverse($secretblocks);

// output bytes in the correct order
foreach ($secretblocks as $block) {
    for ($byte = 0; $byte < 32; $byte++) {
        echo chr($block[$byte]);
    }
}
