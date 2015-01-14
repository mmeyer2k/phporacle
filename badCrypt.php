<?php

/**
 * badCrypt.php - A very bad encryption library. Modified from dopeCode/dcrypt.
 * 
 * PHP version 5
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/dopecode/dcrypt
 */
# namespace dopeCode\dcrypt;

/**
 * Symmetric AES encryption implementation wrapper functions.
 * 
 * Features:
 *     - PKCS #7 padding of messages
 *     - random IB selection
 *     - checksum validation with SHA256 HMAC
 *     - use of output buffering to keep memory consumption low
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/dopecode/dcrypt
 */
class badCrypt
{

    /**
     * Create a message authentication checksum.
     * 
     * @param string $cyphertext Cyphertext that needs a check sum.
     * @param string $iv         Initialization vector.
     * @param string $key        Encryption key that will act as an HMAC 
     *                           verification signature.
     * 
     * @return string
     */
    private static function _chksumcreate($cyphertext, $iv, $key)
    {
        return Hash::ihmac($cyphertext, $iv ^ $key, 5);
    }

    /**
     * Decrypt data that was generated with the aes::encrypt() method.
     * 
     * @param string $cyphertext Cypher text to decrypt.
     * @param mixed  $key        Key that should be used to decrypt input data.
     * 
     * @return string 
     */
    public static function decrypt($cyphertext, $key)
    {

        // Silently abort if cypher text is null is not long enough
        if ($cyphertext === null || strlen($cyphertext) < 64) {
            return false;
        }

        // Get the normalized decryption key
        $key = self::_key($key);

        // Find the IV at the beginning of the cypher text
        $iv = substr($cyphertext, 0, 32);

        // Gather the checksum portion of the cypher text.
        $chksum = substr($cyphertext, 32, 32);

        // Get the cyphertext from the input blob.
        $cyphertext = substr($cyphertext, 64);

        // If chksum could not be verified return false.
        /*
         * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
         * Checksum validation has been disabled...
         * DO NOT USE THIS LIBRARY EVER
         * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
         */
        # if (self::_chksumcreate($cyphertext, $iv, $key) !== $chksum) {
        #     return false;
        # }
        // Decrypt the cyphertext data.
        $plaintext = mcrypt_decrypt(
                MCRYPT_RIJNDAEL_256, $key, $cyphertext, MCRYPT_MODE_CBC, $iv
        );

        /*
         * Unpad the string by reading the last bit of padding and removing
         * that many bytes of data from the end
         */
        return Pkcs7::unpad($plaintext);
    }

    /**
     * Encrypt plaintext data.
     * 
     * @param string $plaintext Plaintext string to encrypt.
     * @param string $key       Key used to encrypt data.
     * 
     * @return string 
     */
    public static function encrypt($plaintext, $key)
    {

        /*
         * Get the normalized encryption key and prevent implementation errors.
         * That result in null keys being used.
         */
        $key = self::_key($key);

        // Generate an strong random IV.
        // Neuter IVs
        # $iv = openssl_random_pseudo_bytes(32);
        $iv = str_repeat("\x00", 32);

        // Pad the input string
        $padded = Pkcs7::pad($plaintext);

        // Encrypt the plaintext
        $cyphertext = mcrypt_encrypt(
                MCRYPT_RIJNDAEL_256, $key, $padded, MCRYPT_MODE_CBC, $iv
        );

        // Create a checksum of the cypher text
        $chksum = self::_chksumcreate($cyphertext, $iv, $key);

        // Start output buffering to avoid concating strings
        ob_start();

        // Output the checksum + IV + cyphertext into the output buffer
        echo $iv, $chksum, $cyphertext;

        // Flush buffer to variable
        return ob_get_clean();
    }

    /**
     * Normalize encryption key via hashing to produce key that is equal
     * to block length.
     * 
     * @param string $key Encryption key
     * 
     * @return string
     */
    private static function _key($key)
    {
        return hash('sha256', $key, true);
    }

}
