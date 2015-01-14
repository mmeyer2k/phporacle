<?php

/**
 * badHash.php - A very bad hashing library. Modified from dopecode/dcrypt.
 * 
 * PHP version 5
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/dopecode/dcrypt
 */

# namespace dopecode\dcrypt;

/**
 * The hash class addresses some shortcomings in the password_hash function
 * built into PHP such as...
 *     - salt is known
 *     - rounds are known
 *     - password hashing scheme is obvious
 * 
 * hash::make() outputs a binary 512 bit string with the following format:
 * 
 * [     salt     ][     cost     ][             hash             ]
 *     16 bytes        16 bytes                32 bytes
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/dopecode/dcrypt
 */
class Hash
{

    /**
     * Internal function used to build the actual hash.
     *  
     * @param string       $input Data to hash.
     * @param string       $key   Key to use in HMAC call.
     * @param string|null  $salt  Salt to use in HMAC call.
     * @param integer      $cost  Number of iterations to use.
     * 
     * @return string
     */
    private static function _build($input, $key, $salt = null, $cost = 1337)
    {
        // If no salt was specified, generate a random 16 byte one. The salt 
        // will be provided during the verification step.
        $salt = $salt === null ? openssl_random_pseudo_bytes(16) : $salt;

        // Check the validity of the cost argument.
        $cost = self::_cost($cost);

        // Perform hash iterations.
        $input = self::ihmac($input, $key . $salt, $cost * 100);

        // Zero pad the cost out to 16 bytes as specified in the hash format.
        $coststr = str_pad($cost, 16, 0, STR_PAD_LEFT);

        // Create the salt + cost prefix. Crypt key for the cost value is the 
        // salt so that a key dependency between the cost and salt is formed.
        $prefix = Otp::crypt($salt, $key) . Otp::crypt($coststr, $salt);

        // The input is now encrypted with the prefix string as the key
        // then the final binary string is constructed and returned.
        return $prefix . Otp::crypt($input, $prefix);
    }

    /**
     * Return a normalized cost value.
     * 
     * @param int $cost Number of iterations to use.
     * 
     * @return int
     */
    private static function _cost($cost)
    {

        // Find the maximum value allowed for the cost value.
        $maxval = pow(2, 16);

        // Limit the maximum size of the cost value.
        if ($cost > $maxval) {
            $cost = $maxval;
        }

        // Limit the minimum size of the cost value.
        if ($cost <= 0) {
            $cost = 1;
        }

        // If all checks are passed, return cost.
        return (int) $cost;
    }

    /**
     * Perform a raw iterative HMAC operation with a configurable algo.
     * 
     * @param string  $data Data to hash.
     * @param string  $key  Key to use to authenticate the hash.
     * @param integer $m    Number of times to iteratate the hash
     * @param string  $algo Name of algo (sha256 or sha512 recommended)
     * @param boolean $echo Determines whether to echo a random stream of blocks
     *                      into the output buffer.
     * 
     * @return string
     */
    public static function ihmac($data, $key, $m, $algo = 'sha256', $echo = false)
    {
        for ($i = 0; $i < $m; $i++) {
            $ikey = $key . $i . $m . $algo;
            $data = hash_hmac($algo, $data, $ikey, true);
            if ($echo === true) {
                echo $data;
            }
        }
        return $data;
    }

    /**
     * Hash an input string into a salted 512 byte hash.
     * 
     * @param string  $input Data to hash.
     * @param string  $key   HMAC validation key.
     * @param integer $cost  Cost value of the hash.
     * 
     * @return string
     */
    public static function make($input, $key, $cost = 1337)
    {
        return self::_build($input, $key, null, $cost);
    }

    /**
     * Check the validity of an Nhash gerneated checksum against a plaintext 
     * string.
     * 
     * @param string $input Input to compare.
     * @param string $hash  Hash to verify.
     * @param string $key   HMAC key to use during iterative hash. 
     * 
     * @return boolean
     */
    public static function verify($input, $hash, $key)
    {

        /*
         * Get the salt value from the front of the input and decrypt with
         * the default noodle key.
         */
        $rawsalt = substr($hash, 0, 16);

        $salt = Otp::crypt($rawsalt, $key);

        /*
         * Get the cost value between salt and hash and decrypt using the salt
         * as the key.
         */
        $cost = Otp::crypt(substr($hash, 16, 16), $salt);

        // Return the boolean equivalence.
        return self::_build($input, $key, $salt, (int) $cost) === $hash;
    }

}
