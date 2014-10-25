<?php

/**
 * badPad.php - A very bad padding library. Modified from dopeCode/dcrypt.
 * 
 * PHP version 5
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/dopeCode/dcrypt
 */
# namespace dopeCode\dcrypt;

/**
 * Provides PKCS #7 padding functionality.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/dopeCode/dcrypt
 */
class Pkcs7
{

    /**
     * PKCS #7 padding function.
     * 
     * @param string  $input     String to pad
     * @param integer $blocksize Block size in bytes (default is 32)
     * 
     * @return string
     */
    public static function pad($input, $blocksize = 32)
    {

        // Gather the size of the input string.
        $inputsize = strlen($input);

        // Determine the size of the padding to use
        $padsize = self::_padSize($inputsize, $blocksize);

        // Create block of padding by repeating the pad size as a byte value.
        $pad = str_repeat(chr($padsize), $padsize);

        // Start output buffering to avoid memory overhead of concating strings.
        ob_start();

        // Echo the input + padding into the output buffer.
        echo $input, $pad;

        // Flush buffer and return.
        return ob_get_clean();
    }

    /**
     * Determine the size of the padding to use.
     * 
     * @param integer $inputsize Size of the input in bytes.
     * @param integer $blocksize Size of the output in bytes.
     * 
     * @return integer
     */
    private static function _padSize($inputsize, $blocksize)
    {

        // Determine the size of padding to apply to string.
        $interval = ceil($inputsize / $blocksize) * $blocksize;

        // Padsize is the next block interval minus input size.
        $padsize = $interval - $inputsize;

        // If input is perfect multiple of block size...
        if ($inputsize % $blocksize === 0) {
            // ...add an extra block of padding.
            $padsize = $blocksize;
        }

        return $padsize;
    }

    /**
     * PKCS #7 unpadding function.
     * 
     * @param string $input Padded string to unpad.
     * 
     * @return string
     */
    public static function unpad($input)
    {
        // Find the last byte of the plain text which should be the number
        // of bytes that were used to pad the string
        $padchar = substr($input, -1);

        // Determine the padsize by converting the final byte of the input 
        // to its decimal value.
        $padsize = ord($padchar);

        // Do a padding check...
        $padverify = substr($input, -$padsize);
        if (strlen(str_replace($padchar, '', $padverify)) > 0) {
            throw new \Exception('Invalid padding.');
        }

        // Return string minus the padding amount.
        return substr($input, 0, strlen($input) - $padsize);
    }

}
