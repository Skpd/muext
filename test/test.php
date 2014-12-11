<?php

//chdir(dirname(dirname(__DIR__)));

//require 'vendor/autoload.php';

mu_decoder_init("Enc2.dat", "Dec1.dat");

$packet = [0xC3, 0x44, 0xAD, 0xF8, 0x00, 0xFA, 0x8E, 0x3C, 0x50, 0x10, 0xEC, 0xA7, 0x92, 0x83, 0x3E, 0x49, 0xDE, 0x93, 0xC6, 0x13, 0xDA, 0x88, 0x83, 0xB6, 0x9B, 0x04, 0x3A, 0x4B, 0x96, 0x27, 0xF1, 0xA1, 0x04, 0x44, 0x71, 0xCE, 0x18, 0x16, 0x1A, 0xA8, 0x0D, 0x70, 0xF5, 0x55, 0xA9, 0x9C, 0x28, 0xF6, 0x71, 0x9D, 0xC4, 0x30, 0xC3, 0x66, 0xE8, 0xED, 0xD8, 0xD3, 0xE5, 0x0E, 0x43, 0xCE, 0x13, 0x90, 0x36, 0x15, 0xDD, 0xE8];

$decodeResult = mu_decode_c3(implode('', array_map('chr', $packet)), $class, $head, $sub);

assert(!empty($decodeResult) === true);

assert($class === 0xC1) || var_dump(bin2hex($class));
assert($head === 0xF1) || var_dump(dechex($head));
assert($sub === 0x01) || var_dump($sub);

assert(trim(substr($decodeResult, 4, 10)) === "skpd") || var_dump(trim(substr($decodeResult, 4, 10)));
assert(trim(substr($decodeResult, -16)) === "FIRSTPHPMUSERVER") || var_dump(trim(substr($decodeResult, -16)));
assert(trim(substr($decodeResult, -21, 5)) === "09700") || var_dump(trim(substr($decodeResult, -21, 5)));
exit;
$toEncode      = $decodeResult;//array_map('hexdec', array_map('bin2hex', str_split($decodeResult)));
$encodeResult  = mu_encode_c3($toEncode, 0xF1, 0x01);
$encodedPacket = array_map('hexdec', array_map('bin2hex', str_split($encodeResult)));

foreach ($encodedPacket as $k => $v) {
    if ($v != $packet[$k]) {
        echo "ORIG\tPHP\n";
        for ($i = $k; $i < $k + 4; $i++) {
            printf("%02X\t%02X\n", $packet[$i], $encodedPacket[$i]);
        }
        exit(1);
    }
}
var_dump(strtoupper(implode('', array_map('dechex', $encodedPacket))));
$secondDecodeResult = mu_decode_c3($encodedPacket, $class, $head, $sub);

assert($secondDecodeResult === $decodeResult) || var_dump($decodeResult, $secondDecodeResult);