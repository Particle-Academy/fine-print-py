<?php

declare(strict_types=1);

/**
 * PHP's answers for the behaviours fine_print/_php.py reproduces, over the
 * inputs in argv[1] (JSON), printed as JSON. Hex in, hex out for bytes.
 */
$in = json_decode((string) file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
$out = ['scrub' => [], 'u16be' => [], 'u16le' => [], 'floatStr' => [], 'varExport' => [], 'intCast' => [], 'trim' => []];
foreach ($in['bytes'] as $hex) {
    $b = (string) hex2bin($hex);
    $out['scrub'][] = bin2hex(mb_scrub($b, 'UTF-8'));
    $out['u16be'][] = bin2hex((string) @mb_convert_encoding($b, 'UTF-8', 'UTF-16BE'));
    $out['u16le'][] = bin2hex((string) @mb_convert_encoding($b, 'UTF-8', 'UTF-16LE'));
    $out['trim'][] = bin2hex(trim($b));
}
foreach ($in['floats'] as $f) {
    $f = match ($f) { 'INF' => INF, '-INF' => -INF, 'NAN' => NAN, default => (float) $f };
    $out['floatStr'][] = (string) $f;
    $out['varExport'][] = var_export($f, true);
    $out['intCast'][] = (string) (int) $f;
}
echo json_encode($out);
