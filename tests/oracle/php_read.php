<?php

declare(strict_types=1);

/**
 * The live PHP oracle for the reader: runs PHP fine-print over corpus cases
 * and prints one JSON line per case with every variant's result.
 *
 *   php tests/oracle/php_read.php <corpus dir> <ids file> <out.jsonl>
 *
 * FINE_PRINT_PHP_SRC (the PHP src/) is required: no sibling guessing here, the
 * Python side resolves it and passes it on. A minimal PSR-4 autoloader; no
 * Composer needed.
 *
 * Results are normalised for JSON exactly as tests/_oracle.py normalises the
 * Python side: a non-finite float becomes the string "INF" / "-INF" / "NAN",
 * and every string is mb_scrub'bed (PHP strings are bytes; Python's are text).
 */
$src = getenv('FINE_PRINT_PHP_SRC');
if (! is_string($src) || ! is_file($src.'/Agent.php')) {
    fwrite(STDERR, "FINE_PRINT_PHP_SRC must point at PHP fine-print's src/\n");
    exit(2);
}
spl_autoload_register(function (string $class) use ($src): void {
    $prefix = 'FinePrint\\';
    if (strncmp($class, $prefix, strlen($prefix)) === 0) {
        $file = rtrim($src, '/\\').'/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
ini_set('memory_limit', '1024M');

use FinePrint\Agent;
use FinePrint\Document;
use FinePrint\Exceptions\RefusedException;
use FinePrint\Limits;
use FinePrint\Parser\PdfSyntaxException;

[, $dir, $idsFile, $outFile] = $argv + [null, null, null, null];
$manifest = json_decode((string) file_get_contents($dir.'/manifest.json'), true);
$ids = array_values(array_filter(array_map('trim', file((string) $idsFile) ?: [])));
$out = fopen((string) $outFile, 'w');

function fpo_norm(mixed $v): mixed
{
    if (is_float($v)) {
        return is_nan($v) ? 'NAN' : (is_infinite($v) ? ($v > 0 ? 'INF' : '-INF') : $v);
    }
    if (is_string($v)) {
        return mb_scrub($v, 'UTF-8');
    }
    if (is_array($v)) {
        $o = [];
        foreach ($v as $k => $c) {
            $o[is_string($k) ? mb_scrub($k, 'UTF-8') : $k] = fpo_norm($c);
        }

        return $o;
    }

    return $v;
}

/** @return array<string, mixed> */
function fpo_host(string $bytes, array $lim): array
{
    try {
        $doc = Document::open($bytes, Limits::from($lim));
    } catch (RefusedException $e) {
        return ['refused' => ['reason' => $e->reason, 'message' => $e->getMessage()]];
    }
    $r = ['pages' => [], 'perPage' => []];
    try {
        $r['pages'] = $doc->pages();
        foreach ($r['pages'] as $p) {
            $t = $doc->pageText($p['number']);
            $r['perPage'][] = ['text' => $t['text'], 'spans' => $t['spans'], 'words' => $doc->pageWords($p['number'])];
        }
        $r['metadata'] = $doc->metadata();
        $r['xmp'] = $doc->xmp();
        $r['outline'] = $doc->outline();
        $r['activeContent'] = $doc->activeContent();
        $r['encryption'] = $doc->encryption();
    } catch (RefusedException $e) {
        $r['refusedLater'] = ['reason' => $e->reason, 'message' => $e->getMessage()];
    }
    $r['warnings'] = $doc->warnings();

    return $r;
}

foreach ($ids as $line) {
    // "<id>" for every variant, or "<id> <variant,variant>" for those only.
    [$id, $only] = array_pad(preg_split('/\s+/', $line), 2, '');
    $only = $only === '' ? null : explode(',', $only);
    $case = $manifest[$id];
    $bytes = (string) gzdecode((string) file_get_contents($dir.'/'.$id.'.pdf.gz'));
    $lim = array_merge(get_object_vars(new Limits()), (array) $case['limits']);
    $variants = [];
    $call = function (string $name, callable $fn) use (&$variants, $only): void {
        if ($only !== null && ! in_array($name, $only, true)) {
            return;
        }
        $t = hrtime(true);
        try {
            $res = $fn();
        } catch (Throwable $e) {
            $res = ['threw' => get_class($e)];
        }
        $variants[$name] = ['result' => fpo_norm($res), 'seconds' => (hrtime(true) - $t) / 1e9];
    };
    $call('read', fn () => Agent::read($bytes, ['limits' => $lim]));
    $call('read-words', fn () => Agent::read($bytes, ['limits' => $lim, 'words' => true]));
    if ($only === null && ($variants['read']['result']['ok'] ?? false)) {
        $call('read-flag-low-excerpts', fn () => Agent::read($bytes, ['limits' => $lim, 'words' => true, 'policy' => 'flag', 'threshold' => 'low', 'excerpts' => true]));
        $call('read-discard', fn () => Agent::read($bytes, ['limits' => $lim, 'policy' => 'discard']));
        $call('read-unredacted', fn () => Agent::readUnredacted($bytes, ['limits' => $lim, 'words' => true]));
        $call('host', fn () => fpo_host($bytes, $lim));
    }
    fwrite($out, json_encode(['id' => $id, 'variants' => $variants], JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES)."\n");
}
fclose($out);
