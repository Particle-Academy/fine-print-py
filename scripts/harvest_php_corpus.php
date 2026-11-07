<?php

declare(strict_types=1);

/**
 * Harvests the reader parity corpus FROM THE PHP SUITE ITSELF.
 *
 * Every PDF the PHP fine-print test suite opens (`Document::open`, which every
 * read path goes through, child processes included) is recorded with the
 * Limits it was opened under. So the corpus is exactly "the fixtures the PHP
 * suite already has": PdfBuilder files, the hostile set, the encryption set,
 * writer output, renderer fixtures. A port never builds its own.
 *
 *   php scripts/harvest_php_corpus.php <fine-print repo with vendor/>
 *
 * Writes tests/fixtures/php-corpus/<id>.pdf.gz and manifest.json. How it hooks
 * in: a COPY of src/Document.php with a recorder inserted after one exact line
 * (refused if that line is not there exactly once), loaded through
 * auto_prepend_file before Composer's autoloader can load the original.
 */
$repo = rtrim($argv[1] ?? __DIR__.'/../../fine-print', '/\\');
$doc = $repo.'/src/Document.php';
if (! is_file($doc) || ! is_file($repo.'/vendor/bin/pest')) {
    fwrite(STDERR, "usage: php harvest_php_corpus.php <fine-print repo with vendor/ installed>\n");
    exit(2);
}

$work = sys_get_temp_dir().'/fp-harvest-'.getmypid();
@mkdir($work.'/out', 0777, true);
@mkdir($work.'/ini', 0777, true);

$marker = '        $limits ??= new Limits();'."\n";
$source = str_replace("\r\n", "\n", (string) file_get_contents($doc));
if (substr_count($source, $marker) !== 1) {
    fwrite(STDERR, "Document::open no longer has the marker line; update this script.\n");
    exit(1);
}
$hook = <<<'PHP'
        $harvestDir = getenv('FP_HARVEST_DIR');
        if (is_string($harvestDir) && $harvestDir !== '') {
            $lim = get_object_vars($limits);
            $key = hash('sha256', $bytes."\0".json_encode($lim, JSON_PRESERVE_ZERO_FRACTION));
            $path = $harvestDir.'/'.$key;
            if (! is_file($path.'.json')) {
                file_put_contents($path.'.pdf', $bytes);
                $origin = '';
                foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $f) {
                    if (isset($f['file']) && str_contains(str_replace('\\', '/', $f['file']), '/tests/')) {
                        $origin = basename($f['file']).':'.($f['line'] ?? 0);
                        break;
                    }
                }
                file_put_contents($path.'.json', json_encode(['limits' => $lim, 'origin' => $origin], JSON_PRESERVE_ZERO_FRACTION));
            }
        }

PHP;
file_put_contents($work.'/Document.php', str_replace($marker, $marker.$hook, $source));
file_put_contents($work.'/prepend.php', "<?php\nif (! class_exists('FinePrint\\\\Document', false)) { require ".var_export($work.'/Document.php', true)."; }\n");
file_put_contents($work.'/ini/harvest.ini', 'auto_prepend_file="'.str_replace('\\', '/', $work).'/prepend.php"'."\n");

$env = getenv();
$env['PHP_INI_SCAN_DIR'] = $work.'/ini';
$env['FP_HARVEST_DIR'] = $work.'/out';
$proc = proc_open([PHP_BINARY, 'vendor/bin/pest', '--exclude-group=local'], [1 => ['file', $work.'/pest.log', 'w'], 2 => ['file', $work.'/pest.log', 'a']], $pipes, $repo, $env);
$code = proc_close($proc);
if ($code !== 0) {
    fwrite(STDERR, "the PHP suite failed (exit $code); see $work/pest.log. A corpus from a red suite is not harvested.\n");
    exit(1);
}

spl_autoload_register(function (string $class) use ($repo): void {
    $file = $repo.'/src/'.str_replace('\\', '/', substr($class, strlen('FinePrint\\'))).'.php';
    if (str_starts_with($class, 'FinePrint\\') && is_file($file)) {
        require $file;
    }
});
$defaults = get_object_vars(new FinePrint\Limits());

$dest = __DIR__.'/../tests/fixtures/php-corpus';
@mkdir($dest, 0777, true);
foreach (glob($dest.'/*.pdf.gz') ?: [] as $old) {
    unlink($old);
}
$manifest = [];
foreach (glob($work.'/out/*.json') ?: [] as $meta) {
    $key = basename($meta, '.json');
    $m = json_decode((string) file_get_contents($meta), true);
    $id = substr($key, 0, 16);
    $changed = [];
    foreach ($m['limits'] as $k => $v) {
        if ($defaults[$k] !== $v) {
            $changed[$k] = $v;
        }
    }
    $bytes = (string) file_get_contents($work.'/out/'.$key.'.pdf');
    file_put_contents($dest.'/'.$id.'.pdf.gz', gzencode($bytes, 9));
    $manifest[$id] = ['origin' => $m['origin'], 'bytes' => strlen($bytes), 'sha256' => hash('sha256', $bytes), 'limits' => (object) $changed];
}
ksort($manifest);
file_put_contents($dest.'/manifest.json', json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION)."\n");
echo count($manifest)." cases harvested into tests/fixtures/php-corpus\n";
