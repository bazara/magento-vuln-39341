# APSB26-146 / CVE-2026-75650 – Magento hotfix VULN-39341 installer

Adobe bulletin: https://experienceleague.adobe.com/en/docs/commerce-knowledge-base/kb/announcements/commerce-apsb26-146

Adobe says this flaw is being exploited in the wild. It can let an attacker who is not logged in run code on the server.

`apply-VULN-39341.sh` is a single script that you run on the server. It:

1. Detects the Magento version from `composer.lock` (or `composer.json`).
2. Downloads the matching official hotfix from `repo.magento.com`.
3. Checks the patch against a SHA-256 hash pinned in the script, and stops if it doesn't match.
4. Backs up every file the patch touches, then applies it.
5. Prints the `bin/magento` commands for you to run. It never runs them itself.

It works on Magento Open Source and Adobe Commerce 2.4.4 to 2.4.9, for Composer installs (`vendor/magento/...`) and `git clone` installs (`app/code/Magento/...`, `lib/internal/...`).

## Quick start

```bash
curl -fsSLO https://raw.githubusercontent.com/IvanBila/magento-vuln-39341/main/apply-VULN-39341.sh
chmod +x apply-VULN-39341.sh

./apply-VULN-39341.sh check /var/www/magento    # dry run, changes nothing
./apply-VULN-39341.sh apply /var/www/magento    # download, verify, back up, patch
```

Run it as the user that owns the Magento files. If you run it as root, it puts the original file owners back after patching.

## Commands

```bash
./apply-VULN-39341.sh check    <magento_root> [options]      # dry run, changes nothing
./apply-VULN-39341.sh apply    <magento_root> [options]      # download, verify, back up, patch
./apply-VULN-39341.sh rollback <magento_root> <backup_dir>   # restore files from a backup
./apply-VULN-39341.sh download <version|patch_id> [options]  # fetch + verify into the cache only
./apply-VULN-39341.sh list                                   # which patch covers which version
```

| Option | Purpose |
|---|---|
| `--version V` | Skip auto-detection and treat the install as Magento `V` (e.g. `2.4.7-p3`) |
| `--patch-id ID` | Force a patch from `list` (e.g. `248-p3`). Asks for confirmation if it doesn't match the version. |
| `--patch-file FILE` | Use a local `.patch` or `.zip` instead of downloading. It is still checked against the pinned hash. |
| `--url URL` | Download from another URL (requires `--sha256`) |
| `--sha256 HASH` | Expected SHA-256 of the `.patch` (for `--url`, or if Adobe re-issues a patch) |
| `--backup-dir DIR` | Backup location (default `~/magento-backups/VULN-39341-<timestamp>`) |
| `--cache-dir DIR` | Download cache (default `~/.cache/magento-hotfixes/VULN-39341`) |
| `-y`, `--yes` | Never prompt (for automation) |

Servers without internet access: run `download <version>` on another machine, copy the file over, and use `--patch-file`.

## Supported versions

| Patch id | Magento versions (per APSB26-146) |
|---|---|
| `249` | 2.4.9-2026-aug, 2.4.9-2026-jul |
| `248-p5` | 2.4.8-2026-aug, 2.4.8-2026-jul, 2.4.8-p5, 2.4.8-p4 |
| `248-p3` | 2.4.8-p3, 2.4.8-p2 |
| `248-p1` | 2.4.8-p1, 2.4.8 |
| `247-p10` | 2.4.7-2026-aug, 2.4.7-2026-jul, 2.4.7-p10, 2.4.7-p9 |
| `247-p8` | 2.4.7-p8, 2.4.7-p7 |
| `247-p5` | 2.4.7 – 2.4.7-p6 |
| `246-p15` | 2.4.6-2026-aug, 2.4.6-2026-jul, 2.4.6-p15, 2.4.6-p14 |
| `246-p13` | 2.4.6-p13, 2.4.6-p12, 2.4.5-p15, 2.4.5-p14, 2.4.4-p16, 2.4.4-p15 |
| `246-p11` | 2.4.6 – 2.4.6-p11, 2.4.5 – 2.4.5-p13, 2.4.4 – 2.4.4-p14 |
| `245-p17` | 2.4.5-2026-aug, 2.4.5-2026-jul, 2.4.5-p17, 2.4.5-p16 |
| `244-p18` | 2.4.4-2026-aug, 2.4.4-2026-jul, 2.4.4-p18, 2.4.4-p17 |

If your version isn't in this table, the script stops instead of guessing. Pass `--patch-id` yourself only after `check` shows the patch applies cleanly.

## Checksums

The hashes are for the `.patch` files inside Adobe's zips. They were downloaded from `repo.magento.com` on 2026-10-12 and are pinned in the script:

```
8df23110e1909e2d5f0c2f0ecbe7f803670dfb0c9c3d15a527371c04b7825bf7  VULN-39341_249.patch
75266ec5548f356a0572c2af74ee5f05aadfab40ede374e8d39bc4a39b6b8ec8  VULN-39341_248-p5.patch
bb8df75f0fd542ea03368e36cf7c19e1e2c109ed4c0c9609f21aa6577cb523b9  VULN-39341_248-p3.patch
3df94078e4feb10d767c6ab52ed5e5c82bb6d2f29e71bf34d3e81355d878f386  VULN-39341_248-p1.patch
fbf4019da673f96410c07aa970453bc22dfb6289aed1df26a87a53ca85e76f1d  VULN-39341_247-p10.patch
fbe6ba6fb43ea56c2824ab9d3e4973dc942949a0ccb7dce23afc648a89843f30  VULN-39341_247-p8.patch
0fc86d7b41afb121e7cdab59f0a4d8456f33edd4e1ed5dc32ec99bb9cc50bc5d  VULN-39341_247-p5.patch
ecb778f71d3e57e67251496a1846b8f548f4c2b2cbde762e2a4274c2c905bd1d  VULN-39341_246-p15.patch
4d32c7628318c8720c90954edb902e3ea501f0a0d03a47eafa62c44cfd84a4c3  VULN-39341_246-p13.patch
6b7a95a473c5fdc2d7d1ee303a1cc8f9acb327a94ae271cd83804de5531bdc28  VULN-39341_246-p11.patch
a2496efe386cccbf260182436286401099f31392ff732c9f50d363ff83e6a4dd  VULN-39341_245-p17.patch
a2496efe386cccbf260182436286401099f31392ff732c9f50d363ff83e6a4dd  VULN-39341_244-p18.patch
```

Verified patches are cached with a `SHA256SUMS` file and checked again every time they are used.

## What `apply` does

1. Picks the patch for your version, downloads it (or reuses the cached copy) and checks its SHA-256.
2. Stops if the patch is already applied.
3. Does a dry run. If the patch doesn't apply cleanly (for example, those files have local edits), it stops without changing anything.
4. Saves a backup outside the web root, containing:
   - `files.tar`: the original files
   - `SHA256SUMS.before` and `SHA256SUMS.after`: checksums of the files before and after patching
   - `OWNERS`: the original file owners
   - a copy of the patch with `PATCH.SHA256`, plus an `INFO` file (version, patch id, URL, hash)
5. Applies the patch. If that fails, it puts the original files back automatically.
6. Runs a PHP syntax check (`php -l`) on the changed files and confirms the patch is in place.
7. Prints the deployment commands below, adjusted for your deploy mode and file owner.

### Files changed by the patch

- `Magento/Backend/Model/Widget/Grid/Row/UrlGeneratorFactory.php`: validates the class type before creating it.
- `Magento/Email/Block/Adminhtml/Template/Preview.php`: adds an admin permission (ACL) check.
- `Magento/Email/Model/AbstractTemplate.php`: rejects non-string template text and styles.
- `Magento/Newsletter/Block/Adminhtml/Queue/Preview.php`: adds an admin permission (ACL) resource.
- `Magento/Newsletter/Block/Adminhtml/Template/Preview.php`: adds an admin permission (ACL) check.
- `Magento/Framework/View/Element/BlockFactory.php`: checks that a class is a valid block before creating it.
- `Magento/Framework/View/Layout/Generator/Block.php`: catches `LogicException`.
- `Magento/Framework/Webapi/ErrorProcessor.php`: adds an `exit` guard to API error report files.
- `pub/errors/processor.php`: adds an `exit` guard to error report files and cleans PHP tags out of report data.

## Deployment (after applying)

The script prints these commands for you to run:

```bash
cd /var/www/magento
bin/magento maintenance:enable
rm -rf generated/code/* generated/metadata/*
bin/magento setup:di:compile        # REQUIRED in production mode: the BlockFactory constructor changed
bin/magento cache:flush
bin/magento maintenance:disable
# If OPcache has validate_timestamps=0, reload PHP-FPM as well
```

## Important notes

- **A later `composer install` or `update` will undo the patch**, because it rewrites `vendor/` and `pub/errors/`. Run this tool again after every composer run or deploy, or add the patch to your build (on Adobe Commerce Cloud, use `m2-hotfixes/`).
- **Adobe requires credential rotation after patching.** Rotating the encryption key alone is not enough:
  1. Enable maintenance mode and disable cron.
  2. Rotate the encryption keys.
  3. Rotate all admin passwords.
  4. Regenerate REST, SOAP and GraphQL integration tokens (System > Extensions > Integrations).
  5. Rotate OAuth client secrets for connected third-party apps.
  6. Rotate payment gateway credentials with the provider (Stripe, Braintree, Adyen, PayPal, …).
  7. Rotate database, Fastly, SSH and deploy-key credentials, plus cron and service accounts.
  8. Rotate API keys for shipping, tax and other extensions.
  9. Flush the cache, enable cron and disable maintenance mode.
- **Check whether the store was already compromised.** Look for unknown files in `pub/errors/`, `var/report/` and `pub/media/`, new admin users, and unexpected changes to CMS blocks or email templates.

## Requirements

`bash` (3.2 or newer), `patch`, `curl` or `wget`, `unzip` (or `python3`/`bsdtar`), `sha256sum` or `shasum`. `php` is optional: it is used for version detection and syntax checks.

## Testing

The script was tested on copies of the stock 2.4.8-p3 source files, in both the Composer and `git clone` layouts, on macOS with BSD `patch` and bash 3.2 and 5. Tested:

- check, apply, re-apply (skipped as expected), and rollback (checksums matched)
- refusing a wrong SHA-256, and downloading again after the cache was tampered with
- `--patch-file` with a local zip

It has not been tested with GNU `patch` on Linux yet, so run `check` on the server first.

## Disclaimer

This is a community tool and is not affiliated with Adobe. Patches are downloaded from Adobe's own servers. Test on staging first and keep backups. Provided as-is, with no warranty.
