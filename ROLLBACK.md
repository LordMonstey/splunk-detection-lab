# Rollback

This repository was restructured on 2026-04-28 around a
detection-as-code layout. If something breaks, here is how to revert.

## Option 1 — git (preferred)

The previous tree is preserved on the `backup-junior-version` branch.

```
git fetch origin
git checkout backup-junior-version
```

To make it the new main:

```
git checkout main
git reset --hard backup-junior-version
git push --force-with-lease origin main
```

## Option 2 — filesystem backup

A full copy of the pre-refactor working tree was placed at:

`C:\Users\moi\Desktop\splunk-detection-lab.zip.bak-20260428-011524`

To restore from it:

1. Close anything that has the repo open
2. Rename current repo: `Rename-Item 'C:\Users\moi\Desktop\splunk-detection-lab.zip' 'C:\Users\moi\Desktop\splunk-detection-lab.zip.broken'`
3. Copy the backup back: `Copy-Item -LiteralPath 'C:\Users\moi\Desktop\splunk-detection-lab.zip.bak-20260428-011524' -Destination 'C:\Users\moi\Desktop\splunk-detection-lab.zip' -Recurse`

## Option 3 — local backup branch only

If origin push of `backup-junior-version` failed or was skipped:

```
git checkout backup-junior-version
git checkout -B main
```
