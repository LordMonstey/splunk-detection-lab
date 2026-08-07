# Rollback

This repository was restructured on 2026-04-28 around a
detection-as-code layout. If something breaks, here is how to revert.

## Option 1 - git (preferred)

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

## Option 2 - filesystem backup

A full copy of the pre-refactor working tree can be kept outside the repository.
Use a local path that does not contain personal identifiers, for example:

`<backup-root>\splunk-detection-lab.bak-<timestamp>`

To restore from it:

1. Close anything that has the repo open
2. Rename the current repository: `Rename-Item '<repo-path>' '<repo-path>.broken'`
3. Restore the backup: `Copy-Item -LiteralPath '<backup-path>' -Destination '<repo-path>' -Recurse`

## Option 3 - local backup branch only

If origin push of `backup-junior-version` failed or was skipped:

```
git checkout backup-junior-version
git checkout -B main
```
