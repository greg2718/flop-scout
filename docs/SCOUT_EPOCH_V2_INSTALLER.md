# Scout Epoch V2 offline installer

`scout_epoch_install_package.py` is an operator-only, offline migration tool.
It is not called by the ordinary A1 refresh path and has no production paths,
environment switches, or implicit inputs.

The package format is `flop-scout-epoch-install-package/v1`.  Its canonical
`package.json` commits to a closed role list, relative locators, byte hashes
and sizes, the accepted anchor, bridge predecessor/binding, and target
publication/content/epoch identities.  It contains the candidate pointer,
manifest, transition, plan and artifact; a complete immutable archive; and an
exact A1 bridge publication.  Package metadata contains no absolute paths,
Router receipts, session tokens, or raw evidence.  The archive's source
evidence member is intentionally retained as its separately specified binary
evidence member.

All commands require explicit absolute paths.  Example maintenance ordering
(**not executed by this document**):

```sh
python scout_epoch_install_package.py prepare --candidate-root /safe/candidate \
  --archive-root /safe/archive --bridge-root /safe/bridge --package-root /safe/package \
  --disk-budget 2147483648
python scout_epoch_install_package.py verify --package-root /safe/package
python scout_epoch_install_package.py install --package-root /safe/package \
  --publication-root /safe/current-publication --archive-root /safe/archive-trust \
  --bridge-root /safe/bridge-trust --disk-budget 2147483648 --reserve-bytes 268435456
```

`install` obtains an exclusive publication lock, validates the package and the
current bridge pointer, installs complete immutable archive/bridge directories,
then installs candidate files and replaces `current.json` last.  It journals
only bounded identities and states.  Before pointer replacement the existing
publication remains current.  After replacement, `recover` validates the
committed pointer and completes journal cleanup.  Pre-commit recovery never
prunes immutable archive or bridge material.

Abort on any hash, descriptor, policy, source-binding, lock, capacity, or
existing-target conflict.  Rollback is an explicit operator action restoring a
separately verified pre-transition publication backup; never delete the bridge
or archive, whose first-transition retention is indefinite.
