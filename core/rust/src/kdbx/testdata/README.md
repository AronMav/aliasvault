# KDBX test fixtures

`real_keepassxc.kdbx` was produced by an actual KeePassXC release (2.7.12), not by our own
writer. The fixtures in `fixtures.rs` are built with the `save_kdbx4` feature of the same
crate we parse with, so on their own they only prove that the reader agrees with the writer.
This file is what proves the parser handles a database the real application produced,
attachment included.

The same file is committed a second time as an embedded resource of the end-to-end test
suite, at `apps/server/Tests/AliasVault.E2ETests/TestData/TestKeePassWithAttachment.kdbx`.

Master password: `testkdbxpass123`

To regenerate both copies:

```bash
keepassxc-cli db-create -p real_keepassxc.kdbx
keepassxc-cli add -u alice --url "https://example.com/" -g real_keepassxc.kdbx Example
printf 'hello' > notes.txt
keepassxc-cli attachment-import real_keepassxc.kdbx Example notes.txt notes.txt
cp real_keepassxc.kdbx ../../../../../apps/server/Tests/AliasVault.E2ETests/TestData/TestKeePassWithAttachment.kdbx
```

The commands prompt for the password interactively; pipe it in when scripting.
