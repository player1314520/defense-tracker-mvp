# Bundled third-party license texts

These files are byte-for-byte copies of the license files at the named upstream
Git tags. Each tag was resolved through the GitHub commit API, then the tagged
file and the same path at the resolved commit were fetched separately and
verified to have identical Git blob IDs, byte lengths, and SHA-256 digests.

| Component | Tag | Resolved commit | Upstream path | Bytes | SHA-256 |
|---|---|---|---|---:|---|
| Marked | `v12.0.0` | `cd151602170433b2ab3cd854f8e639185dbadfd0` | [`LICENSE.md`](https://raw.githubusercontent.com/markedjs/marked/v12.0.0/LICENSE.md) | 2942 | `8e3a3f82f59a60958f56ca08f445647c32a4733dc7ca6c2c46f6eb898471ab9c` |
| DOMPurify | `3.2.6` | `32f765e632ff34eebf5e08128ae1ff8f0d0bbe7a` | [`LICENSE`](https://raw.githubusercontent.com/cure53/DOMPurify/3.2.6/LICENSE) | 27729 | `1b02e03c3fb4f87d476c128f0eb9def1f5a1709d28b180465228bd41574623b7` |
| @supabase/supabase-js | `v2.95.0` | `4b87b9ddd59784524eb8169d0632921d9d261fad` | [`LICENSE`](https://raw.githubusercontent.com/supabase/supabase-js/v2.95.0/LICENSE) | 1065 | `334dd6820e2eaeab2064e7c59001b810566728a28a41a7c1dbf69bbee17d0936` |
| esbuild | `v0.28.1` | `bb9db84c02433fbe37b3509f53f9f3e3cc48725e` | [`LICENSE.md`](https://raw.githubusercontent.com/evanw/esbuild/v0.28.1/LICENSE.md) | 1069 | `b40ec5baec7bb34fa5b1c09521fa3cd52d5fad7adafed74932a2010d3612a681` |

## Verification endpoints

- Marked: [GitHub Contents API](https://api.github.com/repos/markedjs/marked/contents/LICENSE.md?ref=v12.0.0); [immutable raw file](https://raw.githubusercontent.com/markedjs/marked/cd151602170433b2ab3cd854f8e639185dbadfd0/LICENSE.md)
- DOMPurify: [GitHub Contents API](https://api.github.com/repos/cure53/DOMPurify/contents/LICENSE?ref=3.2.6); [immutable raw file](https://raw.githubusercontent.com/cure53/DOMPurify/32f765e632ff34eebf5e08128ae1ff8f0d0bbe7a/LICENSE)
- @supabase/supabase-js: [GitHub Contents API](https://api.github.com/repos/supabase/supabase-js/contents/LICENSE?ref=v2.95.0); [immutable raw file](https://raw.githubusercontent.com/supabase/supabase-js/4b87b9ddd59784524eb8169d0632921d9d261fad/LICENSE)
- esbuild: [GitHub Contents API](https://api.github.com/repos/evanw/esbuild/contents/LICENSE.md?ref=v0.28.1); [immutable raw file](https://raw.githubusercontent.com/evanw/esbuild/bb9db84c02433fbe37b3509f53f9f3e3cc48725e/LICENSE.md)

DOMPurify's upstream `LICENSE` contains the complete Apache License 2.0 and
Mozilla Public License 2.0 texts; it is preserved without additions or edits.

## Scope boundaries

- This directory covers only the four named artifacts and is not a complete
  dependency inventory or software bill of materials.
- It does not evaluate Python packages, JavaScript transitive dependencies,
  container images, operating-system packages, or operator-supplied services.
- Hash equality verifies the copied bytes against the cited upstream snapshot;
  it is not legal advice and does not determine every redistribution obligation.
