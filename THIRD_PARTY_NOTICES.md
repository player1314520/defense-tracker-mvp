# Third-Party Notices

The first-party all-rights-reserved notice does not replace or restrict rights
granted by third-party licenses. The following components are directly vendored
or used to generate checked-in browser assets.

## Vendored browser libraries

### Marked 12.0.0

- File: `static/js/marked.min.js`
- Purpose: Markdown parsing
- License: MIT
- Copyright: 2018-present MarkedJS; 2011-2018 Christopher Jeffrey
- Upstream: <https://github.com/markedjs/marked/tree/v12.0.0>
- Bundled license text: [`THIRD_PARTY_LICENSES/marked-v12.0.0/LICENSE.md`](THIRD_PARTY_LICENSES/marked-v12.0.0/LICENSE.md)
- Upstream: <https://github.com/markedjs/marked/blob/v12.0.0/LICENSE.md>

The vendored file retains its upstream version, copyright, and MIT license
header.

### DOMPurify 3.2.6

- File: `static/js/purify.min.js`
- Purpose: HTML sanitization
- License: `(MPL-2.0 OR Apache-2.0)`
- Copyright: 2025 Dr.-Ing. Mario Heiderich, Cure53, and contributors
- Upstream: <https://github.com/cure53/DOMPurify/tree/3.2.6>
- Bundled dual-license text: [`THIRD_PARTY_LICENSES/DOMPurify-3.2.6/LICENSE`](THIRD_PARTY_LICENSES/DOMPurify-3.2.6/LICENSE)
- Upstream: <https://github.com/cure53/DOMPurify/blob/3.2.6/LICENSE>

The vendored file retains its upstream version and dual-license header.

## Generated Supabase browser bundles

The checked-in files `static/js/vendor/v9-supabase-auth.mjs` and
`web/v9-portal/supabase-client.mjs` are generated from the package manifest and
lockfile under `web/v9-auth`.

### @supabase/supabase-js 2.95.0

- Role: bundled runtime dependency, including its Supabase client subpackages
- License: MIT
- Copyright: 2020 Supabase
- Upstream: <https://github.com/supabase/supabase-js/tree/v2.95.0>
- Bundled license text: [`THIRD_PARTY_LICENSES/supabase-js-v2.95.0/LICENSE`](THIRD_PARTY_LICENSES/supabase-js-v2.95.0/LICENSE)
- Upstream: <https://github.com/supabase/supabase-js/blob/v2.95.0/LICENSE>

### esbuild 0.28.1

- Role: build-time bundler; its platform packages are development dependencies
- License: MIT
- Copyright: 2020 Evan Wallace
- Upstream: <https://github.com/evanw/esbuild/tree/v0.28.1>
- Bundled license text: [`THIRD_PARTY_LICENSES/esbuild-v0.28.1/LICENSE.md`](THIRD_PARTY_LICENSES/esbuild-v0.28.1/LICENSE.md)
- Upstream: <https://github.com/evanw/esbuild/blob/v0.28.1/LICENSE.md>

## Inventory and compliance boundaries

This notice is not an exhaustive software bill of materials:

1. transitive JavaScript packages are recorded in
   `web/v9-auth/package-lock.json` but are not all repeated here;
2. Python packages, container images, the operator-supplied Supabase stack, and
   operating-system packages have separate manifests and upstream licenses; and
3. dependency names and license metadata have been checked, but this file is
   not legal advice or a complete license-compliance audit.

Before redistributing any build, regenerate its dependency inventory, review
all transitive and container dependencies, and retain the complete upstream
license and notice texts required by the selected licenses.
