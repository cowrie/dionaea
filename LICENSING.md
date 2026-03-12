# Licensing

Dionaea uses a dual-licensing model. Different parts of the codebase are
available under different terms depending on their origin and copyright
ownership.

## Rust Core (crates/)

The Rust core — everything under `crates/` — is copyright Cowrie and is
available under **either** of the following licenses, at your option:

- **GNU Affero General Public License, version 3.0 only**
  ([LICENSES/AGPL-3.0-only.txt](LICENSES/AGPL-3.0-only.txt)) — free for
  open-source use with AGPL obligations (network-use disclosure requirement).

- **Cowrie Commercial License** — permits proprietary internal use without
  AGPL source-disclosure obligations. Does not grant modification or
  redistribution rights. See
  [LICENSES/LicenseRef-Cowrie-Commercial.txt](LICENSES/LicenseRef-Cowrie-Commercial.txt)
  for the template terms, or contact **sales@cowrie.org** for purchasing.

SPDX header on dual-licensed files:

```
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
```

## Python Protocol Modules (modules/)

The Python protocol handlers under `modules/python/dionaea/` have mixed
licensing depending on their origin:

**Dual-licensed modules** (Cowrie copyright, same terms as Rust core):

| Component | License | Copyright |
|-----------|---------|-----------|
| Modbus module | AGPL-3.0-only OR Commercial | Cowrie |
| RDP module | AGPL-3.0-only OR Commercial | Cowrie |

**Third-party modules** (NOT available under commercial license):

| Component | License | Key Copyright Holders |
|-----------|---------|----------------------|
| Most Python modules | GPL-2.0-or-later | Paul Baecher, Markus Koetter, PhiBo (DinoTools), Tan Kean Siong, and others |
| SMB packet layer (Scapy-derived) | **GPL-2.0-only** | Philippe Biondi, Mark Schloesser |
| FTP module | GPL-2.0-or-later AND MIT | Twisted Matrix Laboratories |
| TFTP module | MIT | Michael P. Soulier |

### Implications for Commercial Licensees

Commercial license holders receive the right to use the Rust core without AGPL
obligations. However:

1. **GPL-2.0-or-later modules** — These must still be used in compliance with
   GPL-2.0 terms. Distributing a proprietary product that links to or includes
   these modules requires either GPL compliance or replacement of those modules.

2. **GPL-2.0-only modules** (SMB packet layer) — These are GPL-2.0-only with
   no "or later" upgrade path. They cannot be relicensed. Commercial customers
   who need a fully proprietary SMB honeypot should contact us about our
   commercially-written replacements.

3. **MIT-licensed modules** (TFTP, portions of FTP) — These are permissive and
   compatible with any use, including proprietary.

## Configuration & Metadata

Files under `conf/`, CI workflows, and similar metadata use **CC0-1.0**
(public domain dedication) and impose no restrictions.

## Documentation

Documentation under `doc/` is licensed **GPL-2.0-or-later** from the original
project.

## Contributing

By submitting a pull request, you agree that your contributions to files under
`crates/` are licensed under the same dual-license terms (AGPL-3.0-only OR
LicenseRef-Cowrie-Commercial). Contributions to files under `modules/` are
licensed under the existing license of the file being modified.

See [CONTRIBUTING.rst](CONTRIBUTING.rst) for details.

## Contact

For commercial licensing inquiries: **sales@cowrie.org**
