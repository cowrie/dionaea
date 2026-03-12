..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2025 The Cowrie Contributors

    SPDX-License-Identifier: GPL-2.0-or-later

Contributing
============

Bug Reports
-----------

File bugs on the `GitHub issue tracker`_. Include:

- What you expected to happen
- What actually happened
- Steps to reproduce
- Dionaea version and OS

Pull Requests
-------------

- Fork the repo and create a branch from ``main``
- One PR per feature or bugfix
- Include tests where applicable
- Update documentation for new functionality
- Make sure pre-commit hooks pass

Licensing of Contributions
^^^^^^^^^^^^^^^^^^^^^^^^^^

By submitting a pull request you agree to the following:

- Contributions to files under ``crates/`` are licensed under
  ``AGPL-3.0-only OR LicenseRef-Cowrie-Commercial`` (dual license).
- Contributions to files under ``modules/`` are licensed under the
  existing license of the file being modified.
- You certify that your contribution is your original work or that you
  have the right to submit it under the applicable license terms
  (`Developer Certificate of Origin`_).

Setup
^^^^^

.. code::

    $ git clone https://github.com/cowrie/dionaea
    $ cd dionaea
    $ git remote add fork https://github.com/<username>/dionaea
    $ pip install pre-commit
    $ pre-commit install

Style
^^^^^

- C code: match the style of surrounding code
- Python code: follow `PEP 8`_
- Rust code: use ``cargo fmt`` and ``cargo clippy``

Review
------

All pull requests require review before merging. Reviewing others' PRs is encouraged.

.. _GitHub issue tracker: https://github.com/cowrie/dionaea/issues
.. _PEP 8: https://www.python.org/dev/peps/pep-0008/
.. _Developer Certificate of Origin: https://developercertificate.org/
