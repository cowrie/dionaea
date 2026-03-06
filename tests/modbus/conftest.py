# ABOUTME: Test fixtures for modbus unit tests
# ABOUTME: Mocks dionaea.core and dionaea.ServiceLoader so protocol logic is testable standalone

import sys
import os
import types

# Add module source path so Python can find dionaea.modbus
_modules_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'modules', 'python')
_dionaea_pkg_dir = os.path.join(_modules_dir, 'dionaea')

# Mock dionaea.core before any dionaea imports.
# This lets us unit-test the pure protocol functions without the C/Rust runtime.

_dionaea_mod = types.ModuleType('dionaea')
_dionaea_mod.__path__ = [os.path.abspath(_dionaea_pkg_dir)]
_dionaea_mod.ServiceLoader = type('ServiceLoader', (), {'name': ''})

_core_mod = types.ModuleType('dionaea.core')
_core_mod.connection = type('connection', (), {
    '__init__': lambda self, proto=None: None,
})
_core_mod.incident = type('incident', (), {
    '__init__': lambda self, origin='': None,
})

_exception_mod = types.ModuleType('dionaea.exception')

sys.modules.setdefault('dionaea', _dionaea_mod)
sys.modules.setdefault('dionaea.core', _core_mod)
sys.modules.setdefault('dionaea.exception', _exception_mod)
