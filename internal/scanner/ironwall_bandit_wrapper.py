"""
Ironwall Bandit Wrapper — injects custom CWE-501/CWE-90 plugins into Bandit 1.9.4.

Bandit 1.9.4 uses stevedore entry_points for plugin discovery. This wrapper
monkey-patches the extension manager to include Ironwall's custom plugins
before running the normal Bandit scan.

Usage: python ironwall_bandit_wrapper.py [bandit_args...]
Example: python ironwall_bandit_wrapper.py -r ./target -f json --quiet
"""

import sys
import os


def _inject_plugins():
    """Inject Ironwall custom plugins into Bandit's extension manager."""
    # Add the parent directory to sys.path so we can import bandit_plugins
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    if plugin_dir not in sys.path:
        sys.path.insert(0, plugin_dir)

    # Import bandit internals BEFORE the scan starts
    import bandit.core.extension_loader as ext_loader

    # Import our custom plugins
    from bandit_plugins import trust_boundary, ldap_injection  # noqa: E402

    # Create a fake stevedore extension wrapper
    class _FakeExt:
        def __init__(self, name, plugin):
            self.name = name
            self.plugin = plugin

    # Inject plugins into the manager
    mgr = ext_loader.MANAGER

    for name, plugin in [
        ("trust_boundary_violation", trust_boundary.trust_boundary_violation),
        ("ldap_injection", ldap_injection.ldap_injection),
    ]:
        test_id = plugin._test_id
        ext = _FakeExt(name, plugin)

        if ext not in mgr.plugins:
            mgr.plugins.append(ext)
        if name not in mgr.plugin_names:
            mgr.plugin_names.append(name)
        mgr.plugins_by_id[test_id] = ext
        mgr.plugins_by_name[name] = ext


def main():
    """Entry point: inject plugins, then delegate to bandit CLI."""
    _inject_plugins()

    # Remove 'ironwall_bandit_wrapper.py' from argv so bandit sees clean args
    # sys.argv[0] stays as the script path (bandit doesn't care about argv[0])
    # but we need to remove wrapper-specific args
    bandit_args = sys.argv[1:] if len(sys.argv) > 1 else []

    # Use bandit's CLI main function (bandit.cli.main is a module, .main() is the entry point)
    import bandit.cli.main as cli_main

    # Replace sys.argv with what bandit expects
    old_argv = sys.argv
    sys.argv = [old_argv[0]] + bandit_args

    try:
        cli_main.main()
    except SystemExit as e:
        return e.code if e.code is not None else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
