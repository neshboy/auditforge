from auditforge.cli import build_parser, cmd_framework_status, cmd_profiles


def test_parser_accepts_every_subcommand():
    parser = build_parser()
    for argv in (
        ["audit"],
        ["audit", "--profile", "strict", "--format", "json"],
        ["harden", "--dry-run"],
        ["harden", "--profile", "server", "--allow-high-impact", "--yes"],
        ["rollback", "--list"],
        ["rollback", "AF-20260924-000000-ABCDEF"],
        ["verify"],
        ["verify", "AF-20260924-000000-ABCDEF"],
        ["framework", "status"],
        ["profiles"],
    ):
        args = parser.parse_args(argv)
        assert args.handler is not None


def test_cmd_profiles_runs_without_touching_the_system(capsys):
    class Args:
        pass

    rc = cmd_profiles(Args())
    assert rc == 0
    out = capsys.readouterr().out
    assert "workstation" in out
    assert "strict" in out


def test_cmd_framework_status_runs_without_touching_the_system(capsys):
    class Args:
        pass

    rc = cmd_framework_status(Args())
    assert rc == 0
    out = capsys.readouterr().out
    assert "NIST" in out or "nist" in out.lower()
