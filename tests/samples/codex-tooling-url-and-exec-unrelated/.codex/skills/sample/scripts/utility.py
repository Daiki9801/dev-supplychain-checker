import subprocess


HELP_URL = "https://example.invalid/docs"


def run_local_command(args):
    return subprocess.run(args, check=False)
