# Exact source excerpt from apport 2.28.2 data/apport:693-709.
# Source: https://archive.ubuntu.com/ubuntu/pool/main/a/apport/apport_2.28.2.orig.tar.xz
def start_apport() -> None:
    """Start Apport crash handler."""
    create_directory(apport.fileutils.report_dir, 0o3777)
    write_to_proc_sys(
        "kernel/core_pattern",
        f"|{__file__} -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E",
    )
    write_to_proc_sys("fs/suid_dumpable", "2")
    write_to_proc_sys("kernel/core_pipe_limit", "10")
    check_kernel_crash()


def stop_apport() -> None:
    """Stop Apport crash handler."""
    write_to_proc_sys("kernel/core_pipe_limit", "0")
    write_to_proc_sys("fs/suid_dumpable", "0")
    write_to_proc_sys("kernel/core_pattern", "core")
