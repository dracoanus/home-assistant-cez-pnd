#!/usr/bin/env python3
"""Fail-closed static checks for the minimal Collector runtime experiment."""

from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
DOCKERFILE = ROOT.joinpath("Dockerfile").read_text(encoding="utf-8")
COMPOSE = ROOT.joinpath("compose.yaml").read_text(encoding="utf-8")
SMOKE_TEST = ROOT.joinpath("smoke_test.py").read_text(encoding="utf-8")
HA_APP_ROOT = ROOT.parent / "collector-runtime-ha-app"
HA_CONFIG = HA_APP_ROOT.joinpath("config.yaml").read_text(encoding="utf-8")
PUBLISH_WORKFLOW = REPOSITORY_ROOT.joinpath(
    ".github", "workflows", "publish-collector-runtime.yaml"
).read_text(encoding="utf-8")
VERSION = "152.0.7977.82-1~deb12u1"
PASSWD_VERSION = "1:4.13+dfsg1-1+deb12u2"
TINI_VERSION = "0.19.0-1+b3"
FORBIDDEN_FLAGS = {
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-gpu-sandbox",
}
GHCR_IMAGE = "ghcr.io/dracoanus/home-assistant-cez-pnd-collector-runtime"
APP_VERSION = "0.1.0"
COMMAND_PROVIDERS = {
    "apt-get": "apt from the digest-pinned Debian/Python base",
    "chmod": "coreutils from the digest-pinned Debian/Python base",
    "command": "/bin/sh builtin from the digest-pinned base",
    "dpkg-query": "dpkg from the digest-pinned Debian/Python base",
    "groupadd": f"explicit passwd={PASSWD_VERSION}",
    "install": "coreutils from the digest-pinned Debian/Python base",
    "pip": "created by the base image's python -m venv",
    "printf": "/bin/sh builtin from the digest-pinned base",
    "python": "python from the digest-pinned Python base",
    "rm": "coreutils from the digest-pinned Debian/Python base",
    "stat": "coreutils from the digest-pinned Debian/Python base",
    "test": "/bin/sh builtin from the digest-pinned base",
    "useradd": f"explicit passwd={PASSWD_VERSION}",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def logical_dockerfile_instructions(text: str) -> list[str]:
    instructions: list[str] = []
    current = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not current and (not stripped or stripped.startswith("#")):
            continue
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        instructions.append(current)
        current = ""
    require(not current, "unterminated Dockerfile continuation")
    return instructions


def run_command_names(text: str) -> set[str]:
    commands: set[str] = set()
    for instruction in logical_dockerfile_instructions(text):
        if not instruction.startswith("RUN "):
            continue
        body = instruction.removeprefix("RUN ")
        for segment in body.split("&&"):
            words = shlex.split(segment, posix=True)
            require(words, "empty RUN command segment")
            commands.add(Path(words[0]).name)
        commands.update(Path(name).name for name in re.findall(r"\$\(([^\s)]+)", body))
    return commands


def verify_dockerfile(text: str) -> None:
    require(f"ARG CHROMIUM_VERSION={VERSION}" in text, "Chromium pin changed")
    require(f"ARG PASSWD_VERSION={PASSWD_VERSION}" in text, "passwd pin changed")
    require(f"ARG TINI_VERSION={TINI_VERSION}" in text, "tini pin changed")
    for package in ("chromium", "chromium-driver", "chromium-sandbox"):
        require(
            f'{package}="${{CHROMIUM_VERSION}}"' in text,
            f"{package} is not explicitly pinned",
        )
        require(
            f"dpkg-query -W -f='${{db:Status-Status}}' {package}" in text,
            f"installed-state verification for {package} is missing",
        )
    for package, version_arg in (("passwd", "PASSWD_VERSION"), ("tini", "TINI_VERSION")):
        require(
            f'{package}="${{{version_arg}}}"' in text,
            f"{package} is not explicitly pinned",
        )
        require(
            f"dpkg-query -W -f='${{db:Status-Status}}' {package}" in text,
            f"installed-state verification for {package} is missing",
        )
        require(
            f"dpkg-query -W -f='${{Version}}' {package}" in text,
            f"exact version verification for {package} is missing",
        )
    require(
        "! dpkg-query -W chromium-sandbox" not in text,
        "obsolete chromium-sandbox absence assertion returned",
    )
    require(
        "dpkg-query -W -f='${Version}' chromium-sandbox" in text,
        "exact chromium-sandbox version verification is missing",
    )
    require(
        "stat -c '%U:%G:%a' /usr/lib/chromium/chrome-sandbox" in text
        and '"root:root:4755"' in text,
        "chrome-sandbox owner/mode verification is missing",
    )
    require("/usr/sbin/groupadd --gid 2000 collector" in text, "absolute groupadd missing")
    require("/usr/sbin/useradd --uid 2000 --gid 2000" in text, "absolute useradd missing")
    require("--shell /bin/false collector" in text, "non-login shell is not deterministic")
    require("/usr/bin/install -d -o 0 -g 0 -m 0555" in text, "absolute install missing")
    require("USER 2000:2000" in text, "container user is not 2000:2000")

    commands = run_command_names(text)
    unknown = commands.difference(COMMAND_PROVIDERS)
    require(not unknown, f"RUN command has no audited provider: {sorted(unknown)}")

    apt_layer = text.index("RUN printf")
    validation_layer = text.index("RUN command -v")
    lock_copy = text.index("COPY requirements.lock")
    pip_layer = text.index("RUN /usr/local/bin/python -m venv")
    user_layer = text.index("RUN /usr/sbin/groupadd")
    source_copy = text.index("COPY --chown=0:0 smoke_test.py")
    require(
        apt_layer < validation_layer < lock_copy < pip_layer < user_layer < source_copy,
        "cache-friendly layer order changed",
    )
    apt_instruction = next(
        item for item in logical_dockerfile_instructions(text) if item.startswith("RUN printf")
    )
    pip_instruction = next(
        item
        for item in logical_dockerfile_instructions(text)
        if item.startswith("RUN /usr/local/bin/python -m venv")
    )
    require("dpkg-query" not in apt_instruction, "cheap validation merged into APT layer")
    require("groupadd" not in pip_instruction, "user creation merged into pip layer")

    for path in (
        "/usr/sbin/groupadd",
        "/usr/sbin/useradd",
        "/usr/bin/install",
        "/usr/bin/stat",
        "/usr/bin/dpkg-query",
        "/bin/false",
        "/usr/local/bin/python",
        "/usr/bin/tini",
        "/usr/bin/chromium",
        "/usr/bin/chromedriver",
    ):
        require(f"command -v {path}" in text, f"executable validation missing: {path}")


def configured_chromium_arguments(source: str) -> set[str]:
    tree = ast.parse(source)
    values: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "arguments" for target in targets):
            continue
        value = node.value
        require(isinstance(value, (ast.List, ast.Tuple)), "arguments must be a literal sequence")
        for item in value.elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                values.add(item.value.split("=", 1)[0])
            elif isinstance(item, ast.JoinedStr):
                literal_prefix = "".join(
                    part.value for part in item.values if isinstance(part, ast.Constant)
                )
                values.add(literal_prefix.split("=", 1)[0])
            else:
                raise AssertionError("non-authoritative Chromium argument expression")
    require(values, "Chromium argument list was not found")
    return values


def verify_smoke_diagnostics(source: str) -> None:
    tree = ast.parse(source)
    service_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Service"
    ]
    require(len(service_calls) == 1, "expected exactly one ChromeDriver Service")
    keywords = {keyword.arg: keyword.value for keyword in service_calls[0].keywords}
    require(
        ast.literal_eval(keywords.get("service_args")) == ["--verbose"],
        "ChromeDriver verbose logging is not enabled",
    )
    log_output = keywords.get("log_output")
    require(
        isinstance(log_output, ast.Call)
        and isinstance(log_output.func, ast.Name)
        and log_output.func.id == "str"
        and len(log_output.args) == 1
        and isinstance(log_output.args[0], ast.Name)
        and log_output.args[0].id == "log_path",
        "ChromeDriver log is not directed to the private temporary file",
    )
    require('log_path.touch(mode=0o600)' in source, "ChromeDriver log mode creation missing")
    require('log_path.chmod(0o600)' in source, "ChromeDriver log mode enforcement missing")
    require("CHROME_LOG_FILE" not in source, "Chromium log forwarding was overridden")
    require(
        re.search(r"(?m)^LOG_TAIL_MAX_BYTES = 32 \* 1024$", source) is not None,
        "bounded byte tail changed",
    )
    require(
        re.search(r"(?m)^LOG_TAIL_MAX_LINES = 200$", source) is not None,
        "bounded line tail changed",
    )
    require('log_file.read(LOG_TAIL_MAX_BYTES)' in source, "bounded log read missing")
    require(
        'lines[-LOG_TAIL_MAX_LINES:]' in source,
        "bounded log line selection missing",
    )
    for diagnostic in (
        'executable_version("/usr/bin/chromium")',
        'executable_version("/usr/bin/chromedriver")',
        'result["configured_chromium_arguments"] = arguments.copy()',
        'result["last_completed_milestone"] = name',
        'result["chromedriver_log_tail"] = bounded_log_tail(log_path)',
    ):
        require(diagnostic in source, f"startup diagnostic missing: {diagnostic}")

    ordered_steps = (
        'milestone(result, "before_webdriver_session")',
        "driver = webdriver.Chrome(service=service, options=options)",
        'milestone(result, "webdriver_session_created")',
        'driver.get("about:blank")',
        'driver.execute_script("return 1")',
        'driver.get("data:text/html;charset=utf-8," + quote(inline_html))',
        "driver.get(loopback_url)",
    )
    positions = [source.index(step) for step in ordered_steps]
    require(positions == sorted(positions), "ordered functional smoke sequence changed")


def verify_minimal_sandbox_gate(source: str) -> None:
    required_evidence = (
        'status.get("NoNewPrivs")',
        'status.get("Seccomp")',
        'status.get("CapEff")',
        'for namespace in ("user", "pid", "net")',
        'renderer.get("effective_uid") == 2000',
        'renderer.get("effective_gid") == 2000',
        'renderer.get("no_new_privs") == "1"',
        'renderer.get("seccomp") == "2"',
        'renderer.get("cap_eff") == "0000000000000000"',
        'all(renderer.get("separate_namespaces", {}).values())',
        '"identity_stable": start_before == start_after',
        'result["cleanup_verified"] = not result["orphan_chromium_pids"]',
    )
    for evidence in required_evidence:
        require(evidence in source, f"minimal sandbox evidence missing: {evidence}")

    functional_end = source.index('milestone(result, "loopback_dom_verified")')
    sandbox_check = source.index('result["sandbox"] = verify_renderer_sandbox()')
    sandbox_milestone = source.index('milestone(result, "renderer_sandbox_verified")')
    pass_assignment = source.index('result["passed"] = True')
    require(
        functional_end < sandbox_check < sandbox_milestone < pass_assignment,
        "overall PASS can occur before functional and sandbox verification",
    )

    tree = ast.parse(source)
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "process_argument_present"
    )
    namespace = {"re": re}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), "smoke-helper", "exec"), namespace)
    argument_present = namespace["process_argument_present"]
    require(argument_present(["/usr/lib/chromium/chromium", "--type=renderer"], "--type=renderer"), "normal renderer argv rejected")
    require(argument_present(["/usr/lib/chromium/chromium --type=renderer --lang=en"], "--type=renderer"), "rewritten renderer title rejected")
    require(argument_present(["chromium --no-sandbox=true"], "--no-sandbox"), "forbidden argument with value missed")
    require(not argument_present(["chromium --not-no-sandbox"], "--no-sandbox"), "argument substring produced a false match")


def parse_minimal_app_manifest(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    active_list: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        require("\t" not in raw_line, f"tab in App manifest line {line_number}")
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line.startswith("  - "):
            require(active_list is not None, f"unexpected list item at line {line_number}")
            value = raw_line[4:].strip()
            require(isinstance(result[active_list], list), "invalid list state")
            result[active_list].append(value)
            continue
        require(not raw_line.startswith(" "), f"unsupported nesting at line {line_number}")
        require(":" in raw_line, f"missing mapping separator at line {line_number}")
        key, raw_value = raw_line.split(":", 1)
        value = raw_value.strip()
        active_list = None
        require(key not in result, f"duplicate App manifest key: {key}")
        if not value:
            result[key] = []
            active_list = key
        elif value in {"true", "false"}:
            result[key] = value == "true"
        elif value == "{}":
            result[key] = {}
        elif value.startswith('"') and value.endswith('"'):
            result[key] = value[1:-1]
        else:
            result[key] = value
    return result


def verify_prebuilt_ha_app() -> None:
    manifest = parse_minimal_app_manifest(HA_CONFIG)
    required_keys = {"name", "version", "slug", "description", "arch", "image"}
    allowed_keys = {
        *required_keys,
        "url",
        "startup",
        "boot",
        "init",
        "stage",
        "host_network",
        "host_pid",
        "host_ipc",
        "host_uts",
        "host_dbus",
        "hassio_api",
        "homeassistant_api",
        "auth_api",
        "docker_api",
        "full_access",
        "apparmor",
        "audio",
        "video",
        "gpio",
        "usb",
        "uart",
        "udev",
        "devicetree",
        "kernel_modules",
        "realtime",
        "journald",
        "ingress",
        "stdin",
        "options",
        "schema",
    }
    require(required_keys.issubset(manifest), "required App manifest key missing")
    require(not set(manifest).difference(allowed_keys), "unsupported App manifest key")
    require(manifest.get("version") == APP_VERSION, "unexpected App image version")
    require(manifest.get("image") == GHCR_IMAGE, "unexpected prebuilt App image")
    require(manifest.get("arch") == ["amd64"], "App must remain amd64-only")
    require(manifest.get("startup") == "once", "runtime gate must run once")
    require(manifest.get("boot") == "manual", "runtime gate must start manually")
    require(manifest.get("apparmor") is True, "AppArmor must remain enabled")
    for key in (
        "host_network",
        "host_pid",
        "host_ipc",
        "host_uts",
        "host_dbus",
        "hassio_api",
        "homeassistant_api",
        "auth_api",
        "docker_api",
        "full_access",
        "audio",
        "video",
        "gpio",
        "usb",
        "uart",
        "udev",
        "devicetree",
        "kernel_modules",
        "realtime",
        "journald",
        "ingress",
        "stdin",
    ):
        require(manifest.get(key) is False, f"forbidden App permission enabled: {key}")
    for key in ("ports", "map", "devices", "privileged"):
        require(key not in manifest, f"unnecessary App resource declared: {key}")
    require(not HA_APP_ROOT.joinpath("Dockerfile").exists(), "HA wrapper must not build locally")

    workflow_requirements = (
        'tags:\n      - "collector-runtime-v*"',
        f"IMAGE: {GHCR_IMAGE}",
        "platforms: linux/amd64",
        "context: ./poc/collector-runtime",
        "push: true",
        "sbom: true",
        "provenance: mode=max",
        "Refuse to overwrite immutable tags",
        'version="${GITHUB_REF_NAME#collector-runtime-v}"',
        "steps.publish.outputs.digest",
        "image-digest.txt",
    )
    for requirement in workflow_requirements:
        require(requirement in PUBLISH_WORKFLOW, f"publish workflow requirement missing: {requirement}")
    require("latest" not in PUBLISH_WORKFLOW.lower(), "mutable latest tag is forbidden")
    require("pull_request_target" not in PUBLISH_WORKFLOW, "unsafe workflow trigger")
    action_refs = re.findall(r"(?m)^\s*uses:\s*[^\s]+@([^\s#]+)", PUBLISH_WORKFLOW)
    require(action_refs, "no GitHub Actions dependencies found")
    require(
        all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_refs),
        "GitHub Actions dependencies must be pinned to commit SHAs",
    )


def verify_current_files() -> None:
    require(
        not ROOT.joinpath("docker-compose.yml").exists(),
        "ambiguous legacy Compose manifest is forbidden",
    )
    verify_dockerfile(DOCKERFILE)
    verify_smoke_diagnostics(SMOKE_TEST)
    verify_minimal_sandbox_gate(SMOKE_TEST)
    verify_prebuilt_ha_app()
    arguments = configured_chromium_arguments(SMOKE_TEST)
    require(not arguments.intersection(FORBIDDEN_FLAGS), "forbidden Chromium flag")

    lowered = f"{DOCKERFILE}\n{COMPOSE}".lower()
    require("network_mode: none" in COMPOSE, "network namespace is not isolated")
    require("cap_drop:" in COMPOSE and "- all" in COMPOSE.lower(), "cap_drop ALL missing")
    require("no-new-privileges:true" in COMPOSE, "no-new-privileges is missing")
    require("privileged:" not in COMPOSE, "privileged mode declared")
    for key in ("cap_add:", "ports:", "volumes:", "devices:", "full_access:"):
        require(key not in COMPOSE, f"forbidden Compose setting: {key}")
    require("sys_admin" not in lowered, "SYS_ADMIN declared")
    require("net_admin" not in lowered, "NET_ADMIN declared")


def verify_regression_guard() -> None:
    old_assumption = DOCKERFILE.replace(
        '&& test "$(dpkg-query -W -f=\'${db:Status-Status}\' chromium-sandbox)" = "installed" \\\n',
        "&& ! dpkg-query -W chromium-sandbox >/dev/null 2>&1 \\\n",
    )
    require(old_assumption != DOCKERFILE, "regression fixture substitution failed")
    try:
        verify_dockerfile(old_assumption)
    except AssertionError:
        pass
    else:
        raise AssertionError("obsolete chromium-sandbox absence assertion was accepted")

    missing_passwd = DOCKERFILE.replace('      passwd="${PASSWD_VERSION}" \\\n', "")
    try:
        verify_dockerfile(missing_passwd)
    except AssertionError:
        pass
    else:
        raise AssertionError("missing passwd package was accepted")

    path_dependent = DOCKERFILE.replace("RUN /usr/sbin/groupadd", "RUN groupadd")
    try:
        verify_dockerfile(path_dependent)
    except AssertionError:
        pass
    else:
        raise AssertionError("PATH-dependent groupadd was accepted")

    unknown_command = DOCKERFILE.replace(
        "RUN chmod 0555 /opt/collector/smoke_test.py",
        "RUN unaudited-command && chmod 0555 /opt/collector/smoke_test.py",
    )
    try:
        verify_dockerfile(unknown_command)
    except AssertionError:
        pass
    else:
        raise AssertionError("RUN command without an audited provider was accepted")

    for mutation, message in (
        (SMOKE_TEST.replace('service_args=["--verbose"]', "service_args=[]"), "verbose logging"),
        (SMOKE_TEST.replace("LOG_TAIL_MAX_LINES = 200", "LOG_TAIL_MAX_LINES = 200000"), "log bound"),
        (SMOKE_TEST.replace("log_path.chmod(0o600)", ""), "private log mode"),
    ):
        require(mutation != SMOKE_TEST, f"{message} regression substitution failed")
        try:
            verify_smoke_diagnostics(mutation)
        except (AssertionError, ValueError):
            pass
        else:
            raise AssertionError(f"missing {message} was accepted")

    weakened_seccomp = SMOKE_TEST.replace(
        'renderer.get("seccomp") == "2"',
        'renderer.get("seccomp") == "0"',
    )
    require(weakened_seccomp != SMOKE_TEST, "seccomp regression substitution failed")
    try:
        verify_minimal_sandbox_gate(weakened_seccomp)
    except AssertionError:
        pass
    else:
        raise AssertionError("weakened seccomp requirement was accepted")


if __name__ == "__main__":
    verify_current_files()
    verify_regression_guard()
    audited_commands = sorted(run_command_names(DOCKERFILE))
    print(
        "collector-runtime static verification: PASS "
        f"({len(audited_commands)} RUN commands audited: "
        f"{', '.join(audited_commands)})"
    )
