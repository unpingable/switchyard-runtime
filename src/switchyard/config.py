from __future__ import annotations

import hashlib
import os
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BackendIdentity:
    executable: Path
    version: str
    sha256: str
    home: Path

    @property
    def command(self) -> list[str]:
        return [str(self.executable), "app-server", "--listen", "stdio://"]

    @property
    def environment(self) -> dict[str, str]:
        return {"CODEX_HOME": str(self.home)}

    def as_dict(self) -> dict[str, str]:
        return {
            "executable": str(self.executable),
            "version": self.version,
            "sha256": self.sha256,
            "home": str(self.home),
        }


@dataclass(frozen=True)
class Config:
    github_repo: str | None
    allowed_actors: frozenset[str]
    dispatch_label: str
    poll_seconds: float
    state_path: Path
    codex_executable: Path
    codex_expected_version: str
    codex_expected_sha256: str
    codex_home: Path
    cwd_allow_roots: tuple[Path, ...]
    allow_interrupt: bool
    allow_approval_responses: bool
    enable_deprecated_github_mailbox: bool = False
    native_host_name: str = "com.switchyard.bridge"
    allowed_extension_ids: frozenset[str] = frozenset()
    allowed_origins: frozenset[str] = frozenset()

    @classmethod
    def load(cls, path: Path) -> "Config":
        with path.open('rb') as handle:
            data = tomllib.load(handle)
        github = data.get('github', {})
        runtime = data.get('runtime', {})
        codex = data.get('codex', {})
        safety = data.get('safety', {})
        browser = data.get('browser', {})

        repo_obj = github.get('repo')
        repo = str(repo_obj) if isinstance(repo_obj, str) and repo_obj else None
        actors_obj = github.get('allowed_actors', [])
        if not isinstance(actors_obj, list):
            raise ValueError('github.allowed_actors must be a list when supplied')
        actors = frozenset(str(actor) for actor in actors_obj if str(actor))
        enable_deprecated = bool(github.get('enable_deprecated_adapter', False))
        if enable_deprecated:
            if repo is None or '/' not in repo:
                raise ValueError('github.repo must be owner/name when the deprecated adapter is enabled')
            if not actors:
                raise ValueError(
                    'github.allowed_actors must be a non-empty list when the deprecated adapter is enabled'
                )
        elif repo is not None and '/' not in repo:
            raise ValueError('github.repo must be owner/name when supplied')

        state_text = str(runtime.get('state_path', '~/.local/state/switchyard/state.sqlite3'))
        state_path = Path(os.path.expanduser(state_text)).resolve()
        executable = Path(_required_string(codex, 'executable')).expanduser()
        expected_version = _required_string(codex, 'expected_version')
        expected_sha256 = _required_string(codex, 'expected_sha256').lower()
        home = Path(_required_string(codex, 'home')).expanduser()
        if len(expected_sha256) != 64 or any(
            char not in '0123456789abcdef' for char in expected_sha256
        ):
            raise ValueError('codex.expected_sha256 must be a 64-character hexadecimal SHA256')

        roots = codex.get('cwd_allow_roots', [])
        if not isinstance(roots, list) or not roots:
            raise ValueError('codex.cwd_allow_roots must be a non-empty list')
        root_paths = tuple(Path(os.path.expanduser(str(root))).resolve() for root in roots)

        extension_ids_obj = browser.get('allowed_extension_ids', [])
        if not isinstance(extension_ids_obj, list):
            raise ValueError('browser.allowed_extension_ids must be a list when supplied')
        origins_obj = browser.get('allowed_origins', [])
        if not isinstance(origins_obj, list):
            raise ValueError('browser.allowed_origins must be a list when supplied')

        return cls(
            github_repo=repo,
            allowed_actors=actors,
            dispatch_label=str(github.get('dispatch_label', 'codex-dispatch')),
            poll_seconds=float(runtime.get('poll_seconds', 15.0)),
            state_path=state_path,
            codex_executable=executable,
            codex_expected_version=expected_version,
            codex_expected_sha256=expected_sha256,
            codex_home=home,
            cwd_allow_roots=root_paths,
            allow_interrupt=bool(safety.get('allow_interrupt', False)),
            allow_approval_responses=bool(safety.get('allow_approval_responses', False)),
            enable_deprecated_github_mailbox=enable_deprecated,
            native_host_name=str(browser.get('native_host_name', 'com.switchyard.bridge')),
            allowed_extension_ids=frozenset(
                str(extension_id) for extension_id in extension_ids_obj if str(extension_id)
            ),
            allowed_origins=frozenset(str(origin) for origin in origins_obj if str(origin)),
        )

    def validate_cwd(self, cwd: str) -> Path:
        candidate = Path(os.path.expanduser(cwd)).resolve()
        allowed = any(
            candidate == root or candidate.is_relative_to(root)
            for root in self.cwd_allow_roots
        )
        if not allowed:
            roots = ', '.join(str(root) for root in self.cwd_allow_roots)
            raise ValueError(f'cwd {candidate} is outside allowlisted roots: {roots}')
        return candidate

    def verify_backend(self) -> BackendIdentity:
        """Verify the exact qualified backend without changing its installation."""
        executable = self.codex_executable
        if not executable.is_absolute():
            raise ValueError('codex.executable must be an absolute path')
        try:
            resolved_executable = executable.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError(f'codex executable does not exist: {executable}') from exc
        if resolved_executable != executable:
            raise ValueError(
                f'codex executable resolves unexpectedly: {executable} -> {resolved_executable}'
            )
        if not resolved_executable.is_file() or not os.access(resolved_executable, os.X_OK):
            raise ValueError(f'codex executable is not an executable file: {resolved_executable}')

        digest = hashlib.sha256()
        with resolved_executable.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        observed_sha256 = digest.hexdigest()
        if observed_sha256 != self.codex_expected_sha256:
            raise ValueError(
                'codex executable SHA256 mismatch: '
                f'expected {self.codex_expected_sha256}, observed {observed_sha256}'
            )

        if not self.codex_home.is_absolute():
            raise ValueError('codex.home must be an absolute path')
        try:
            resolved_home = self.codex_home.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError(f'isolated CODEX_HOME does not exist: {self.codex_home}') from exc
        if not resolved_home.is_dir():
            raise ValueError(f'isolated CODEX_HOME is not a directory: {resolved_home}')
        global_home = (Path.home() / '.codex').resolve()
        if resolved_home == global_home:
            raise ValueError('isolated CODEX_HOME must not resolve to ~/.codex')

        environment = os.environ.copy()
        environment['CODEX_HOME'] = str(resolved_home)
        try:
            result = subprocess.run(
                [str(resolved_executable), '--version'],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError as exc:
            raise ValueError(f'unable to execute qualified Codex backend: {exc}') from exc
        observed_version = result.stdout.strip()
        if result.returncode != 0 or observed_version != self.codex_expected_version:
            detail = result.stderr.strip()
            raise ValueError(
                'codex version mismatch: '
                f'expected {self.codex_expected_version!r}, observed {observed_version!r}'
                + (f' ({detail})' if detail else '')
            )

        return BackendIdentity(
            executable=resolved_executable,
            version=observed_version,
            sha256=observed_sha256,
            home=resolved_home,
        )



def _required_string(table: dict[str, object], key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f'codex.{key} must be a non-empty string')
    return value
