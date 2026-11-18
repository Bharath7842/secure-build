"""Collector registry — single source of truth for which ecosystems can be collected.

Imported by both the ecosystem detection node (to decide `collector` / `status`)
and the dependency node (to dispatch collection), so detection and collection can
never disagree.
"""

from .base import DependencyCollector
from .cargo import CargoCollector
from .clojure import ClojureCollector
from .composer import ComposerCollector
from .cpp import CppCollector
from .crystal import CrystalCollector
from .dart import DartCollector
from .deno import DenoCollector
from .docker import DockerCollector
from .elm import ElmCollector
from .golang import GoCollector
from .gradle import GradleCollector
from .haskell import HaskellCollector
from .hex import HexCollector
from .julia import JuliaCollector
from .maven import MavenCollector
from .npm import NpmCollector
from .nuget import NuGetCollector
from .perl import PerlCollector
from .python import PythonCollector
from .r import RCollector
from .ruby import RubyCollector
from .sbt import SbtCollector
from .swift import SwiftCollector
from .terraform import TerraformCollector

__all__ = [
    "CLI_SOURCE_MARKERS",
    "COLLECTOR_MAP",
    "LOCKFILE_MARKERS",
    "MANIFEST_MARKERS",
    "SUPPORTED_ECOSYSTEMS",
    "DependencyCollector",
]

COLLECTOR_MAP: dict[str, DependencyCollector] = {
    "maven": MavenCollector(),
    "gradle": GradleCollector(),
    "npm": NpmCollector(),
    "python": PythonCollector(),
    "go": GoCollector(),
    "cargo": CargoCollector(),
    "nuget": NuGetCollector(),
    "composer": ComposerCollector(),
    "ruby": RubyCollector(),
    "swift": SwiftCollector(),
    "dart": DartCollector(),
    "cpp": CppCollector(),
    "docker": DockerCollector(),
    "hex": HexCollector(),
    "julia": JuliaCollector(),
    "terraform": TerraformCollector(),
    "deno": DenoCollector(),
    "sbt": SbtCollector(),
    "clojure": ClojureCollector(),
    "r": RCollector(),
    "haskell": HaskellCollector(),
    "elm": ElmCollector(),
    "crystal": CrystalCollector(),
    "perl": PerlCollector(),
}

SUPPORTED_ECOSYSTEMS: frozenset[str] = frozenset(COLLECTOR_MAP)

# ``source_file`` values written by CLI fallback paths (§5.3), used by the
# dependency node to report how a collector sourced each ecosystem's components.
CLI_SOURCE_MARKERS: frozenset[str] = frozenset({
    "npm ls",
    "dependency:tree",
    "gradle dependencies",
    "go list -m all",
    "cargo metadata",
    "dotnet list package --json",
    "composer show --json",
    "bundle list --parseable",
    "swift package show-dependencies --json",
    "dart pub deps --json",
    "pip list",
})

# Markers used to detect an ecosystem (§5.1/§5.2): manifests and lockfiles.
MANIFEST_MARKERS: dict[str, list[str]] = {
    "maven": ["pom.xml"],
    "gradle": ["build.gradle", "build.gradle.kts"],
    "npm": ["package.json"],
    "python": ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"],
    "go": ["go.mod"],
    "cargo": ["Cargo.toml"],
    "nuget": ["*.csproj", "*.fsproj", "*.vbproj", "packages.config", "Directory.Packages.props"],
    "composer": ["composer.json"],
    "ruby": ["Gemfile", "*.gemspec"],
    "swift": ["Package.swift", "Podfile"],
    "dart": ["pubspec.yaml"],
    "cpp": ["conanfile.txt", "conanfile.py", "vcpkg.json", "CMakeLists.txt"],
    "hex": ["mix.exs"],
    "julia": ["Project.toml", "Manifest.toml"],
    "terraform": ["*.tf", "*.tf.json"],
    "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    "deno": ["deno.json", "deno.jsonc"],
    "sbt": ["build.sbt"],
    "clojure": ["deps.edn", "project.clj"],
    "r": ["DESCRIPTION"],
    "haskell": ["stack.yaml", "package.yaml", "*.cabal"],
    "elm": ["elm.json"],
    "crystal": ["shard.yml"],
    "perl": ["cpanfile", "META.json"],
}

LOCKFILE_MARKERS: dict[str, list[str]] = {
    "maven": ["pom.xml"],
    "gradle": ["gradle.lockfile", "libs.versions.toml"],
    "npm": ["npm-shrinkwrap.json", "bun.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "python": ["uv.lock", "pdm.lock", "poetry.lock", "Pipfile.lock", "requirements.txt"],
    "go": ["go.sum"],
    "cargo": ["Cargo.lock"],
    "nuget": ["packages.lock.json", "project.assets.json"],
    "composer": ["composer.lock"],
    "ruby": ["Gemfile.lock"],
    "swift": ["Package.resolved", "Podfile.lock"],
    "dart": ["pubspec.lock"],
    "cpp": ["conan.lock", "vcpkg.json"],
    "hex": ["mix.lock"],
    "julia": ["Manifest.toml"],
    "terraform": [".terraform.lock.hcl"],
    "docker": [],
    "deno": ["deno.lock"],
    "sbt": [],
    "clojure": [],
    "r": ["renv.lock"],
    "haskell": ["stack.yaml.lock", "cabal.project.freeze"],
    "elm": [],
    "crystal": ["shard.lock"],
    "perl": ["cpanfile.snapshot"],
}

# Ecosystems we can detect but whose dependency collection is not implemented (§5).
DETECTED_ONLY_ECOSYSTEMS: frozenset[str] = frozenset(
    set(MANIFEST_MARKERS) - SUPPORTED_ECOSYSTEMS
)
