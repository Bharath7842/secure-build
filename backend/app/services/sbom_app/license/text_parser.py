import logging
import re
from pathlib import Path

logger = logging.getLogger("sbom.license.text")

MAX_LICENSE_FILE_SIZE = 100 * 1024

LICENSE_PATTERNS = {
    "MIT": [
        r"permission is hereby granted, free of charge, to any person obtaining a copy",
        r"the above copyright notice and this permission notice shall be included",
        r"the software is provided .as is., without warranty of any kind",
    ],
    "Apache-2.0": [
        r"licensed under the apache license, version 2\.0",
        r"you may not use this file except in compliance with the license",
        r"copyright \d{4}.*licensed under the apache license",
        r"apache license,? version 2\.0, january 2004",
        r"terms and conditions for use, reproduction, and distribution",
    ],
    "GPL-2.0-only": [
        r"gnu general public license version 2",
        r"this program is free software; you can redistribute it and/or modify",
        r"terms and conditions for copying, distribution and modification",
    ],
    "GPL-3.0-only": [
        r"gnu general public license version 3",
        r"this program is free software: you can redistribute it and/or modify",
        r"terms and conditions for copying, distribution and modification",
    ],
    "LGPL-2.1-only": [
        r"gnu lesser general public license version 2\.1",
        r"this library is free software; you can redistribute it and/or modify",
    ],
    "LGPL-3.0-only": [
        r"gnu lesser general public license version 3",
        r"this library is free software; you can redistribute it and/or modify",
    ],
    "BSD-2-Clause": [
        r"redistribution and use in source and binary forms, with or without modification",
        r"this software is provided by the copyright holders and contributors .as is.",
        r"the name of the organization may not be used to endorse or promote products",
    ],
    "BSD-3-Clause": [
        r"redistribution and use in source and binary forms, with or without modification",
        r"neither the name of the copyright holder nor the names of its contributors may be used",
        r"this software is provided by the copyright holders and contributors .as is.",
    ],
    "ISC": [
        r"permission to use, copy, modify, and/or distribute this software for any purpose",
        r"the software is provided .as is., without warranty of any kind",
        r"provided .as is. and the author disclaims all warranties",
    ],
    "MPL-2.0": [
        r"mozilla public license version 2\.0",
        r"this source code form is subject to the terms of the mozilla public license",
    ],
    "Unlicense": [
        r"this is free and unencumbered software released into the public domain",
        r"anyone is free to copy, modify, publish, use, compile, sell, or distribute",
    ],
    "CC0-1.0": [
        r"creative commons legal code",
        r"cc0 1\.0 universal",
        r"the person who associated a work with this deed has waived all rights",
    ],
    "AGPL-3.0-only": [
        r"gnu affero general public license version 3",
        r"this program is free software: you can redistribute it and/or modify",
    ],
    "BSL-1.0": [
        r"boost software license.*version 1\.0",
        r"permission is hereby granted, free of charge, to any person or organization",
    ],
    "Artistic-2.0": [
        r"the artistic license",
        r"provided that the conditions described below in this document are met",
    ],
    "WTFPL": [
        r"do whatever you want to public license",
        r"version 2.*do whatever you want to",
    ],
    "0BSD": [
        r"zero clause BSD license",
        r"permission to use, copy, modify, and/or distribute this software for any purpose",
    ],
    "Zlib": [
        r"zlib license",
        r"this software is provided .as is., without warranty of any kind",
    ],
    "PostgreSQL": [
        r"postgresql free software licence",
        r"permission to use, copy, modify, and distribute this software and its documentation",
    ],
    "EPL-2.0": [
        r"eclipse public license",
        r"version 2\.0",
    ],
    "EPL-1.0": [
        r"eclipse public license",
        r"version 1\.0",
    ],
    "CPL-1.0": [
        r"common public license",
        r"version 1\.0",
    ],
    "CDDL-1.0": [
        r"common development and distribution license",
        r"version 1\.0",
    ],
}

LICENSE_FILE_PATTERNS = [
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "LICENSE.rst",
    "LICENCE",
    "LICENCE.txt",
    "LICENCE.md",
    "COPYING",
    "COPYING.txt",
    "COPYING.md",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "LICENSE.APACHE",
    "LICENSE.MIT",
]


class LicenseTextParser:

    def __init__(self):
        self._compiled_patterns = {}
        for spdx_id, patterns in LICENSE_PATTERNS.items():
            self._compiled_patterns[spdx_id] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def find_license_files(self, repo_path: Path) -> list[Path]:
        found = []
        for pattern in LICENSE_FILE_PATTERNS:
            for f in repo_path.rglob(pattern):
                if "node_modules" not in str(f) and "target" not in str(f):
                    try:
                        if f.stat().st_size <= MAX_LICENSE_FILE_SIZE:
                            found.append(f)
                    except OSError:
                        pass
        return found

    def match_license_content(self, content: str) -> tuple[str | None, int]:
        """Score ``content`` against the license table.

        Returns ``(spdx_id, match_score)``; a score >= 2 comes from the
        pattern table, score 1 from the keyword fallbacks, ``(None, 0)``
        when nothing matched. Shared by the file and in-memory (archive
        license text) paths. Whitespace is collapsed first so a phrase
        wrapped across lines in a real-world LICENSE file still matches.
        """
        normalized = re.sub(r"\s+", " ", content)
        best_match = None
        best_score = 0

        for spdx_id, patterns in self._compiled_patterns.items():
            matches = sum(1 for p in patterns if p.search(normalized))
            if matches > best_score:
                best_score = matches
                best_match = spdx_id

        if best_match and best_score >= 2:
            return best_match, best_score

        content_lower = normalized.lower()

        if "mit license" in content_lower or "permission is hereby granted, free of charge" in content_lower:
            return "MIT", 1
        if "apache license" in content_lower and "version 2.0" in content_lower:
            return "Apache-2.0", 1
        if "gnu general public license" in content_lower:
            if "version 3" in content_lower:
                return "GPL-3.0-only", 1
            return "GPL-2.0-only", 1
        if "gnu lesser general public license" in content_lower:
            if "version 3" in content_lower:
                return "LGPL-3.0-only", 1
            return "LGPL-2.1-only", 1
        if "mozilla public license" in content_lower:
            return "MPL-2.0", 1
        if "creative commons" in content_lower and "cc0" in content_lower:
            return "CC0-1.0", 1
        if "boost software license" in content_lower:
            return "BSL-1.0", 1
        if "artistic license" in content_lower:
            return "Artistic-2.0", 1
        if "the isc license" in content_lower:
            return "ISC", 1
        if "this is free and unencumbered software" in content_lower:
            return "Unlicense", 1
        if "zlib license" in content_lower or (
            "this software is provided 'as-is'" in content_lower
        ):
            return "Zlib", 1

        return None, 0

    def parse_license_text(self, file_path: Path) -> str | None:
        try:
            size = file_path.stat().st_size
            if size > MAX_LICENSE_FILE_SIZE:
                return None
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        spdx_id, _score = self.match_license_content(content)
        return spdx_id

    def match_license_candidates(self, content: str) -> list[tuple[str, int]]:
        """Every id whose patterns score >= 2 in ``content``, best first.

        Package archives often ship one file containing two license texts
        (dual-licensed packages); verification must consider both. Falls
        back to the keyword path when no table clears the threshold.
        """
        normalized = re.sub(r"\s+", " ", content)
        scored: list[tuple[str, int]] = []
        for spdx_id, patterns in self._compiled_patterns.items():
            score = sum(1 for p in patterns if p.search(normalized))
            if score >= 2:
                scored.append((spdx_id, score))
        if scored:
            scored.sort(key=lambda pair: -pair[1])
            return scored
        spdx_id, score = self.match_license_content(content)
        return [(spdx_id, score)] if spdx_id else []

    def get_confidence(self, spdx_id: str | None, match_score: int = 0) -> float:
        if not spdx_id:
            return 0.0
        if match_score >= 3:
            return 0.95
        if match_score >= 2:
            return 0.85
        return 0.7
