#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

def parse_requirements(path):
    components=[]
    for line in path.read_text(encoding="utf-8").splitlines():
        line=line.strip()
        if not line or line.startswith("#"): continue
        # Editable VCS requirements are valid pip input, but their leading
        # ``-e``/``--editable`` option used to make them disappear from the
        # SBOM.  The egg fragment is the package name supplied by pip when
        # the URL itself does not carry a distribution filename.
        if line.startswith(("-e ", "--editable ")):
            target = line.split(None, 1)[1].strip()
            egg = re.search(r"(?:^|[#&])egg=([A-Za-z0-9_.-]+)(?:&|$)", target)
            if egg:
                components.append({"name":egg.group(1),"version":"UNKNOWN","type":"python"})
            continue
        if line.startswith("-"): continue
        # PEP 508 allows an inline comment after whitespace.  Keep URL
        # fragments intact while removing comments from pinned versions;
        # otherwise the comment becomes part of the version and prevents
        # exact SBOM/vulnerability matching.
        line = re.split(r"\s+#", line, maxsplit=1)[0].rstrip()
        # Environment markers qualify a requirement but do not change which
        # distribution belongs in the SBOM.  This offline tool cannot
        # evaluate the target interpreter, so retain the package and remove
        # the marker before parsing its version specifier.
        line = line.split(";", 1)[0].rstrip()
        # Extras identify the same distribution and must not make an
        # otherwise valid requirement disappear from the SBOM.
        direct = re.match(
            r"^([A-Za-z0-9_.-]+)(?:\s*\[[A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*\])?"
            r"\s*@\s*\S+$",
            line,
        )
        if direct:
            # A direct URL/VCS reference has no reliable version without
            # downloading package metadata; retaining it as UNKNOWN is
            # safer than silently omitting a dependency from the SBOM.
            components.append({"name":direct.group(1),"version":"UNKNOWN","type":"python"})
            continue
        # pip also accepts a bare archive/VCS URL with an ``#egg`` fragment.
        # Keep these dependencies visible for the same reason as PEP 508
        # direct references above.
        egg = re.search(r"(?:^|[#&])egg=([A-Za-z0-9_.-]+)(?:&|$)", line)
        if egg and (line.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://"))):
            components.append({"name":egg.group(1),"version":"UNKNOWN","type":"python"})
            continue
        match=re.match(
            r"([A-Za-z0-9_.-]+)(?:\s*\[[A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*\])?"
            r"\s*([=<>!~].*)?$",
            line,
        )
        if match:
            specifier = match.group(2) or ""
            # A comma joins multiple PEP 440 constraints (for example
            # ``foo>=1.0,<2.0``), so stripping the first operator would
            # produce the invalid pseudo-version ``1.0,<2.0``.  Emitting
            # that value makes downstream vulnerability matching treat a
            # range as an exact version.  Keep the existing lower-bound
            # behavior for single constraints, but mark compound ranges as
            # unknown because this lightweight SBOM has no resolver.
            version = "UNKNOWN" if "," in specifier else specifier.lstrip("=<>!~ ") or "UNKNOWN"
            components.append({"name":match.group(1),"version":version,"type":"python"})
    return components

def parse_package_lock(path):
    data=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("package-lock must be a JSON object")
    components=[]; packages=data.get("packages",{})
    if packages is None:
        packages={}
    if not isinstance(packages, dict):
        raise ValueError("package-lock packages must be an object")
    for location,info in packages.items():
        if not location or not isinstance(info, dict): continue
        name = info.get("name")
        if name is not None and not isinstance(name, str):
            raise ValueError("package-lock package name must be a string")
        if not name:
            # npm lockfile v2/v3 entries commonly omit ``name``; derive it
            # from the final node_modules path (including scoped packages).
            match = re.search(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/]+)$", location)
            if match:
                name = match.group(1)
        if not name:
            continue
        components.append({"name":name,"version":info.get("version","UNKNOWN"),"type":"npm"})
    if not components:
        def add_dependencies(dependencies):
            for name, info in dependencies.items():
                if not isinstance(info, dict):
                    continue
                components.append({"name":name,"version":info.get("version","UNKNOWN"),"type":"npm"})
                nested = info.get("dependencies",{})
                if isinstance(nested, dict):
                    add_dependencies(nested)

        dependencies = data.get("dependencies",{})
        if dependencies is None:
            dependencies={}
        if not isinstance(dependencies, dict):
            raise ValueError("package-lock dependencies must be an object")
        if isinstance(dependencies, dict):
            add_dependencies(dependencies)
    return components

def generate(path):
    components=parse_package_lock(path) if path.name=="package-lock.json" else parse_requirements(path)
    return {"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"source":str(path)},"components":sorted(components,key=lambda item:(item["type"],item["name"]))}

def main(argv=None):
    parser=argparse.ArgumentParser(description="Generate a small offline SBOM"); parser.add_argument("input",type=Path); parser.add_argument("-o","--output",type=Path,required=True); args=parser.parse_args(argv)
    try: bom=generate(args.input); args.output.write_text(json.dumps(bom,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    # Requirements and lockfiles are external artifacts.  Invalid UTF-8
    # should be reported as a normal input error instead of leaking a
    # UnicodeDecodeError traceback from Path.read_text().
    except (OSError,json.JSONDecodeError,UnicodeError,ValueError,TypeError) as exc: print(f"error: {exc}"); return 2
    print(f"wrote {args.output} ({len(bom['components'])} components)"); return 0

if __name__=="__main__": raise SystemExit(main())
