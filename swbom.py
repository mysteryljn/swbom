#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

def parse_requirements(path):
    components=[]
    for line in path.read_text(encoding="utf-8").splitlines():
        line=line.strip()
        if not line or line.startswith("#") or line.startswith("-"): continue
        match=re.match(r"([A-Za-z0-9_.-]+)\s*([=<>!~].*)?$",line)
        if match: components.append({"name":match.group(1),"version":(match.group(2) or "").lstrip("=<>!~ ") or "UNKNOWN","type":"python"})
    return components

def parse_package_lock(path):
    data=json.loads(path.read_text(encoding="utf-8")); components=[]; packages=data.get("packages",{})
    for location,info in packages.items():
        if not location or not isinstance(info, dict): continue
        name = info.get("name")
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
        if isinstance(dependencies, dict):
            add_dependencies(dependencies)
    return components

def generate(path):
    components=parse_package_lock(path) if path.name=="package-lock.json" else parse_requirements(path)
    return {"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"source":str(path)},"components":sorted(components,key=lambda item:(item["type"],item["name"]))}

def main(argv=None):
    parser=argparse.ArgumentParser(description="Generate a small offline SBOM"); parser.add_argument("input",type=Path); parser.add_argument("-o","--output",type=Path,required=True); args=parser.parse_args(argv)
    try: bom=generate(args.input); args.output.write_text(json.dumps(bom,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    except (OSError,json.JSONDecodeError) as exc: print(f"error: {exc}"); return 2
    print(f"wrote {args.output} ({len(bom['components'])} components)"); return 0

if __name__=="__main__": raise SystemExit(main())
