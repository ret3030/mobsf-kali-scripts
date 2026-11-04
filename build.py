#!/usr/bin/env python3
"""Build the Android Application Penetration Testing guide.

    python3 build.py        # whole book -> android-pentest-guide.pdf

Sources live in src/: preamble.tex, frontmatter.tex, chapters/NN-*.tex.
Requires tectonic. Intermediate files go to build/.
"""
import subprocess, pathlib

here = pathlib.Path(__file__).resolve().parent
src = here / "src"
build = here / "build"
build.mkdir(exist_ok=True)

# (part title, [chapter numbers]); numbers match the file prefixes in src/chapters
PARTS = [
    ("Foundations", ["00"]),
    ("Static Review", ["01", "02"]),
    ("Dynamic Analysis", ["03", "04", "05"]),
    ("Reporting", ["06"]),
]


def chapter_file(num):
    hits = sorted((src / "chapters").glob(f"{num}-*.tex"))
    if not hits:
        raise SystemExit(f"no chapter {num} in src/chapters")
    return hits[0]


def build_book():
    body = [(src / "frontmatter.tex").read_text(), "\\mainmatter\n"]
    for ptitle, nums in PARTS:
        body.append(f"\\part{{{ptitle}}}\n")
        for num in nums:
            if num == "00":
                body.append("\\setcounter{chapter}{-1}\n")
            body.append(chapter_file(num).read_text())
    doc = ((src / "preamble.tex").read_text() + "\n\\begin{document}\n"
           + "\n".join(body) + "\n\\end{document}\n")
    (build / "android-pentest-guide.tex").write_text(doc)
    subprocess.run(["tectonic", "-c", "minimal", "android-pentest-guide.tex"],
                   cwd=build, check=True)
    (build / "android-pentest-guide.pdf").replace(here / "android-pentest-guide.pdf")
    print("done:", here / "android-pentest-guide.pdf")


if __name__ == "__main__":
    build_book()
