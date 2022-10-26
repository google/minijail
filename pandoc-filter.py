#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=locally-disabled
# pylint: disable=too-few-public-methods
# pylint: disable=missing-docstring

"""Filter to improve the man->markdown conversion with pandoc.

Run with no options to run pandoc with the right settings.
"""

import argparse
from pathlib import Path
import re
import subprocess
import sys

from pandocfilters import *  # pylint: disable=wildcard-import,unused-wildcard-import


FILE = Path(__file__).resolve()
DIR = FILE.parent

# Alias for stub attributes.
NoAttrs = attributes({})


def dbg(*args, **kwargs):
    """Helper for quick printf-style debugging."""
    assert "file" not in kwargs
    kwargs["file"] = sys.stderr
    print(*args, **kwargs)


def ghanchor(text):
    """Generate anchor link that GitHub pages use."""
    return "#" + re.sub(r"[()/]", "", text.lower().replace(" ", "-"))


def NewLink(text, url):
    """Convenience method for constructing new Link objects."""
    if not isinstance(text, list):
        if not isinstance(text, dict):
            text = Str(text)
        text = [text]
    return Link(NoAttrs, text, [url, ""])


class ActionVisitor:
    """Base class to implement visitor pattern as an action.

    Classes derive from this implement visit_<element> methods.
    e.g. visit_str() for Str() elements.
    """

    def __call__(self, key, value, format, meta):
        # These aren't normally used, nor changed, so be lazy and pass them as
        # properties rather than function arguments.
        self.format = format
        self.meta = meta

        method_name = "visit_" + key.lower()
        func = getattr(self, method_name, None)
        if func:
            return func(key, value)


class AutoLinkUris(ActionVisitor):
    """Automatically link URIs."""

    def __init__(self):
        self.relinked = False

    def visit_str(self, key, value):
        if value.startswith("http"):
            # When we create a new Str node, we'll get called right away for it.
            # Ignore the next Str call with our content.
            if self.relinked == value:
                self.relinked = None
                return
            self.relinked = value
            return NewLink(value, value)


class AutoLinkMans(ActionVisitor):
    """Automatically link references to other manpages."""

    @staticmethod
    def link_man7(sect, page):
        return "https://man7.org/linux/man-pages/man%(sect)s/%(page)s.%(sect)s.html" % {
            "sect": sect,
            "page": page,
        }

    @staticmethod
    def link_kdoc(page):
        # |page| will be Documentation/prctl/no_new_privs.txt.  Transform it.
        page = page[14:-4]
        return f"https://docs.kernel.org/{page}.html"

    @staticmethod
    def link_source(page):
        return f"https://github.com/google/minijail/blob/HEAD/{page}"

    @staticmethod
    def link_local(sect, page):
        return f"./{page}.{sect}"

    def visit_para(self, key, value):
        # NB: We use paragraphs because we need to look for consecutive nodes:
        # Strong(Str("nohup")) Str("(1)")
        # {'t': 'Strong', 'c': [{'t': 'Str', 'c': 'minijail0'}]}
        # {'t': 'Strong', 'c': [{'c': 'libminijail.h', 't': 'Str'}]}
        #
        # {'t': 'Emph', 'c': [{'c': 'Documentation/prctl/no_new_privs.txt', 't': 'Str'}]}
        for i, ele in enumerate(value):
            replace_count = 0

            if ele["t"] == "Emph":
                page = ele["c"][0]["c"]
                if page.startswith("Documentation/"):
                    url = self.link_kdoc(page)
                    text = [Emph([Str(page)])]
                    replace_count = 1
                    new_eles = [NewLink(text, url)]
            elif ele["t"] == "Strong":
                page = ele["c"][0]["c"]
                if page in {"libminijail.h"}:
                    text = [Strong([Str(page)])]
                    url = self.link_source(page)
                    replace_count = 1
                    new_eles = [NewLink(text, url)]
                elif i + 1 < len(value):
                    next_ele = value[i + 1]
                    if next_ele["t"] == "Str":
                        m = re.match(r"\(([0-9])\)(.*)", next_ele["c"])
                        if m:
                            sect = m.group(1)
                            rem = m.group(2)
                            text = [Strong([Str(page)]), Str("(" + sect + ")")]
                            if page in {"minijail0"}:
                                url = self.link_local(sect, page)
                            else:
                                url = self.link_man7(sect, page)
                            new_eles = [NewLink(text, url)]
                            if rem:
                                new_eles.append(Str(rem))
                            replace_count = 2

            if replace_count:
                value[:] = value[0:i] + new_eles + value[i + replace_count :]


class AutoLinkSections(ActionVisitor):
    """Automatically link references to other sections in the page."""

    def __init__(self, get_toc):
        self.get_toc = get_toc

    def visit_strong(self, key, value):
        text = stringify(value)
        if text in self.get_toc.sections:
            value[:] = [NewLink(text, ghanchor(text))]


class ConvertNameSectionToTitle(ActionVisitor):
    """Convert first NAME header to a title for the whole page.

    The .TH doesn't seem to be handled well, so we have to fake it.
    Plus the .SH NAME is a bit redundant.

    Header
     [1, ['', [], []], [{'c': 'NAME', 't': 'Str'}]]
    Para
     [{'c': 'nosig', 't': 'Str'}, {'t': 'Space'}, {'c': '-', 't': 'Str'},
     {'t': 'Space'}, {'c': 'run', 't': 'Str'}, {'t': 'Space'},
     {'c': 'a', 't': 'Str'}, {'t': 'Space'}, {'c': 'program', 't': 'Str'},
     {'t': 'Space'}, {'c': 'with', 't': 'Str'}, {'t': 'Space'},
     {'c': 'specified', 't': 'Str'}, {'t': 'Space'}, {'c': 'signals', 't': 'Str'},
     {'t': 'Space'}, {'c': 'blocked', 't': 'Str'}]
    """

    def __init__(self, get_name, get_toc):
        self.done = False
        self.get_name = get_name
        self.get_toc = get_toc

    def visit_header(self, key, value):
        """Grab the first header."""
        if value[0] != 1:
            return

        # Sanity check this is the first header as we expect.
        assert value[0] == 1
        assert stringify(value[2]) == "NAME"

        return self.get_name.render()

    def visit_para(self, key, value):
        """Rewrite the into paragraph.

        We'll rip the existing text into the title, and then insert the TOC.
        """
        if self.done:
            return

        self.done = True

        # Replace the paragraph with the TOC.
        return self.get_toc.render()


class GatherName(ActionVisitor):
    """Find the first NAME section to turn into title for the whole page.

    The .TH doesn't seem to be handled well, so we have to fake it.
    Plus the .SH NAME is a bit redundant.

    Header
     [1, ['', [], []], [{'c': 'NAME', 't': 'Str'}]]
    Para
     [{'c': 'nosig', 't': 'Str'}, {'t': 'Space'}, {'c': '-', 't': 'Str'}, ...]
    """

    def __init__(self):
        self.title = None

    def render(self):
        """Return the captured NAME section as a single string."""
        return Header(1, NoAttrs, [Str(self.title)])

    def visit_para(self, key, value):
        """Assume the first paragraph is the NAME we want."""
        if self.title:
            return

        # This will be a normal node:
        # {'t': 'MetaInlines', 'c': [{'t': 'Str', 'c': '5'}]}
        section = self.meta["section"]["c"][0]["c"]

        # This turns "nosig - foo" into "nosig(1): foo" for the title.
        eles = stringify(value).split()
        eles[0] += f"({section}):"
        eles.pop(1)
        self.title = " ".join(eles)


class TocNode:
    """Class to hold a header for the TOC."""

    def __init__(self, parent, level, text):
        self.level = level
        self.text = text
        self.parent = parent
        self.children = []

    def append(self, node):
        """Append a node to this one."""
        self.children.append(node)

    def render(self):
        """Turn the current node & its children into the TOC content."""
        eles = []
        if self.text:
            eles.append(Plain([NewLink(self.text, ghanchor(self.text))]))
        eles += [x.render() for x in self.children]
        return BulletList([eles]) if self.text else eles


class GatherToc(ActionVisitor):
    """Gather all the headers for a TOC.

    This won't do any mutation of the headers -- we expect other code to use the
    data we gathered here to insert the TOC.
    """

    def __init__(self):
        self.root = TocNode(None, 0, None)
        self.curr = self.root
        # All the sections we've seen so code can look them up quickly without
        # having to walk the whole graph.
        self.sections = set()

    def append(self, level, text):
        """Append a new node to the TOC."""
        if level > self.curr.level:
            # Append a child.
            node = TocNode(self.curr, level, text)
            self.curr.append(node)
        else:
            # Walk up until we find a parent at a higher level.
            parent = self.curr.parent
            while level <= parent.level:
                parent = parent.parent
            node = TocNode(parent, level, text)
            parent.append(node)
        self.curr = node

    def render(self):
        return self.root.render()

    def visit_header(self, key, value):
        """Add each header to the TOC."""
        level, _, text = value
        text = stringify(text)
        # A bit of a hack: Skip the NAME header as we know we'll be rewriting
        # that into a title section and we don't want it in the TOC.
        if text == "NAME":
            return

        value[0] = level = level + 1
        if text == text.upper():
            text = text.title()
            value[2] = [Str(text)]

        assert text not in self.sections, 'Duplicate section "%s"!?' % (text,)
        self.sections.add(text)
        self.append(level, text)


class ConvertDefinitionList(ActionVisitor):
    """Handle DefinitionList types.

    Since pandoc itself doesn't currently do this, we have to.
    https://github.com/jgm/pandoc/issues/1039
    https://github.com/jgm/pandoc/issues/8394
    """

    def visit_definitionlist(str, key, value):
        """Create a BulletList from the DefinitionList."""
        bl = []
        for (term, details) in value:
            details[0][0]["c"][:] = term + [LineBreak()] + details[0][0]["c"]
            bl += details
        return BulletList(bl)


def pandoc_main(argv):
    """Main func when script is run by pandoc as a filter."""
    gather_toc = GatherToc()
    gather_name = GatherName()
    toJSONFilters(
        [
            AutoLinkUris(),
            AutoLinkMans(),
            ConvertDefinitionList(),
            gather_toc,
            gather_name,
            AutoLinkSections(gather_toc),
            ConvertNameSectionToTitle(gather_name, gather_toc),
        ]
    )


def user_main(argv):
    """Main func when script is run by a user."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("man", help="man page to read")
    parser.add_argument("md", help="markdown file to write")
    opts = parser.parse_args(argv)

    os.chdir(DIR)
    cmd = ["pandoc", "-r", "man", "-w", "gfm+smart", "-F", FILE.name, opts.man]
    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)

    print("Updating", opts.md)
    lines = result.stdout.splitlines(keepends=True)
    # Strip out the <!-- --> markers in the generated TOC.  Ugly.
    i = 1
    while i < len(lines):
        line = lines[i]
        if line.startswith(b"#"):
            break
        if not line.strip() and lines[i + 1].strip() == b"<!-- -->":
            lines.pop(i)
            lines.pop(i)
            if not lines[i].strip():
                lines.pop(i)
            continue
        i += 1
    with open(opts.md, "wb") as fp:
        fp.writelines(lines)


if __name__ == "__main__":
    main = user_main if sys.stdin.isatty() else pandoc_main
    sys.exit(main(sys.argv[1:]))
