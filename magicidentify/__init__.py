#!/usr/bin/python3

"""magicidentify implements a wrapper around both the python-magic
module and the identify module to try and always return results, even
if one fails.  Finally, failing that it will try to guess some minimal
shell script environments too (specifically looking at common keywords
in malware droppers/downloaders that do not always have leading
identification lines).

It returns two strings, one which may be a higher level text
description and a second which should always be a mime-type
identifier.

Example usage:

    import magicidentify
    c = magicidentify.MagicIdentify()
    print(c.identify("/bin/ls"))
    # ('application/x-pie-executable', 'application/x-pie-executable')
"""

import sys
import logging
from logging import debug, info, warning, error, critical


class MagicIdentify():
    """A wrapper class around both the magic and identify classes"""
    def __init__(self, prefer_identify=False):
        try:
            import magic
            self.magic = magic.Magic(magic.MAGIC_MIME)
        except Exception as ex:
            debug(f"magic creation exception: {ex}")
            debug("failed to create the magic class - need python-magic > 0.4.24")
            self.magic = magic.Magic()
        self.prefer_identify = prefer_identify

    def identify(self, filepath):
        "identify a file to the best of our cooperative ability"
        if self.prefer_identify:
            (results, mime) = self.use_identify(filepath)
            if results and mime and results != "unknown":
                return (results, mime)

        mime = self.use_magic(filepath)
        if mime[0] == 'text/plain' or mime[0] == 'application/octet-stream' \
           or mime[1] == "missing":
            debug("magic was boring -- trying identify")
            identify_results = self.use_identify(filepath)
            if not identify_results or identify_results[0] == "unknown":
                debug("ok, identify was even more boring -- returning magic")
                return mime
        return mime

    def use_magic(self, filepath):
        "use the magic module for doing identification"
        results = None
        try:
            results = self.magic.from_file(filepath)
        except Exception as ex:
            debug(f"magic exception: {ex}")

        # XXX?
        if not results:
            return ("Not Found", "missing")
        return (results, results)

    def use_identify(self, filepath):
        "try using the identify module for determining file type"
        try:
            from identify import identify
            f = open(filepath)
            topline = next(f)

            if topline[0] == '#':
                parts = topline.split()
                if parts[0] == "#!/usr/bin/env" or parts[0] == "#!/bin/env":
                    parts.pop(0)
                    parts[0] = "#!" + parts[0]
                tags = list(identify.tags_from_interpreter(parts[0][2:]))
                if len(tags) == 0:
                    tags = ['unknown']
                return ("/".join(tags), "text/x-" + tags[0])
            else:
                # try to guess based on contents
                sh_markers = 0
                for line in f:
                    for keyword in ['wget', 'curl', 'chmod', 'rm',
                                    'cd', 'mips', 'arm']:
                        if keyword in line:
                            sh_markers += 1
                if sh_markers > 3:
                    return ("unmarked shell", "text/x-shellscript")

                return("unknown", 'unknown')
        except Exception as exp:
            debug(f"Failed to read/identify {filepath}: {exp}")
            return ("unknown", "unknown")

