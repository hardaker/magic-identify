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
    def __init__(self, prefer_identify=False, prefer_magic=False):
        try:
            import magic
            self.magic = magic.Magic(magic.MAGIC_MIME)
        except Exception as ex:
            debug(f"magic creation exception: {ex}")
            debug("failed to create the magic class - need python-magic > 0.4.24")
        self.prefer_identify = prefer_identify
        self.prefer_magic = prefer_magic

    def identify(self, filepath):
        "identify a file to the best of our cooperative ability"

        # should we only use identify?
        if self.prefer_identify:
            return self.use_identify(filepath)

        # should we only use magic?
        if self.prefer_magic:
            return self.use_magic(filepath)

        # get the magic output and see if it's any good
        magic_results = self.use_magic(filepath)

        # if it looks like a reasonable repsonse, return it
        if magic_results[0] != 'text/plain' and \
           magic_results[0] != 'application/octet-stream' and \
           magic_results[1] != 'missing':
            debug("using magic results")
            return magic_results

        debug("magic was boring -- trying identify")
        identify_results = self.use_identify(filepath)
        if identify_results and identify_results[0] != "unknown":
            debug("using identify results")
            return identify_results

        # Ok, super boring so far...  try our internal hacks
        debug("ok, even magic was boring -- trying our hacks")
        hack_results = self.use_hack_it(filepath)
        if hack_results and hack_results[0] != "unknown":
            debug("using hack results")
            return hack_results

        # falling back to magic as nothing produced good results
        return magic_results

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
            return("unknown", 'unknown')
        except Exception as exp:
            debug(f"Failed to read/identify {filepath}: {exp}")
            return ("unknown", "unknown")

    def use_hack_it(self, filepath):
        try:
            with open(filepath) as f:
                sh_markers = 0
                for line in f:
                    parts = line.split(" ")
                    for keyword in ['wget', 'curl', 'chmod', 'rm',
                                    'cd', 'mips', 'arm', 'sh',
                                    'apt', 'dpkg', 'sudo', 'mkdir', 'alias'
                                    'fi', 'else']:
                        if keyword in parts:
                            sh_markers += 1
                if sh_markers > 3:
                    return ("unmarked shell", "text/x-shellscript")
        except Exception as exp:
            debug(f"failed to hack-analyze {filepath}")
        return ("unknown", "unknown")
