#!/usr/bin/python3

"""magic-identify tries hard to find descriptions for a file.

It uses two python classes: python-magic and identify to print
information about what a file might be.
"""

from magicidentify import MagicIdentify
import logging
from logging import debug, info, warning, error, critical

def main():
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, FileType

    def parse_args():
        parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                                description=__doc__,
                                epilog="Example usage: magic-identify FILE ...")

        parser.add_argument("--log-level", default="info",
                            help="Define the logging verbosity level (debug, info, warning, error, fotal, critical).")

        parser.add_argument("-i", "--prefer-identify", action="store_true",
                            help="Prefer identify over magic")

        parser.add_argument("-q", "--quiet", action="store_true",
                            help="Simplfy output to just the best mime-type")

        parser.add_argument("input_files", help="Input files to identify",
                            nargs='*')

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level,
                            format="%(levelname)-10s:\t%(message)s")
        return args

    args = parse_args()

    c = MagicIdentify(args.prefer_identify)
    for arg in args.input_files:
        parts = c.identify(arg)

        if args.quiet:
            print(parts[1])
        else:
            print(f"{arg}: {', '.join(parts)}")

            magic = c.use_magic(arg)
            print(f"  using magic:    {', '.join(magic)}")

            id = c.use_identify(arg)
            print(f"  using identify: {', '.join(id)}")


if __name__ == "__main__":
    main()
