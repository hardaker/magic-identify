# About

magic-identify implements a wrapper around both the python-magic
module and the identify module to try and always return results, even
if one fails.  Finally, failing that it will try to guess some minimal
shell script environments too (specifically looking at common keywords
in malware droppers/downloaders that do not always have leading
identification lines).

It returns two strings, one which may be a higher level text
description and a second which should always be a mime-type
identifier.

# Example module use:

    import magicidentify
    c = magicidentify.MagicIdentify()
    print(c.identify("/bin/ls"))
    # ('application/x-pie-executable', 'application/x-pie-executable')
    
# Example CLI use:

    # magic-identify /bin/ls /sbin/ifup
    /bin/ls: application/x-pie-executable, application/x-pie-executable
      using magic:    application/x-pie-executable, application/x-pie-executable
      using identify: unknown, unknown
      using hack:     unknown, unknown
    /sbin/ifup: inode/symlink, inode/symlink
      using magic:    inode/symlink, inode/symlink
      using identify: bash/shell, text/x-bash
      using hack:     unknown, unknown

    # magic-identify -q /bin/ls /sbin/ifup
    application/x-pie-executable
    inode/symlink

# Todo

- Handle more boring cases from some outputs (text/inode)

# Acknowledgements

The following wonderful github accounts have contributed to the code base:

- @JakeRoggenbuck
