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

    magic-identify /bin/ls

# Todo

- Handle more boring cases from some outputs (text/inode)
- test suite
