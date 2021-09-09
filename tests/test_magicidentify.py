import magicidentify


MAGIC_CASES = [
    ("/bin/ls", ("application/x-pie-executable",) * 2),
    ("/etc/hostname", ("text/plain", "text/plain")),
    ("/bin", ("Not Found", "missing")),
]

IDENTIFY_CASES = [
    ("/bin/ls", ("unknown", "unknown")),
    ("/etc/hostname", ("unknown", "unknown")),
    ("/bin", ("unknown", "unknown")),
]


class TestMagicIdentify:
    mi = magicidentify.MagicIdentify()

    def test_identify(self):
        # TODO: Since none of the test results are interesting from identify
        # it always returns the result from magic. This test should have cases
        # that it knows will be boring from magic and interesting from identify
        for case in MAGIC_CASES:
            assert self.mi.identify(case[0]) == case[1]

    def test_use_magic(self):
        for case in MAGIC_CASES:
            assert self.mi.use_magic(case[0]) == case[1]

    def test_use_identify(self):
        # TODO: use_identify looks for keywords. To test, this function
        # should create a file that includes different amounts of keywords to
        # check if its identified as a shell script
        for case in IDENTIFY_CASES:
            assert self.mi.use_identify(case[0]) == case[1]
