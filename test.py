import maltrieve


def test_args():
    args = maltrieve.setup_args(['-l', 'testlog'])
    assert args.logfile == 'testlog'
