def assert_raises(expected_message, thunk):
    try:
        thunk()
    except ValueError as error:
        assert expected_message in str(error)
        return

    raise AssertionError("expected ValueError containing: " + expected_message)
