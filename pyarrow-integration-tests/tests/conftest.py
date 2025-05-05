import os
from pathlib import Path


def pytest_generate_tests(metafunc):
    # Configure a "test_file_path" fixture that will be parameterized
    # to run a test with all encryption test files.
    if "test_file_path" in metafunc.fixturenames:
        test_data_dir = Path(os.environ["PARQUET_ENCRYPTION_DATA_DIR"])
        test_files = [
                f for f in test_data_dir.iterdir()
                if f.suffix == ".parquet" and f.name != "unencrypted.parquet"]
        metafunc.parametrize("test_file_path", test_files, ids=lambda path: path.stem)
