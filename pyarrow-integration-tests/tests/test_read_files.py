import os
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe
from pyarrow_integration_tests.kms import kms_client_factory
import pytest


def test_read_integration_test_file(test_file_path: Path, expected_data: pa.Table):
    crypto_factory = pe.CryptoFactory(kms_client_factory)

    kms_connection_config = pe.KmsConnectionConfig()
    decryption_config = pe.DecryptionConfiguration()
    decryption_properties = crypto_factory.file_decryption_properties(
            kms_connection_config, decryption_config)

    parquet_file = pq.ParquetFile(
            test_file_path, decryption_properties=decryption_properties)
    table = parquet_file.read()

    assert table.equals(expected_data)


@pytest.fixture
def expected_data() -> pa.Table:
    test_data_dir = Path(os.environ["PARQUET_ENCRYPTION_DATA_DIR"])
    file_path = test_data_dir / "unencrypted.parquet"
    return pq.read_table(file_path)
