import sys
from pathlib import Path
from typing import Optional

import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe
from .kms import kms_client_factory


def generate_test_files():
    data_dir = Path(sys.argv[1])
    crypto_factory = pe.CryptoFactory(kms_client_factory)

    _write_parquet(data_dir / "unencrypted.parquet", crypto_factory, None)

    encryption_config = pe.EncryptionConfiguration(
        footer_key="kf",
        column_keys={
            "kc1": ["x"],
            "kc2": ["y", "z"],
        },
        double_wrapping=False)
    _write_parquet(data_dir / "per_column_single_wrapped.parquet", crypto_factory, encryption_config)

    encryption_config = pe.EncryptionConfiguration(
        footer_key="kf",
        column_keys={
            "kc1": ["x"],
            "kc2": ["y", "z"],
        },
        double_wrapping=True)
    _write_parquet(data_dir / "per_column_double_wrapped.parquet", crypto_factory, encryption_config)


def _write_parquet(file_path: Path, crypto_factory: pe.CryptoFactory, encryption_config: Optional[pe.EncryptionConfiguration]):
    if encryption_config:
        kms_connection_config = pe.KmsConnectionConfig()
        encryption_properties = crypto_factory.file_encryption_properties(
                kms_connection_config, encryption_config)
    else:
        encryption_properties = None

    table = pa.Table.from_pydict({
        "id": pa.array([0, 1, 2, 3, 4, 5], type=pa.int32()),
        "x": pa.array([0.0, 0.1, 0.2, 0.3, 0.4, 0.5], type=pa.float32()),
        "y": pa.array([1.0, 1.1, 1.2, 1.3, 1.4, 1.5], type=pa.float32()),
        "z": pa.array([2.0, 2.1, 2.2, 2.3, 2.4, 2.5], type=pa.float32()),
    })

    with pq.ParquetWriter(file_path, table.schema,
                         encryption_properties=encryption_properties) as writer:
       writer.write_table(table)
