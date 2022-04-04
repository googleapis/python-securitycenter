#!/usr/bin/env python
#
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# TODO(developer): Replace these variables before running the sample.
import os
import re
import uuid

from _pytest.capture import CaptureFixture
import pytest

import snippets_bigquery_export

PROJECT_ID = os.environ["GCLOUD_PROJECT"]
GOOGLE_APPLICATION_CREDENTIALS = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
BIGQUERY_DATASET_ID = "sampledataset"


@pytest.fixture
def bigquery_export():
    bigquery_export_id = f"default-{str(uuid.uuid4()).split('-')[0]}"

    create_bigquery_dataset(BIGQUERY_DATASET_ID)
    export_filter = "severity=\"LOW\" OR severity=\"MEDIUM\""
    snippets_bigquery_export.create_bigquery_export(f"projects/{PROJECT_ID}", export_filter, BIGQUERY_DATASET_ID, bigquery_export_id)

    yield bigquery_export_id

    snippets_bigquery_export.delete_bigquery_export(f"projects/{PROJECT_ID}", bigquery_export_id)
    assert re.search(f"BigQuery export request deleted successfully: {bigquery_export_id}")
    delete_bigquery_dataset(BIGQUERY_DATASET_ID)


def create_bigquery_dataset(dataset_id: str):
    from google.cloud import bigquery

    bigquery_client = bigquery.Client()

    dataset = bigquery.Dataset(dataset_id)
    dataset = bigquery_client.create_dataset(dataset)
    print("Dataset {} created.".format(dataset.dataset_id))


def delete_bigquery_dataset(dataset_id: str):
    from google.cloud import bigquery

    bigquery_client = bigquery.Client()
    bigquery_client.delete_dataset(dataset_id)
    print("Dataset {} deleted.".format(dataset_id))


def test_get_bigquery_export(capsys: CaptureFixture, export_id: bigquery_export):
    snippets_bigquery_export.get_bigquery_export(f"projects/{PROJECT_ID}", export_id)
    out, _ = capsys.readouterr()
    assert re.search(f"Retrieved the BigQuery export: projects/{PROJECT_ID}/bigQueryExports/{export_id}", out)


def test_list_bigquery_exports(capsys: CaptureFixture, export_id: bigquery_export):
    snippets_bigquery_export.list_bigquery_exports(f"projects/{PROJECT_ID}")
    out, _ = capsys.readouterr()
    assert re.search("Listing BigQuery exports:", out)
    assert re.search(export_id, out)


def test_update_bigquery_exports(capsys: CaptureFixture, export_id: bigquery_export):
    export_filter = "severity=\"MEDIUM\""
    snippets_bigquery_export.update_bigquery_export(f"projects/{PROJECT_ID}", export_filter, export_id)
    out, _ = capsys.readouterr()
    assert re.search("BigQueryExport updated successfully!", out)
