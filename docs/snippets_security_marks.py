#!/usr/bin/env python
#
# Copyright 2019 Google LLC
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
"""Demos for working with security marks."""
import os
import random

import pytest


@pytest.fixture(scope="module")
def organization_id():
    """Gets Organization ID from the environment variable """
    return os.environ["GCLOUD_ORGANIZATION"]


@pytest.fixture(scope="module")
def asset_name(organization_id):
    """Returns a random asset name from existing assets."""
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()
    # organization_id is the numeric ID of the organization.
    # organization_id=1234567777
    org_name = "organizations/{org_id}".format(org_id=organization_id)
    assets = list(client.list_assets(org_name))
    # Select a random asset to avoid collision between integration tests.
    asset = (random.sample(assets, 1)[0]).asset.name

    # Set fresh marks.
    update = client.update_security_marks(
        {"name": "{}/securityMarks".format(asset), "marks": {"other": "other_val"}}
    )
    assert update.marks == {"other": "other_val"}
    return asset


@pytest.fixture(scope="module")
def source_name(organization_id):
    """Creates a new source in the organization."""
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()
    org_name = "organizations/{org_id}".format(org_id=organization_id)
    source = client.create_source(
        org_name,
        {
            "display_name": "Security marks Unit test source",
            "description": "A new custom source that does X",
        },
    )
    return source.name


@pytest.fixture(scope="module")
def finding_name(source_name):
    """Creates a new finding and returns it name."""
    from google.cloud import securitycenter
    from google.cloud.securitycenter_v1.proto.finding_pb2 import Finding
    from google.protobuf.timestamp_pb2 import Timestamp

    client = securitycenter.SecurityCenterClient()

    now_proto = Timestamp()
    now_proto.GetCurrentTime()

    finding = client.create_finding(
        source_name,
        "scfinding",
        {
            "state": Finding.ACTIVE,
            "category": "C1",
            "event_time": now_proto,
            "resource_name": "//cloudresourcemanager.googleapis.com/organizations/1234",
        },
    )
    client.create_finding(
        source_name,
        "untouched",
        {
            "state": Finding.ACTIVE,
            "category": "MEDIUM_RISK_ONE",
            "event_time": now_proto,
            "resource_name": "//cloudresourcemanager.googleapis.com/organizations/1234",
        },
    )

    return finding.name


def test_add_to_asset(asset_name):
    """Add new security marks to an asset."""
    # [START add_marks_to_asset]
    from google.cloud import securitycenter
    from google.protobuf import field_mask_pb2

    # Create a new client.
    client = securitycenter.SecurityCenterClient()

    # asset_name is the resource path for an asset that exists in CSCC.
    # Its format is "organization/{organization_id}/assets/{asset_id}
    # e.g.:
    # asset_name = organizations/123123342/assets/12312321
    marks_name = "{}/securityMarks".format(asset_name)

    # Notice the suffix after "marks." in the field mask matches the keys
    # in marks.
    field_mask = field_mask_pb2.FieldMask(paths=["marks.key_a", "marks.key_b"])
    marks = {"key_a": "value_a", "key_b": "value_b"}

    updated_marks = client.update_security_marks(
        {"name": marks_name, "marks": marks},
        # If this field was left empty, all marks would be cleared before adding
        # the new values.
        update_mask=field_mask,
    )
    print(updated_marks)
    # [END add_marks_to_asset]
    assert updated_marks.marks.keys() >= marks.keys()


def test_clear_from_asset(asset_name):
    """Removes security marks from an asset."""
    # Make sure they are there first
    test_add_to_asset(asset_name)
    # [START clear_marks_asset]
    from google.cloud import securitycenter
    from google.protobuf import field_mask_pb2

    # Create a new client.
    client = securitycenter.SecurityCenterClient()

    # asset_name is the resource path for an asset that exists in CSCC.
    # Its format is "organization/{organization_id}/assets/{asset_id}
    # e.g.:
    # asset_name = organizations/123123342/assets/12312321
    marks_name = "{}/securityMarks".format(asset_name)

    field_mask = field_mask_pb2.FieldMask(paths=["marks.key_a", "marks.key_b"])

    updated_marks = client.update_security_marks(
        {
            "name": marks_name
            # Note, no marks specified, so the specified values in
            # the fields masks will be deleted.
        },
        # If this field was left empty, all marks would be cleared.
        update_mask=field_mask,
    )
    print(updated_marks)
    # [END clear_marks_asset]
    assert "other" in updated_marks.marks
    assert len(updated_marks.marks) == 1


def test_delete_and_update_marks(asset_name):
    """Updates and deletes security marks from an asset in the same call."""
    # Make sure they are there first
    test_add_to_asset(asset_name)
    # [START delete_and_update_marks]
    from google.cloud import securitycenter
    from google.protobuf import field_mask_pb2

    client = securitycenter.SecurityCenterClient()
    # asset_name is the resource path for an asset that exists in CSCC.
    # Its format is "organization/{organization_id}/assets/{asset_id}
    # e.g.:
    # asset_name = organizations/123123342/assets/12312321
    marks_name = "{}/securityMarks".format(asset_name)

    field_mask = field_mask_pb2.FieldMask(paths=["marks.key_a", "marks.key_b"])
    marks = {"key_a": "new_value_for_a"}

    updated_marks = client.update_security_marks(
        {"name": marks_name, "marks": marks}, update_mask=field_mask
    )
    print(updated_marks)
    # [END delete_and_update_marks]
    assert updated_marks.marks == {"key_a": "new_value_for_a", "other": "other_val"}


def test_add_to_finding(finding_name):
    """Adds security marks to a finding. """
    # [START add_marks_to_finding]
    from google.cloud import securitycenter
    from google.protobuf import field_mask_pb2

    client = securitycenter.SecurityCenterClient()
    # finding_name is the resource path for a finding that exists in CSCC.
    # Its format is
    # "organizations/{org_id}/sources/{source_id}/findings/{finding_id}"
    # e.g.:
    # finding_name = "organizations/1112/sources/1234/findings/findingid"
    finding_marks_name = "{}/securityMarks".format(finding_name)

    # Notice the suffix after "marks." in the field mask matches the keys
    # in marks.
    field_mask = field_mask_pb2.FieldMask(
        paths=["marks.finding_key_a", "marks.finding_key_b"]
    )
    marks = {"finding_key_a": "value_a", "finding_key_b": "value_b"}

    updated_marks = client.update_security_marks(
        {"name": finding_marks_name, "marks": marks}, update_mask=field_mask
    )
    # [END add_marks_to_finding]

    assert updated_marks.marks == marks


def test_list_assets_with_query_marks(organization_id, asset_name):
    """Lists assets with a filter on security marks. """
    test_add_to_asset(asset_name)
    # [START demo_list_assets_with_security_marks]
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()

    # organization_id is the numeric ID of the organization.
    # organization_id=1234567777
    org_name = "organizations/{org_id}".format(org_id=organization_id)

    marks_filter = 'security_marks.marks.key_a = "value_a"'
    # Call the API and print results.
    asset_iterator = client.list_assets(org_name, filter_=marks_filter)

    # Call the API and print results.
    asset_iterator = client.list_assets(org_name, filter_=marks_filter)
    for i, asset_result in enumerate(asset_iterator):
        print(i, asset_result)
    # [END demo_list_assets_with_security_marks]
    assert i >= 0


def test_list_findings_with_query_marks(source_name, finding_name):
    """Lists findings with a filter on security marks."""
    # ensure marks are set on finding.
    test_add_to_finding(finding_name)
    i = -1
    # [START demo_list_findings_with_security_marks]
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()

    # source_name is the resource path for a source that has been
    # created previously (you can use list_sources to find a specific one).
    # Its format is:
    # source_name = "organizations/{organization_id}/sources/{source_id}"
    # e.g.:
    # source_name = "organizations/111122222444/sources/1234"
    marks_filter = 'NOT security_marks.marks.finding_key_a="value_a"'

    # Call the API and print results.
    finding_iterator = client.list_findings(source_name, filter_=marks_filter)
    for i, finding_result in enumerate(finding_iterator):
        print(i, finding_result)
    # [END demo_list_findings_with_security_marks]
    # one finding should have been updated with keys, and one should be
    # untouched.
    assert i == 0
