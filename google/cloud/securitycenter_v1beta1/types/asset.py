# -*- coding: utf-8 -*-

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import proto  # type: ignore


from google.cloud.securitycenter_v1beta1.types import (
    security_marks as gcs_security_marks,
)
from google.protobuf import struct_pb2 as struct  # type: ignore
from google.protobuf import timestamp_pb2 as timestamp  # type: ignore


__protobuf__ = proto.module(
    package="google.cloud.securitycenter.v1beta1", manifest={"Asset",},
)


class Asset(proto.Message):
    r"""Cloud Security Command Center's (Cloud SCC) representation of
    a Google Cloud Platform (GCP) resource.

    The Asset is a Cloud SCC resource that captures information
    about a single GCP resource. All modifications to an Asset are
    only within the context of Cloud SCC and don't affect the
    referenced GCP resource.

    Attributes:
        name (str):
            The relative resource name of this asset. See:
            https://cloud.google.com/apis/design/resource_names#relative_resource_name
            Example:
            "organizations/{organization_id}/assets/{asset_id}".
        security_center_properties (~.asset.Asset.SecurityCenterProperties):
            Cloud SCC managed properties. These
            properties are managed by Cloud SCC and cannot
            be modified by the user.
        resource_properties (Sequence[~.asset.Asset.ResourcePropertiesEntry]):
            Resource managed properties. These properties
            are managed and defined by the GCP resource and
            cannot be modified by the user.
        security_marks (~.gcs_security_marks.SecurityMarks):
            User specified security marks. These marks
            are entirely managed by the user and come from
            the SecurityMarks resource that belongs to the
            asset.
        create_time (~.timestamp.Timestamp):
            The time at which the asset was created in
            Cloud SCC.
        update_time (~.timestamp.Timestamp):
            The time at which the asset was last updated,
            added, or deleted in Cloud SCC.
    """

    class SecurityCenterProperties(proto.Message):
        r"""Cloud SCC managed properties. These properties are managed by
        Cloud SCC and cannot be modified by the user.

        Attributes:
            resource_name (str):
                Immutable. The full resource name of the GCP resource this
                asset represents. This field is immutable after create time.
                See:
                https://cloud.google.com/apis/design/resource_names#full_resource_name
            resource_type (str):
                The type of the GCP resource. Examples
                include: APPLICATION, PROJECT, and ORGANIZATION.
                This is a case insensitive field defined by
                Cloud SCC and/or the producer of the resource
                and is immutable after create time.
            resource_parent (str):
                The full resource name of the immediate parent of the
                resource. See:
                https://cloud.google.com/apis/design/resource_names#full_resource_name
            resource_project (str):
                The full resource name of the project the resource belongs
                to. See:
                https://cloud.google.com/apis/design/resource_names#full_resource_name
            resource_owners (Sequence[str]):
                Owners of the Google Cloud resource.
        """

        resource_name = proto.Field(proto.STRING, number=1)

        resource_type = proto.Field(proto.STRING, number=2)

        resource_parent = proto.Field(proto.STRING, number=3)

        resource_project = proto.Field(proto.STRING, number=4)

        resource_owners = proto.RepeatedField(proto.STRING, number=5)

    name = proto.Field(proto.STRING, number=1)

    security_center_properties = proto.Field(
        proto.MESSAGE, number=2, message=SecurityCenterProperties,
    )

    resource_properties = proto.MapField(
        proto.STRING, proto.MESSAGE, number=7, message=struct.Value,
    )

    security_marks = proto.Field(
        proto.MESSAGE, number=8, message=gcs_security_marks.SecurityMarks,
    )

    create_time = proto.Field(proto.MESSAGE, number=9, message=timestamp.Timestamp,)

    update_time = proto.Field(proto.MESSAGE, number=10, message=timestamp.Timestamp,)


__all__ = tuple(sorted(__protobuf__.manifest))
