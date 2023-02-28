# -*- coding: utf-8 -*-
# Copyright 2022 Google LLC
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
from __future__ import annotations

from typing import MutableMapping, MutableSequence

from google.protobuf import timestamp_pb2  # type: ignore
import proto  # type: ignore

__protobuf__ = proto.module(
    package="google.cloud.securitycenter.v1",
    manifest={
        "MuteConfig",
    },
)


class MuteConfig(proto.Message):
    r"""A mute config is a Cloud SCC resource that contains the
    configuration to mute create/update events of findings.

    Attributes:
        name (str):
            This field will be ignored if provided on config creation.
            Format
            "organizations/{organization}/muteConfigs/{mute_config}"
            "folders/{folder}/muteConfigs/{mute_config}"
            "projects/{project}/muteConfigs/{mute_config}".
        display_name (str):
            The human readable name to be displayed for
            the mute config.
        description (str):
            A description of the mute config.
        filter (str):
            Required. An expression that defines the filter to apply
            across create/update events of findings. While creating a
            filter string, be mindful of the scope in which the mute
            configuration is being created. E.g., If a filter contains
            project = X but is created under the project = Y scope, it
            might not match any findings.

            The following field and operator combinations are supported:

            -  severity: ``=``, ``:``
            -  category: ``=``, ``:``
            -  resource.name: ``=``, ``:``
            -  resource.project_name: ``=``, ``:``
            -  resource.project_display_name: ``=``, ``:``
            -  resource.folders.resource_folder: ``=``, ``:``
            -  resource.parent_name: ``=``, ``:``
            -  resource.parent_display_name: ``=``, ``:``
            -  resource.type: ``=``, ``:``
            -  finding_class: ``=``, ``:``
            -  indicator.ip_addresses: ``=``, ``:``
            -  indicator.domains: ``=``, ``:``
        create_time (google.protobuf.timestamp_pb2.Timestamp):
            Output only. The time at which the mute
            config was created. This field is set by the
            server and will be ignored if provided on config
            creation.
        update_time (google.protobuf.timestamp_pb2.Timestamp):
            Output only. The most recent time at which
            the mute config was updated. This field is set
            by the server and will be ignored if provided on
            config creation or update.
        most_recent_editor (str):
            Output only. Email address of the user who
            last edited the mute config. This field is set
            by the server and will be ignored if provided on
            config creation or update.
    """

    name: str = proto.Field(
        proto.STRING,
        number=1,
    )
    display_name: str = proto.Field(
        proto.STRING,
        number=2,
    )
    description: str = proto.Field(
        proto.STRING,
        number=3,
    )
    filter: str = proto.Field(
        proto.STRING,
        number=4,
    )
    create_time: timestamp_pb2.Timestamp = proto.Field(
        proto.MESSAGE,
        number=5,
        message=timestamp_pb2.Timestamp,
    )
    update_time: timestamp_pb2.Timestamp = proto.Field(
        proto.MESSAGE,
        number=6,
        message=timestamp_pb2.Timestamp,
    )
    most_recent_editor: str = proto.Field(
        proto.STRING,
        number=7,
    )


__all__ = tuple(sorted(__protobuf__.manifest))
