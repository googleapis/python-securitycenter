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

import abc
import typing

from google import auth
from google.api_core import exceptions  # type: ignore
from google.api_core import operations_v1  # type: ignore
from google.auth import credentials  # type: ignore

from google.cloud.securitycenter_v1.types import finding
from google.cloud.securitycenter_v1.types import finding as gcs_finding
from google.cloud.securitycenter_v1.types import notification_config
from google.cloud.securitycenter_v1.types import (
    notification_config as gcs_notification_config,
)
from google.cloud.securitycenter_v1.types import organization_settings
from google.cloud.securitycenter_v1.types import (
    organization_settings as gcs_organization_settings,
)
from google.cloud.securitycenter_v1.types import security_marks as gcs_security_marks
from google.cloud.securitycenter_v1.types import securitycenter_service
from google.cloud.securitycenter_v1.types import source
from google.cloud.securitycenter_v1.types import source as gcs_source
from google.iam.v1 import iam_policy_pb2 as iam_policy  # type: ignore
from google.iam.v1 import policy_pb2 as policy  # type: ignore
from google.longrunning import operations_pb2 as operations  # type: ignore
from google.protobuf import empty_pb2 as empty  # type: ignore


class SecurityCenterTransport(abc.ABC):
    """Abstract transport class for SecurityCenter."""

    AUTH_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)

    def __init__(
        self,
        *,
        host: str = "securitycenter.googleapis.com",
        credentials: credentials.Credentials = None,
        credentials_file: typing.Optional[str] = None,
        scopes: typing.Optional[typing.Sequence[str]] = AUTH_SCOPES,
        **kwargs,
    ) -> None:
        """Instantiate the transport.

        Args:
            host (Optional[str]): The hostname to connect to.
            credentials (Optional[google.auth.credentials.Credentials]): The
                authorization credentials to attach to requests. These
                credentials identify the application to the service; if none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            credentials_file (Optional[str]): A file with credentials that can
                be loaded with :func:`google.auth.load_credentials_from_file`.
                This argument is mutually exclusive with credentials.
            scope (Optional[Sequence[str]]): A list of scopes.
        """
        # Save the hostname. Default to port 443 (HTTPS) if none is specified.
        if ":" not in host:
            host += ":443"
        self._host = host

        # If no credentials are provided, then determine the appropriate
        # defaults.
        if credentials and credentials_file:
            raise exceptions.DuplicateCredentialArgs(
                "'credentials_file' and 'credentials' are mutually exclusive"
            )

        if credentials_file is not None:
            credentials, _ = auth.load_credentials_from_file(
                credentials_file, scopes=scopes
            )
        elif credentials is None:
            credentials, _ = auth.default(scopes=scopes)

        # Save the credentials.
        self._credentials = credentials

    @property
    def operations_client(self) -> operations_v1.OperationsClient:
        """Return the client designed to process long-running operations."""
        raise NotImplementedError()

    @property
    def create_source(
        self,
    ) -> typing.Callable[
        [securitycenter_service.CreateSourceRequest],
        typing.Union[gcs_source.Source, typing.Awaitable[gcs_source.Source]],
    ]:
        raise NotImplementedError()

    @property
    def create_finding(
        self,
    ) -> typing.Callable[
        [securitycenter_service.CreateFindingRequest],
        typing.Union[gcs_finding.Finding, typing.Awaitable[gcs_finding.Finding]],
    ]:
        raise NotImplementedError()

    @property
    def create_notification_config(
        self,
    ) -> typing.Callable[
        [securitycenter_service.CreateNotificationConfigRequest],
        typing.Union[
            gcs_notification_config.NotificationConfig,
            typing.Awaitable[gcs_notification_config.NotificationConfig],
        ],
    ]:
        raise NotImplementedError()

    @property
    def delete_notification_config(
        self,
    ) -> typing.Callable[
        [securitycenter_service.DeleteNotificationConfigRequest],
        typing.Union[empty.Empty, typing.Awaitable[empty.Empty]],
    ]:
        raise NotImplementedError()

    @property
    def get_iam_policy(
        self,
    ) -> typing.Callable[
        [iam_policy.GetIamPolicyRequest],
        typing.Union[policy.Policy, typing.Awaitable[policy.Policy]],
    ]:
        raise NotImplementedError()

    @property
    def get_notification_config(
        self,
    ) -> typing.Callable[
        [securitycenter_service.GetNotificationConfigRequest],
        typing.Union[
            notification_config.NotificationConfig,
            typing.Awaitable[notification_config.NotificationConfig],
        ],
    ]:
        raise NotImplementedError()

    @property
    def get_organization_settings(
        self,
    ) -> typing.Callable[
        [securitycenter_service.GetOrganizationSettingsRequest],
        typing.Union[
            organization_settings.OrganizationSettings,
            typing.Awaitable[organization_settings.OrganizationSettings],
        ],
    ]:
        raise NotImplementedError()

    @property
    def get_source(
        self,
    ) -> typing.Callable[
        [securitycenter_service.GetSourceRequest],
        typing.Union[source.Source, typing.Awaitable[source.Source]],
    ]:
        raise NotImplementedError()

    @property
    def group_assets(
        self,
    ) -> typing.Callable[
        [securitycenter_service.GroupAssetsRequest],
        typing.Union[
            securitycenter_service.GroupAssetsResponse,
            typing.Awaitable[securitycenter_service.GroupAssetsResponse],
        ],
    ]:
        raise NotImplementedError()

    @property
    def group_findings(
        self,
    ) -> typing.Callable[
        [securitycenter_service.GroupFindingsRequest],
        typing.Union[
            securitycenter_service.GroupFindingsResponse,
            typing.Awaitable[securitycenter_service.GroupFindingsResponse],
        ],
    ]:
        raise NotImplementedError()

    @property
    def list_assets(
        self,
    ) -> typing.Callable[
        [securitycenter_service.ListAssetsRequest],
        typing.Union[
            securitycenter_service.ListAssetsResponse,
            typing.Awaitable[securitycenter_service.ListAssetsResponse],
        ],
    ]:
        raise NotImplementedError()

    @property
    def list_findings(
        self,
    ) -> typing.Callable[
        [securitycenter_service.ListFindingsRequest],
        typing.Union[
            securitycenter_service.ListFindingsResponse,
            typing.Awaitable[securitycenter_service.ListFindingsResponse],
        ],
    ]:
        raise NotImplementedError()

    @property
    def list_notification_configs(
        self,
    ) -> typing.Callable[
        [securitycenter_service.ListNotificationConfigsRequest],
        typing.Union[
            securitycenter_service.ListNotificationConfigsResponse,
            typing.Awaitable[securitycenter_service.ListNotificationConfigsResponse],
        ],
    ]:
        raise NotImplementedError()

    @property
    def list_sources(
        self,
    ) -> typing.Callable[
        [securitycenter_service.ListSourcesRequest],
        typing.Union[
            securitycenter_service.ListSourcesResponse,
            typing.Awaitable[securitycenter_service.ListSourcesResponse],
        ],
    ]:
        raise NotImplementedError()

    @property
    def run_asset_discovery(
        self,
    ) -> typing.Callable[
        [securitycenter_service.RunAssetDiscoveryRequest],
        typing.Union[operations.Operation, typing.Awaitable[operations.Operation]],
    ]:
        raise NotImplementedError()

    @property
    def set_finding_state(
        self,
    ) -> typing.Callable[
        [securitycenter_service.SetFindingStateRequest],
        typing.Union[finding.Finding, typing.Awaitable[finding.Finding]],
    ]:
        raise NotImplementedError()

    @property
    def set_iam_policy(
        self,
    ) -> typing.Callable[
        [iam_policy.SetIamPolicyRequest],
        typing.Union[policy.Policy, typing.Awaitable[policy.Policy]],
    ]:
        raise NotImplementedError()

    @property
    def test_iam_permissions(
        self,
    ) -> typing.Callable[
        [iam_policy.TestIamPermissionsRequest],
        typing.Union[
            iam_policy.TestIamPermissionsResponse,
            typing.Awaitable[iam_policy.TestIamPermissionsResponse],
        ],
    ]:
        raise NotImplementedError()

    @property
    def update_finding(
        self,
    ) -> typing.Callable[
        [securitycenter_service.UpdateFindingRequest],
        typing.Union[gcs_finding.Finding, typing.Awaitable[gcs_finding.Finding]],
    ]:
        raise NotImplementedError()

    @property
    def update_notification_config(
        self,
    ) -> typing.Callable[
        [securitycenter_service.UpdateNotificationConfigRequest],
        typing.Union[
            gcs_notification_config.NotificationConfig,
            typing.Awaitable[gcs_notification_config.NotificationConfig],
        ],
    ]:
        raise NotImplementedError()

    @property
    def update_organization_settings(
        self,
    ) -> typing.Callable[
        [securitycenter_service.UpdateOrganizationSettingsRequest],
        typing.Union[
            gcs_organization_settings.OrganizationSettings,
            typing.Awaitable[gcs_organization_settings.OrganizationSettings],
        ],
    ]:
        raise NotImplementedError()

    @property
    def update_source(
        self,
    ) -> typing.Callable[
        [securitycenter_service.UpdateSourceRequest],
        typing.Union[gcs_source.Source, typing.Awaitable[gcs_source.Source]],
    ]:
        raise NotImplementedError()

    @property
    def update_security_marks(
        self,
    ) -> typing.Callable[
        [securitycenter_service.UpdateSecurityMarksRequest],
        typing.Union[
            gcs_security_marks.SecurityMarks,
            typing.Awaitable[gcs_security_marks.SecurityMarks],
        ],
    ]:
        raise NotImplementedError()


__all__ = ("SecurityCenterTransport",)
