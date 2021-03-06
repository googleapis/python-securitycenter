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

import warnings
from typing import Awaitable, Callable, Dict, Optional, Sequence, Tuple

from google.api_core import gapic_v1  # type: ignore
from google.api_core import grpc_helpers_async  # type: ignore
from google.api_core import operations_v1  # type: ignore
from google import auth  # type: ignore
from google.auth import credentials  # type: ignore
from google.auth.transport.grpc import SslCredentials  # type: ignore

import grpc  # type: ignore
from grpc.experimental import aio  # type: ignore

from google.cloud.securitycenter_v1beta1.types import finding
from google.cloud.securitycenter_v1beta1.types import finding as gcs_finding
from google.cloud.securitycenter_v1beta1.types import organization_settings
from google.cloud.securitycenter_v1beta1.types import (
    organization_settings as gcs_organization_settings,
)
from google.cloud.securitycenter_v1beta1.types import (
    security_marks as gcs_security_marks,
)
from google.cloud.securitycenter_v1beta1.types import securitycenter_service
from google.cloud.securitycenter_v1beta1.types import source
from google.cloud.securitycenter_v1beta1.types import source as gcs_source
from google.iam.v1 import iam_policy_pb2 as iam_policy  # type: ignore
from google.iam.v1 import policy_pb2 as policy  # type: ignore
from google.longrunning import operations_pb2 as operations  # type: ignore

from .base import SecurityCenterTransport, DEFAULT_CLIENT_INFO
from .grpc import SecurityCenterGrpcTransport


class SecurityCenterGrpcAsyncIOTransport(SecurityCenterTransport):
    """gRPC AsyncIO backend transport for SecurityCenter.

    V1 Beta APIs for Security Center service.

    This class defines the same methods as the primary client, so the
    primary client can load the underlying transport implementation
    and call it.

    It sends protocol buffers over the wire using gRPC (which is built on
    top of HTTP/2); the ``grpcio`` package must be installed.
    """

    _grpc_channel: aio.Channel
    _stubs: Dict[str, Callable] = {}

    @classmethod
    def create_channel(
        cls,
        host: str = "securitycenter.googleapis.com",
        credentials: credentials.Credentials = None,
        credentials_file: Optional[str] = None,
        scopes: Optional[Sequence[str]] = None,
        quota_project_id: Optional[str] = None,
        **kwargs,
    ) -> aio.Channel:
        """Create and return a gRPC AsyncIO channel object.
        Args:
            address (Optional[str]): The host for the channel to use.
            credentials (Optional[~.Credentials]): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If
                none are specified, the client will attempt to ascertain
                the credentials from the environment.
            credentials_file (Optional[str]): A file with credentials that can
                be loaded with :func:`google.auth.load_credentials_from_file`.
                This argument is ignored if ``channel`` is provided.
            scopes (Optional[Sequence[str]]): A optional list of scopes needed for this
                service. These are only used when credentials are not specified and
                are passed to :func:`google.auth.default`.
            quota_project_id (Optional[str]): An optional project to use for billing
                and quota.
            kwargs (Optional[dict]): Keyword arguments, which are passed to the
                channel creation.
        Returns:
            aio.Channel: A gRPC AsyncIO channel object.
        """
        scopes = scopes or cls.AUTH_SCOPES
        return grpc_helpers_async.create_channel(
            host,
            credentials=credentials,
            credentials_file=credentials_file,
            scopes=scopes,
            quota_project_id=quota_project_id,
            **kwargs,
        )

    def __init__(
        self,
        *,
        host: str = "securitycenter.googleapis.com",
        credentials: credentials.Credentials = None,
        credentials_file: Optional[str] = None,
        scopes: Optional[Sequence[str]] = None,
        channel: aio.Channel = None,
        api_mtls_endpoint: str = None,
        client_cert_source: Callable[[], Tuple[bytes, bytes]] = None,
        ssl_channel_credentials: grpc.ChannelCredentials = None,
        quota_project_id=None,
        client_info: gapic_v1.client_info.ClientInfo = DEFAULT_CLIENT_INFO,
    ) -> None:
        """Instantiate the transport.

        Args:
            host (Optional[str]): The hostname to connect to.
            credentials (Optional[google.auth.credentials.Credentials]): The
                authorization credentials to attach to requests. These
                credentials identify the application to the service; if none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
                This argument is ignored if ``channel`` is provided.
            credentials_file (Optional[str]): A file with credentials that can
                be loaded with :func:`google.auth.load_credentials_from_file`.
                This argument is ignored if ``channel`` is provided.
            scopes (Optional[Sequence[str]]): A optional list of scopes needed for this
                service. These are only used when credentials are not specified and
                are passed to :func:`google.auth.default`.
            channel (Optional[aio.Channel]): A ``Channel`` instance through
                which to make calls.
            api_mtls_endpoint (Optional[str]): Deprecated. The mutual TLS endpoint.
                If provided, it overrides the ``host`` argument and tries to create
                a mutual TLS channel with client SSL credentials from
                ``client_cert_source`` or applicatin default SSL credentials.
            client_cert_source (Optional[Callable[[], Tuple[bytes, bytes]]]):
                Deprecated. A callback to provide client SSL certificate bytes and
                private key bytes, both in PEM format. It is ignored if
                ``api_mtls_endpoint`` is None.
            ssl_channel_credentials (grpc.ChannelCredentials): SSL credentials
                for grpc channel. It is ignored if ``channel`` is provided.
            quota_project_id (Optional[str]): An optional project to use for billing
                and quota.
            client_info (google.api_core.gapic_v1.client_info.ClientInfo):	
                The client info used to send a user-agent string along with	
                API requests. If ``None``, then default info will be used.	
                Generally, you only need to set this if you're developing	
                your own client library.

        Raises:
            google.auth.exceptions.MutualTlsChannelError: If mutual TLS transport
              creation failed for any reason.
          google.api_core.exceptions.DuplicateCredentialArgs: If both ``credentials``
              and ``credentials_file`` are passed.
        """
        self._ssl_channel_credentials = ssl_channel_credentials

        if channel:
            # Sanity check: Ensure that channel and credentials are not both
            # provided.
            credentials = False

            # If a channel was explicitly provided, set it.
            self._grpc_channel = channel
            self._ssl_channel_credentials = None
        elif api_mtls_endpoint:
            warnings.warn(
                "api_mtls_endpoint and client_cert_source are deprecated",
                DeprecationWarning,
            )

            host = (
                api_mtls_endpoint
                if ":" in api_mtls_endpoint
                else api_mtls_endpoint + ":443"
            )

            if credentials is None:
                credentials, _ = auth.default(
                    scopes=self.AUTH_SCOPES, quota_project_id=quota_project_id
                )

            # Create SSL credentials with client_cert_source or application
            # default SSL credentials.
            if client_cert_source:
                cert, key = client_cert_source()
                ssl_credentials = grpc.ssl_channel_credentials(
                    certificate_chain=cert, private_key=key
                )
            else:
                ssl_credentials = SslCredentials().ssl_credentials

            # create a new channel. The provided one is ignored.
            self._grpc_channel = type(self).create_channel(
                host,
                credentials=credentials,
                credentials_file=credentials_file,
                ssl_credentials=ssl_credentials,
                scopes=scopes or self.AUTH_SCOPES,
                quota_project_id=quota_project_id,
                options=[
                    ("grpc.max_send_message_length", -1),
                    ("grpc.max_receive_message_length", -1),
                ],
            )
            self._ssl_channel_credentials = ssl_credentials
        else:
            host = host if ":" in host else host + ":443"

            if credentials is None:
                credentials, _ = auth.default(
                    scopes=self.AUTH_SCOPES, quota_project_id=quota_project_id
                )

            # create a new channel. The provided one is ignored.
            self._grpc_channel = type(self).create_channel(
                host,
                credentials=credentials,
                credentials_file=credentials_file,
                ssl_credentials=ssl_channel_credentials,
                scopes=scopes or self.AUTH_SCOPES,
                quota_project_id=quota_project_id,
                options=[
                    ("grpc.max_send_message_length", -1),
                    ("grpc.max_receive_message_length", -1),
                ],
            )

        # Run the base constructor.
        super().__init__(
            host=host,
            credentials=credentials,
            credentials_file=credentials_file,
            scopes=scopes or self.AUTH_SCOPES,
            quota_project_id=quota_project_id,
            client_info=client_info,
        )

        self._stubs = {}
        self._operations_client = None

    @property
    def grpc_channel(self) -> aio.Channel:
        """Create the channel designed to connect to this service.

        This property caches on the instance; repeated calls return
        the same channel.
        """
        # Return the channel from cache.
        return self._grpc_channel

    @property
    def operations_client(self) -> operations_v1.OperationsAsyncClient:
        """Create the client designed to process long-running operations.

        This property caches on the instance; repeated calls return the same
        client.
        """
        # Sanity check: Only create a new client if we do not already have one.
        if self._operations_client is None:
            self._operations_client = operations_v1.OperationsAsyncClient(
                self.grpc_channel
            )

        # Return the client from cache.
        return self._operations_client

    @property
    def create_source(
        self,
    ) -> Callable[
        [securitycenter_service.CreateSourceRequest], Awaitable[gcs_source.Source]
    ]:
        r"""Return a callable for the create source method over gRPC.

        Creates a source.

        Returns:
            Callable[[~.CreateSourceRequest],
                    Awaitable[~.Source]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "create_source" not in self._stubs:
            self._stubs["create_source"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/CreateSource",
                request_serializer=securitycenter_service.CreateSourceRequest.serialize,
                response_deserializer=gcs_source.Source.deserialize,
            )
        return self._stubs["create_source"]

    @property
    def create_finding(
        self,
    ) -> Callable[
        [securitycenter_service.CreateFindingRequest], Awaitable[gcs_finding.Finding]
    ]:
        r"""Return a callable for the create finding method over gRPC.

        Creates a finding. The corresponding source must
        exist for finding creation to succeed.

        Returns:
            Callable[[~.CreateFindingRequest],
                    Awaitable[~.Finding]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "create_finding" not in self._stubs:
            self._stubs["create_finding"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/CreateFinding",
                request_serializer=securitycenter_service.CreateFindingRequest.serialize,
                response_deserializer=gcs_finding.Finding.deserialize,
            )
        return self._stubs["create_finding"]

    @property
    def get_iam_policy(
        self,
    ) -> Callable[[iam_policy.GetIamPolicyRequest], Awaitable[policy.Policy]]:
        r"""Return a callable for the get iam policy method over gRPC.

        Gets the access control policy on the specified
        Source.

        Returns:
            Callable[[~.GetIamPolicyRequest],
                    Awaitable[~.Policy]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "get_iam_policy" not in self._stubs:
            self._stubs["get_iam_policy"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetIamPolicy",
                request_serializer=iam_policy.GetIamPolicyRequest.SerializeToString,
                response_deserializer=policy.Policy.FromString,
            )
        return self._stubs["get_iam_policy"]

    @property
    def get_organization_settings(
        self,
    ) -> Callable[
        [securitycenter_service.GetOrganizationSettingsRequest],
        Awaitable[organization_settings.OrganizationSettings],
    ]:
        r"""Return a callable for the get organization settings method over gRPC.

        Gets the settings for an organization.

        Returns:
            Callable[[~.GetOrganizationSettingsRequest],
                    Awaitable[~.OrganizationSettings]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "get_organization_settings" not in self._stubs:
            self._stubs["get_organization_settings"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetOrganizationSettings",
                request_serializer=securitycenter_service.GetOrganizationSettingsRequest.serialize,
                response_deserializer=organization_settings.OrganizationSettings.deserialize,
            )
        return self._stubs["get_organization_settings"]

    @property
    def get_source(
        self,
    ) -> Callable[[securitycenter_service.GetSourceRequest], Awaitable[source.Source]]:
        r"""Return a callable for the get source method over gRPC.

        Gets a source.

        Returns:
            Callable[[~.GetSourceRequest],
                    Awaitable[~.Source]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "get_source" not in self._stubs:
            self._stubs["get_source"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetSource",
                request_serializer=securitycenter_service.GetSourceRequest.serialize,
                response_deserializer=source.Source.deserialize,
            )
        return self._stubs["get_source"]

    @property
    def group_assets(
        self,
    ) -> Callable[
        [securitycenter_service.GroupAssetsRequest],
        Awaitable[securitycenter_service.GroupAssetsResponse],
    ]:
        r"""Return a callable for the group assets method over gRPC.

        Filters an organization's assets and  groups them by
        their specified properties.

        Returns:
            Callable[[~.GroupAssetsRequest],
                    Awaitable[~.GroupAssetsResponse]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "group_assets" not in self._stubs:
            self._stubs["group_assets"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/GroupAssets",
                request_serializer=securitycenter_service.GroupAssetsRequest.serialize,
                response_deserializer=securitycenter_service.GroupAssetsResponse.deserialize,
            )
        return self._stubs["group_assets"]

    @property
    def group_findings(
        self,
    ) -> Callable[
        [securitycenter_service.GroupFindingsRequest],
        Awaitable[securitycenter_service.GroupFindingsResponse],
    ]:
        r"""Return a callable for the group findings method over gRPC.

        Filters an organization or source's findings and groups them by
        their specified properties.

        To group across all sources provide a ``-`` as the source id.
        Example:
        /v1beta1/organizations/{organization_id}/sources/-/findings

        Returns:
            Callable[[~.GroupFindingsRequest],
                    Awaitable[~.GroupFindingsResponse]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "group_findings" not in self._stubs:
            self._stubs["group_findings"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/GroupFindings",
                request_serializer=securitycenter_service.GroupFindingsRequest.serialize,
                response_deserializer=securitycenter_service.GroupFindingsResponse.deserialize,
            )
        return self._stubs["group_findings"]

    @property
    def list_assets(
        self,
    ) -> Callable[
        [securitycenter_service.ListAssetsRequest],
        Awaitable[securitycenter_service.ListAssetsResponse],
    ]:
        r"""Return a callable for the list assets method over gRPC.

        Lists an organization's assets.

        Returns:
            Callable[[~.ListAssetsRequest],
                    Awaitable[~.ListAssetsResponse]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "list_assets" not in self._stubs:
            self._stubs["list_assets"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListAssets",
                request_serializer=securitycenter_service.ListAssetsRequest.serialize,
                response_deserializer=securitycenter_service.ListAssetsResponse.deserialize,
            )
        return self._stubs["list_assets"]

    @property
    def list_findings(
        self,
    ) -> Callable[
        [securitycenter_service.ListFindingsRequest],
        Awaitable[securitycenter_service.ListFindingsResponse],
    ]:
        r"""Return a callable for the list findings method over gRPC.

        Lists an organization or source's findings.

        To list across all sources provide a ``-`` as the source id.
        Example:
        /v1beta1/organizations/{organization_id}/sources/-/findings

        Returns:
            Callable[[~.ListFindingsRequest],
                    Awaitable[~.ListFindingsResponse]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "list_findings" not in self._stubs:
            self._stubs["list_findings"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListFindings",
                request_serializer=securitycenter_service.ListFindingsRequest.serialize,
                response_deserializer=securitycenter_service.ListFindingsResponse.deserialize,
            )
        return self._stubs["list_findings"]

    @property
    def list_sources(
        self,
    ) -> Callable[
        [securitycenter_service.ListSourcesRequest],
        Awaitable[securitycenter_service.ListSourcesResponse],
    ]:
        r"""Return a callable for the list sources method over gRPC.

        Lists all sources belonging to an organization.

        Returns:
            Callable[[~.ListSourcesRequest],
                    Awaitable[~.ListSourcesResponse]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "list_sources" not in self._stubs:
            self._stubs["list_sources"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListSources",
                request_serializer=securitycenter_service.ListSourcesRequest.serialize,
                response_deserializer=securitycenter_service.ListSourcesResponse.deserialize,
            )
        return self._stubs["list_sources"]

    @property
    def run_asset_discovery(
        self,
    ) -> Callable[
        [securitycenter_service.RunAssetDiscoveryRequest],
        Awaitable[operations.Operation],
    ]:
        r"""Return a callable for the run asset discovery method over gRPC.

        Runs asset discovery. The discovery is tracked with a
        long-running operation.

        This API can only be called with limited frequency for an
        organization. If it is called too frequently the caller will
        receive a TOO_MANY_REQUESTS error.

        Returns:
            Callable[[~.RunAssetDiscoveryRequest],
                    Awaitable[~.Operation]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "run_asset_discovery" not in self._stubs:
            self._stubs["run_asset_discovery"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/RunAssetDiscovery",
                request_serializer=securitycenter_service.RunAssetDiscoveryRequest.serialize,
                response_deserializer=operations.Operation.FromString,
            )
        return self._stubs["run_asset_discovery"]

    @property
    def set_finding_state(
        self,
    ) -> Callable[
        [securitycenter_service.SetFindingStateRequest], Awaitable[finding.Finding]
    ]:
        r"""Return a callable for the set finding state method over gRPC.

        Updates the state of a finding.

        Returns:
            Callable[[~.SetFindingStateRequest],
                    Awaitable[~.Finding]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "set_finding_state" not in self._stubs:
            self._stubs["set_finding_state"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/SetFindingState",
                request_serializer=securitycenter_service.SetFindingStateRequest.serialize,
                response_deserializer=finding.Finding.deserialize,
            )
        return self._stubs["set_finding_state"]

    @property
    def set_iam_policy(
        self,
    ) -> Callable[[iam_policy.SetIamPolicyRequest], Awaitable[policy.Policy]]:
        r"""Return a callable for the set iam policy method over gRPC.

        Sets the access control policy on the specified
        Source.

        Returns:
            Callable[[~.SetIamPolicyRequest],
                    Awaitable[~.Policy]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "set_iam_policy" not in self._stubs:
            self._stubs["set_iam_policy"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/SetIamPolicy",
                request_serializer=iam_policy.SetIamPolicyRequest.SerializeToString,
                response_deserializer=policy.Policy.FromString,
            )
        return self._stubs["set_iam_policy"]

    @property
    def test_iam_permissions(
        self,
    ) -> Callable[
        [iam_policy.TestIamPermissionsRequest],
        Awaitable[iam_policy.TestIamPermissionsResponse],
    ]:
        r"""Return a callable for the test iam permissions method over gRPC.

        Returns the permissions that a caller has on the
        specified source.

        Returns:
            Callable[[~.TestIamPermissionsRequest],
                    Awaitable[~.TestIamPermissionsResponse]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "test_iam_permissions" not in self._stubs:
            self._stubs["test_iam_permissions"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/TestIamPermissions",
                request_serializer=iam_policy.TestIamPermissionsRequest.SerializeToString,
                response_deserializer=iam_policy.TestIamPermissionsResponse.FromString,
            )
        return self._stubs["test_iam_permissions"]

    @property
    def update_finding(
        self,
    ) -> Callable[
        [securitycenter_service.UpdateFindingRequest], Awaitable[gcs_finding.Finding]
    ]:
        r"""Return a callable for the update finding method over gRPC.

        Creates or updates a finding. The corresponding
        source must exist for a finding creation to succeed.

        Returns:
            Callable[[~.UpdateFindingRequest],
                    Awaitable[~.Finding]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "update_finding" not in self._stubs:
            self._stubs["update_finding"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateFinding",
                request_serializer=securitycenter_service.UpdateFindingRequest.serialize,
                response_deserializer=gcs_finding.Finding.deserialize,
            )
        return self._stubs["update_finding"]

    @property
    def update_organization_settings(
        self,
    ) -> Callable[
        [securitycenter_service.UpdateOrganizationSettingsRequest],
        Awaitable[gcs_organization_settings.OrganizationSettings],
    ]:
        r"""Return a callable for the update organization settings method over gRPC.

        Updates an organization's settings.

        Returns:
            Callable[[~.UpdateOrganizationSettingsRequest],
                    Awaitable[~.OrganizationSettings]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "update_organization_settings" not in self._stubs:
            self._stubs["update_organization_settings"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateOrganizationSettings",
                request_serializer=securitycenter_service.UpdateOrganizationSettingsRequest.serialize,
                response_deserializer=gcs_organization_settings.OrganizationSettings.deserialize,
            )
        return self._stubs["update_organization_settings"]

    @property
    def update_source(
        self,
    ) -> Callable[
        [securitycenter_service.UpdateSourceRequest], Awaitable[gcs_source.Source]
    ]:
        r"""Return a callable for the update source method over gRPC.

        Updates a source.

        Returns:
            Callable[[~.UpdateSourceRequest],
                    Awaitable[~.Source]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "update_source" not in self._stubs:
            self._stubs["update_source"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateSource",
                request_serializer=securitycenter_service.UpdateSourceRequest.serialize,
                response_deserializer=gcs_source.Source.deserialize,
            )
        return self._stubs["update_source"]

    @property
    def update_security_marks(
        self,
    ) -> Callable[
        [securitycenter_service.UpdateSecurityMarksRequest],
        Awaitable[gcs_security_marks.SecurityMarks],
    ]:
        r"""Return a callable for the update security marks method over gRPC.

        Updates security marks.

        Returns:
            Callable[[~.UpdateSecurityMarksRequest],
                    Awaitable[~.SecurityMarks]]:
                A function that, when called, will call the underlying RPC
                on the server.
        """
        # Generate a "stub function" on-the-fly which will actually make
        # the request.
        # gRPC handles serialization and deserialization, so we just need
        # to pass in the functions for each.
        if "update_security_marks" not in self._stubs:
            self._stubs["update_security_marks"] = self.grpc_channel.unary_unary(
                "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateSecurityMarks",
                request_serializer=securitycenter_service.UpdateSecurityMarksRequest.serialize,
                response_deserializer=gcs_security_marks.SecurityMarks.deserialize,
            )
        return self._stubs["update_security_marks"]


__all__ = ("SecurityCenterGrpcAsyncIOTransport",)
