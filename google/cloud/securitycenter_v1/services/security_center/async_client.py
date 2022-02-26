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
from collections import OrderedDict
import functools
import re
from typing import Dict, Optional, Sequence, Tuple, Type, Union
import pkg_resources

from google.api_core.client_options import ClientOptions
from google.api_core import exceptions as core_exceptions
from google.api_core import gapic_v1
from google.api_core import retry as retries
from google.auth import credentials as ga_credentials  # type: ignore
from google.oauth2 import service_account  # type: ignore

try:
    OptionalRetry = Union[retries.Retry, gapic_v1.method._MethodDefault]
except AttributeError:  # pragma: NO COVER
    OptionalRetry = Union[retries.Retry, object]  # type: ignore

from google.api_core import operation  # type: ignore
from google.api_core import operation_async  # type: ignore
from google.cloud.securitycenter_v1.services.security_center import pagers
from google.cloud.securitycenter_v1.types import access
from google.cloud.securitycenter_v1.types import external_system as gcs_external_system
from google.cloud.securitycenter_v1.types import finding
from google.cloud.securitycenter_v1.types import finding as gcs_finding
from google.cloud.securitycenter_v1.types import indicator
from google.cloud.securitycenter_v1.types import mute_config
from google.cloud.securitycenter_v1.types import mute_config as gcs_mute_config
from google.cloud.securitycenter_v1.types import notification_config
from google.cloud.securitycenter_v1.types import (
    notification_config as gcs_notification_config,
)
from google.cloud.securitycenter_v1.types import organization_settings
from google.cloud.securitycenter_v1.types import (
    organization_settings as gcs_organization_settings,
)
from google.cloud.securitycenter_v1.types import run_asset_discovery_response
from google.cloud.securitycenter_v1.types import security_marks
from google.cloud.securitycenter_v1.types import security_marks as gcs_security_marks
from google.cloud.securitycenter_v1.types import securitycenter_service
from google.cloud.securitycenter_v1.types import source
from google.cloud.securitycenter_v1.types import source as gcs_source
from google.cloud.securitycenter_v1.types import vulnerability
from google.iam.v1 import iam_policy_pb2  # type: ignore
from google.iam.v1 import policy_pb2  # type: ignore
from google.protobuf import empty_pb2  # type: ignore
from google.protobuf import field_mask_pb2  # type: ignore
from google.protobuf import timestamp_pb2  # type: ignore
from .transports.base import SecurityCenterTransport, DEFAULT_CLIENT_INFO
from .transports.grpc_asyncio import SecurityCenterGrpcAsyncIOTransport
from .client import SecurityCenterClient


class SecurityCenterAsyncClient:
    """V1 APIs for Security Center service."""

    _client: SecurityCenterClient

    DEFAULT_ENDPOINT = SecurityCenterClient.DEFAULT_ENDPOINT
    DEFAULT_MTLS_ENDPOINT = SecurityCenterClient.DEFAULT_MTLS_ENDPOINT

    asset_path = staticmethod(SecurityCenterClient.asset_path)
    parse_asset_path = staticmethod(SecurityCenterClient.parse_asset_path)
    external_system_path = staticmethod(SecurityCenterClient.external_system_path)
    parse_external_system_path = staticmethod(
        SecurityCenterClient.parse_external_system_path
    )
    finding_path = staticmethod(SecurityCenterClient.finding_path)
    parse_finding_path = staticmethod(SecurityCenterClient.parse_finding_path)
    mute_config_path = staticmethod(SecurityCenterClient.mute_config_path)
    parse_mute_config_path = staticmethod(SecurityCenterClient.parse_mute_config_path)
    notification_config_path = staticmethod(
        SecurityCenterClient.notification_config_path
    )
    parse_notification_config_path = staticmethod(
        SecurityCenterClient.parse_notification_config_path
    )
    organization_settings_path = staticmethod(
        SecurityCenterClient.organization_settings_path
    )
    parse_organization_settings_path = staticmethod(
        SecurityCenterClient.parse_organization_settings_path
    )
    security_marks_path = staticmethod(SecurityCenterClient.security_marks_path)
    parse_security_marks_path = staticmethod(
        SecurityCenterClient.parse_security_marks_path
    )
    source_path = staticmethod(SecurityCenterClient.source_path)
    parse_source_path = staticmethod(SecurityCenterClient.parse_source_path)
    topic_path = staticmethod(SecurityCenterClient.topic_path)
    parse_topic_path = staticmethod(SecurityCenterClient.parse_topic_path)
    common_billing_account_path = staticmethod(
        SecurityCenterClient.common_billing_account_path
    )
    parse_common_billing_account_path = staticmethod(
        SecurityCenterClient.parse_common_billing_account_path
    )
    common_folder_path = staticmethod(SecurityCenterClient.common_folder_path)
    parse_common_folder_path = staticmethod(
        SecurityCenterClient.parse_common_folder_path
    )
    common_organization_path = staticmethod(
        SecurityCenterClient.common_organization_path
    )
    parse_common_organization_path = staticmethod(
        SecurityCenterClient.parse_common_organization_path
    )
    common_project_path = staticmethod(SecurityCenterClient.common_project_path)
    parse_common_project_path = staticmethod(
        SecurityCenterClient.parse_common_project_path
    )
    common_location_path = staticmethod(SecurityCenterClient.common_location_path)
    parse_common_location_path = staticmethod(
        SecurityCenterClient.parse_common_location_path
    )

    @classmethod
    def from_service_account_info(cls, info: dict, *args, **kwargs):
        """Creates an instance of this client using the provided credentials
            info.

        Args:
            info (dict): The service account private key info.
            args: Additional arguments to pass to the constructor.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            SecurityCenterAsyncClient: The constructed client.
        """
        return SecurityCenterClient.from_service_account_info.__func__(SecurityCenterAsyncClient, info, *args, **kwargs)  # type: ignore

    @classmethod
    def from_service_account_file(cls, filename: str, *args, **kwargs):
        """Creates an instance of this client using the provided credentials
            file.

        Args:
            filename (str): The path to the service account private key json
                file.
            args: Additional arguments to pass to the constructor.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            SecurityCenterAsyncClient: The constructed client.
        """
        return SecurityCenterClient.from_service_account_file.__func__(SecurityCenterAsyncClient, filename, *args, **kwargs)  # type: ignore

    from_service_account_json = from_service_account_file

    @classmethod
    def get_mtls_endpoint_and_cert_source(
        cls, client_options: Optional[ClientOptions] = None
    ):
        """Return the API endpoint and client cert source for mutual TLS.

        The client cert source is determined in the following order:
        (1) if `GOOGLE_API_USE_CLIENT_CERTIFICATE` environment variable is not "true", the
        client cert source is None.
        (2) if `client_options.client_cert_source` is provided, use the provided one; if the
        default client cert source exists, use the default one; otherwise the client cert
        source is None.

        The API endpoint is determined in the following order:
        (1) if `client_options.api_endpoint` if provided, use the provided one.
        (2) if `GOOGLE_API_USE_CLIENT_CERTIFICATE` environment variable is "always", use the
        default mTLS endpoint; if the environment variabel is "never", use the default API
        endpoint; otherwise if client cert source exists, use the default mTLS endpoint, otherwise
        use the default API endpoint.

        More details can be found at https://google.aip.dev/auth/4114.

        Args:
            client_options (google.api_core.client_options.ClientOptions): Custom options for the
                client. Only the `api_endpoint` and `client_cert_source` properties may be used
                in this method.

        Returns:
            Tuple[str, Callable[[], Tuple[bytes, bytes]]]: returns the API endpoint and the
                client cert source to use.

        Raises:
            google.auth.exceptions.MutualTLSChannelError: If any errors happen.
        """
        return SecurityCenterClient.get_mtls_endpoint_and_cert_source(client_options)  # type: ignore

    @property
    def transport(self) -> SecurityCenterTransport:
        """Returns the transport used by the client instance.

        Returns:
            SecurityCenterTransport: The transport used by the client instance.
        """
        return self._client.transport

    get_transport_class = functools.partial(
        type(SecurityCenterClient).get_transport_class, type(SecurityCenterClient)
    )

    def __init__(
        self,
        *,
        credentials: ga_credentials.Credentials = None,
        transport: Union[str, SecurityCenterTransport] = "grpc_asyncio",
        client_options: ClientOptions = None,
        client_info: gapic_v1.client_info.ClientInfo = DEFAULT_CLIENT_INFO,
    ) -> None:
        """Instantiates the security center client.

        Args:
            credentials (Optional[google.auth.credentials.Credentials]): The
                authorization credentials to attach to requests. These
                credentials identify the application to the service; if none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            transport (Union[str, ~.SecurityCenterTransport]): The
                transport to use. If set to None, a transport is chosen
                automatically.
            client_options (ClientOptions): Custom options for the client. It
                won't take effect if a ``transport`` instance is provided.
                (1) The ``api_endpoint`` property can be used to override the
                default endpoint provided by the client. GOOGLE_API_USE_MTLS_ENDPOINT
                environment variable can also be used to override the endpoint:
                "always" (always use the default mTLS endpoint), "never" (always
                use the default regular endpoint) and "auto" (auto switch to the
                default mTLS endpoint if client certificate is present, this is
                the default value). However, the ``api_endpoint`` property takes
                precedence if provided.
                (2) If GOOGLE_API_USE_CLIENT_CERTIFICATE environment variable
                is "true", then the ``client_cert_source`` property can be used
                to provide client certificate for mutual TLS transport. If
                not provided, the default SSL client certificate will be used if
                present. If GOOGLE_API_USE_CLIENT_CERTIFICATE is "false" or not
                set, no client certificate will be used.

        Raises:
            google.auth.exceptions.MutualTlsChannelError: If mutual TLS transport
                creation failed for any reason.
        """
        self._client = SecurityCenterClient(
            credentials=credentials,
            transport=transport,
            client_options=client_options,
            client_info=client_info,
        )

    async def bulk_mute_findings(
        self,
        request: Union[securitycenter_service.BulkMuteFindingsRequest, dict] = None,
        *,
        parent: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> operation_async.AsyncOperation:
        r"""Kicks off an LRO to bulk mute findings for a parent
        based on a filter. The parent can be either an
        organization, folder or project. The findings matched by
        the filter will be muted after the LRO is done.


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_bulk_mute_findings():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.BulkMuteFindingsRequest(
                    parent="parent_value",
                )

                # Make the request
                operation = client.bulk_mute_findings(request=request)

                print("Waiting for operation to complete...")

                response = operation.result()

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.BulkMuteFindingsRequest, dict]):
                The request object. Request message for bulk findings
                update.
                Note:
                1. If multiple bulk update requests match the same
                resource, the order in which they get executed is not
                defined.
                2. Once a bulk operation is started, there is no way to
                stop it.
            parent (:class:`str`):
                Required. The parent, at which bulk action needs to be
                applied. Its format is
                "organizations/[organization_id]",
                "folders/[folder_id]", "projects/[project_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.api_core.operation_async.AsyncOperation:
                An object representing a long-running operation.

                The result type for the operation will be
                :class:`google.cloud.securitycenter_v1.types.BulkMuteFindingsResponse`
                The response to a BulkMute request. Contains the LRO
                information.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.BulkMuteFindingsRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.bulk_mute_findings,
            default_timeout=None,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Wrap the response in an operation future.
        response = operation_async.from_gapic(
            response,
            self._client._transport.operations_client,
            securitycenter_service.BulkMuteFindingsResponse,
            metadata_type=empty_pb2.Empty,
        )

        # Done; return the response.
        return response

    async def create_source(
        self,
        request: Union[securitycenter_service.CreateSourceRequest, dict] = None,
        *,
        parent: str = None,
        source: gcs_source.Source = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_source.Source:
        r"""Creates a source.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_create_source():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.CreateSourceRequest(
                    parent="parent_value",
                )

                # Make the request
                response = client.create_source(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.CreateSourceRequest, dict]):
                The request object. Request message for creating a
                source.
            parent (:class:`str`):
                Required. Resource name of the new source's parent. Its
                format should be "organizations/[organization_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            source (:class:`google.cloud.securitycenter_v1.types.Source`):
                Required. The Source being created, only the
                display_name and description will be used. All other
                fields will be ignored.

                This corresponds to the ``source`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.Source:
                Security Command Center finding
                source. A finding source is an entity or
                a mechanism that can produce a finding.
                A source is like a container of findings
                that come from the same scanner, logger,
                monitor, and other tools.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, source])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.CreateSourceRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent
        if source is not None:
            request.source = source

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.create_source,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def create_finding(
        self,
        request: Union[securitycenter_service.CreateFindingRequest, dict] = None,
        *,
        parent: str = None,
        finding_id: str = None,
        finding: gcs_finding.Finding = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_finding.Finding:
        r"""Creates a finding. The corresponding source must
        exist for finding creation to succeed.


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_create_finding():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.CreateFindingRequest(
                    parent="parent_value",
                    finding_id="finding_id_value",
                )

                # Make the request
                response = client.create_finding(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.CreateFindingRequest, dict]):
                The request object. Request message for creating a
                finding.
            parent (:class:`str`):
                Required. Resource name of the new finding's parent. Its
                format should be
                "organizations/[organization_id]/sources/[source_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            finding_id (:class:`str`):
                Required. Unique identifier provided
                by the client within the parent scope.
                It must be alphanumeric and less than or
                equal to 32 characters and greater than
                0 characters in length.

                This corresponds to the ``finding_id`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            finding (:class:`google.cloud.securitycenter_v1.types.Finding`):
                Required. The Finding being created. The name and
                security_marks will be ignored as they are both output
                only fields on this resource.

                This corresponds to the ``finding`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.Finding:
                Security Command Center finding.
                A finding is a record of assessment data
                like security, risk, health, or privacy,
                that is ingested into Security Command
                Center for presentation, notification,
                analysis, policy testing, and
                enforcement. For example, a cross-site
                scripting (XSS) vulnerability in an App
                Engine application is a finding.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, finding_id, finding])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.CreateFindingRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent
        if finding_id is not None:
            request.finding_id = finding_id
        if finding is not None:
            request.finding = finding

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.create_finding,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def create_mute_config(
        self,
        request: Union[securitycenter_service.CreateMuteConfigRequest, dict] = None,
        *,
        parent: str = None,
        mute_config: gcs_mute_config.MuteConfig = None,
        mute_config_id: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_mute_config.MuteConfig:
        r"""Creates a mute config.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_create_mute_config():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                mute_config = securitycenter_v1.MuteConfig()
                mute_config.filter = "filter_value"

                request = securitycenter_v1.CreateMuteConfigRequest(
                    parent="parent_value",
                    mute_config=mute_config,
                    mute_config_id="mute_config_id_value",
                )

                # Make the request
                response = client.create_mute_config(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.CreateMuteConfigRequest, dict]):
                The request object. Request message for creating a mute
                config.
            parent (:class:`str`):
                Required. Resource name of the new mute configs's
                parent. Its format is "organizations/[organization_id]",
                "folders/[folder_id]", or "projects/[project_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            mute_config (:class:`google.cloud.securitycenter_v1.types.MuteConfig`):
                Required. The mute config being
                created.

                This corresponds to the ``mute_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            mute_config_id (:class:`str`):
                Required. Unique identifier provided
                by the client within the parent scope.
                It must consist of lower case letters,
                numbers, and hyphen, with the first
                character a letter, the last a letter or
                a number, and a 63 character maximum.

                This corresponds to the ``mute_config_id`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.MuteConfig:
                A mute config is a Cloud SCC resource
                that contains the configuration to mute
                create/update events of findings.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, mute_config, mute_config_id])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.CreateMuteConfigRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent
        if mute_config is not None:
            request.mute_config = mute_config
        if mute_config_id is not None:
            request.mute_config_id = mute_config_id

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.create_mute_config,
            default_timeout=None,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def create_notification_config(
        self,
        request: Union[
            securitycenter_service.CreateNotificationConfigRequest, dict
        ] = None,
        *,
        parent: str = None,
        config_id: str = None,
        notification_config: gcs_notification_config.NotificationConfig = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_notification_config.NotificationConfig:
        r"""Creates a notification config.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_create_notification_config():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.CreateNotificationConfigRequest(
                    parent="parent_value",
                    config_id="config_id_value",
                )

                # Make the request
                response = client.create_notification_config(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.CreateNotificationConfigRequest, dict]):
                The request object. Request message for creating a
                notification config.
            parent (:class:`str`):
                Required. Resource name of the new notification config's
                parent. Its format is "organizations/[organization_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            config_id (:class:`str`):
                Required.
                Unique identifier provided by the client
                within the parent scope. It must be
                between 1 and 128 characters, and
                contains alphanumeric characters,
                underscores or hyphens only.

                This corresponds to the ``config_id`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            notification_config (:class:`google.cloud.securitycenter_v1.types.NotificationConfig`):
                Required. The notification config
                being created. The name and the service
                account will be ignored as they are both
                output only fields on this resource.

                This corresponds to the ``notification_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.NotificationConfig:
                Cloud Security Command Center (Cloud
                SCC) notification configs.
                A notification config is a Cloud SCC
                resource that contains the configuration
                to send notifications for create/update
                events of findings, assets and etc.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, config_id, notification_config])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.CreateNotificationConfigRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent
        if config_id is not None:
            request.config_id = config_id
        if notification_config is not None:
            request.notification_config = notification_config

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.create_notification_config,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def delete_mute_config(
        self,
        request: Union[securitycenter_service.DeleteMuteConfigRequest, dict] = None,
        *,
        name: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> None:
        r"""Deletes an existing mute config.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_delete_mute_config():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.DeleteMuteConfigRequest(
                    name="name_value",
                )

                # Make the request
                client.delete_mute_config(request=request)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.DeleteMuteConfigRequest, dict]):
                The request object. Request message for deleting a mute
                config.
            name (:class:`str`):
                Required. Name of the mute config to delete. Its format
                is organizations/{organization}/muteConfigs/{config_id},
                folders/{folder}/muteConfigs/{config_id}, or
                projects/{project}/muteConfigs/{config_id}

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.
        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.DeleteMuteConfigRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if name is not None:
            request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.delete_mute_config,
            default_timeout=None,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        await rpc(
            request, retry=retry, timeout=timeout, metadata=metadata,
        )

    async def delete_notification_config(
        self,
        request: Union[
            securitycenter_service.DeleteNotificationConfigRequest, dict
        ] = None,
        *,
        name: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> None:
        r"""Deletes a notification config.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_delete_notification_config():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.DeleteNotificationConfigRequest(
                    name="name_value",
                )

                # Make the request
                client.delete_notification_config(request=request)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.DeleteNotificationConfigRequest, dict]):
                The request object. Request message for deleting a
                notification config.
            name (:class:`str`):
                Required. Name of the notification config to delete. Its
                format is
                "organizations/[organization_id]/notificationConfigs/[config_id]".

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.
        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.DeleteNotificationConfigRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if name is not None:
            request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.delete_notification_config,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        await rpc(
            request, retry=retry, timeout=timeout, metadata=metadata,
        )

    async def get_iam_policy(
        self,
        request: Union[iam_policy_pb2.GetIamPolicyRequest, dict] = None,
        *,
        resource: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> policy_pb2.Policy:
        r"""Gets the access control policy on the specified
        Source.


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_get_iam_policy():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.GetIamPolicyRequest(
                    resource="resource_value",
                )

                # Make the request
                response = client.get_iam_policy(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.iam.v1.iam_policy_pb2.GetIamPolicyRequest, dict]):
                The request object. Request message for `GetIamPolicy`
                method.
            resource (:class:`str`):
                REQUIRED: The resource for which the
                policy is being requested. See the
                operation documentation for the
                appropriate value for this field.

                This corresponds to the ``resource`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.iam.v1.policy_pb2.Policy:
                Defines an Identity and Access Management (IAM) policy. It is used to
                   specify access control policies for Cloud Platform
                   resources.

                   A Policy is a collection of bindings. A binding binds
                   one or more members to a single role. Members can be
                   user accounts, service accounts, Google groups, and
                   domains (such as G Suite). A role is a named list of
                   permissions (defined by IAM or configured by users).
                   A binding can optionally specify a condition, which
                   is a logic expression that further constrains the
                   role binding based on attributes about the request
                   and/or target resource.

                   **JSON Example**

                      {
                         "bindings": [
                            {
                               "role":
                               "roles/resourcemanager.organizationAdmin",
                               "members": [ "user:mike@example.com",
                               "group:admins@example.com",
                               "domain:google.com",
                               "serviceAccount:my-project-id@appspot.gserviceaccount.com"
                               ]

                            }, { "role":
                            "roles/resourcemanager.organizationViewer",
                            "members": ["user:eve@example.com"],
                            "condition": { "title": "expirable access",
                            "description": "Does not grant access after
                            Sep 2020", "expression": "request.time <
                            timestamp('2020-10-01T00:00:00.000Z')", } }

                         ]

                      }

                   **YAML Example**

                      bindings: - members: - user:\ mike@example.com -
                      group:\ admins@example.com - domain:google.com -
                      serviceAccount:\ my-project-id@appspot.gserviceaccount.com
                      role: roles/resourcemanager.organizationAdmin -
                      members: - user:\ eve@example.com role:
                      roles/resourcemanager.organizationViewer
                      condition: title: expirable access description:
                      Does not grant access after Sep 2020 expression:
                      request.time <
                      timestamp('2020-10-01T00:00:00.000Z')

                   For a description of IAM and its features, see the
                   [IAM developer's
                   guide](\ https://cloud.google.com/iam/docs).

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([resource])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # The request isn't a proto-plus wrapped type,
        # so it must be constructed via keyword expansion.
        if isinstance(request, dict):
            request = iam_policy_pb2.GetIamPolicyRequest(**request)
        elif not request:
            request = iam_policy_pb2.GetIamPolicyRequest(resource=resource,)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.get_iam_policy,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=60.0,
            ),
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("resource", request.resource),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def get_mute_config(
        self,
        request: Union[securitycenter_service.GetMuteConfigRequest, dict] = None,
        *,
        name: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> mute_config.MuteConfig:
        r"""Gets a mute config.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_get_mute_config():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.GetMuteConfigRequest(
                    name="name_value",
                )

                # Make the request
                response = client.get_mute_config(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.GetMuteConfigRequest, dict]):
                The request object. Request message for retrieving a
                mute config.
            name (:class:`str`):
                Required. Name of the mute config to retrieve. Its
                format is
                organizations/{organization}/muteConfigs/{config_id},
                folders/{folder}/muteConfigs/{config_id}, or
                projects/{project}/muteConfigs/{config_id}

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.MuteConfig:
                A mute config is a Cloud SCC resource
                that contains the configuration to mute
                create/update events of findings.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.GetMuteConfigRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if name is not None:
            request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.get_mute_config,
            default_timeout=None,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def get_notification_config(
        self,
        request: Union[
            securitycenter_service.GetNotificationConfigRequest, dict
        ] = None,
        *,
        name: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> notification_config.NotificationConfig:
        r"""Gets a notification config.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_get_notification_config():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.GetNotificationConfigRequest(
                    name="name_value",
                )

                # Make the request
                response = client.get_notification_config(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.GetNotificationConfigRequest, dict]):
                The request object. Request message for getting a
                notification config.
            name (:class:`str`):
                Required. Name of the notification config to get. Its
                format is
                "organizations/[organization_id]/notificationConfigs/[config_id]".

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.NotificationConfig:
                Cloud Security Command Center (Cloud
                SCC) notification configs.
                A notification config is a Cloud SCC
                resource that contains the configuration
                to send notifications for create/update
                events of findings, assets and etc.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.GetNotificationConfigRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if name is not None:
            request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.get_notification_config,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=60.0,
            ),
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def get_organization_settings(
        self,
        request: Union[
            securitycenter_service.GetOrganizationSettingsRequest, dict
        ] = None,
        *,
        name: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> organization_settings.OrganizationSettings:
        r"""Gets the settings for an organization.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_get_organization_settings():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.GetOrganizationSettingsRequest(
                    name="name_value",
                )

                # Make the request
                response = client.get_organization_settings(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.GetOrganizationSettingsRequest, dict]):
                The request object. Request message for getting
                organization settings.
            name (:class:`str`):
                Required. Name of the organization to get organization
                settings for. Its format is
                "organizations/[organization_id]/organizationSettings".

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.OrganizationSettings:
                User specified settings that are
                attached to the Security Command Center
                organization.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.GetOrganizationSettingsRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if name is not None:
            request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.get_organization_settings,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=60.0,
            ),
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def get_source(
        self,
        request: Union[securitycenter_service.GetSourceRequest, dict] = None,
        *,
        name: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> source.Source:
        r"""Gets a source.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_get_source():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.GetSourceRequest(
                    name="name_value",
                )

                # Make the request
                response = client.get_source(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.GetSourceRequest, dict]):
                The request object. Request message for getting a
                source.
            name (:class:`str`):
                Required. Relative resource name of the source. Its
                format is
                "organizations/[organization_id]/source/[source_id]".

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.Source:
                Security Command Center finding
                source. A finding source is an entity or
                a mechanism that can produce a finding.
                A source is like a container of findings
                that come from the same scanner, logger,
                monitor, and other tools.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.GetSourceRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if name is not None:
            request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.get_source,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=60.0,
            ),
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def group_assets(
        self,
        request: Union[securitycenter_service.GroupAssetsRequest, dict] = None,
        *,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.GroupAssetsAsyncPager:
        r"""Filters an organization's assets and  groups them by
        their specified properties.


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_group_assets():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.GroupAssetsRequest(
                    parent="parent_value",
                    group_by="group_by_value",
                )

                # Make the request
                page_result = client.group_assets(request=request)

                # Handle the response
                for response in page_result:
                    print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.GroupAssetsRequest, dict]):
                The request object. Request message for grouping by
                assets.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.services.security_center.pagers.GroupAssetsAsyncPager:
                Response message for grouping by
                assets.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        request = securitycenter_service.GroupAssetsRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.group_assets,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=480.0,
            ),
            default_timeout=480.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__aiter__` convenience method.
        response = pagers.GroupAssetsAsyncPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    async def group_findings(
        self,
        request: Union[securitycenter_service.GroupFindingsRequest, dict] = None,
        *,
        parent: str = None,
        group_by: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.GroupFindingsAsyncPager:
        r"""Filters an organization or source's findings and groups them by
        their specified properties.

        To group across all sources provide a ``-`` as the source id.
        Example: /v1/organizations/{organization_id}/sources/-/findings,
        /v1/folders/{folder_id}/sources/-/findings,
        /v1/projects/{project_id}/sources/-/findings


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_group_findings():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.GroupFindingsRequest(
                    parent="parent_value",
                    group_by="group_by_value",
                )

                # Make the request
                page_result = client.group_findings(request=request)

                # Handle the response
                for response in page_result:
                    print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.GroupFindingsRequest, dict]):
                The request object. Request message for grouping by
                findings.
            parent (:class:`str`):
                Required. Name of the source to groupBy. Its format is
                "organizations/[organization_id]/sources/[source_id]",
                folders/[folder_id]/sources/[source_id], or
                projects/[project_id]/sources/[source_id]. To groupBy
                across all sources provide a source_id of ``-``. For
                example: organizations/{organization_id}/sources/-,
                folders/{folder_id}/sources/-, or
                projects/{project_id}/sources/-

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            group_by (:class:`str`):
                Required. Expression that defines what assets fields to
                use for grouping (including ``state_change``). The
                string value should follow SQL syntax: comma separated
                list of fields. For example: "parent,resource_name".

                The following fields are supported:

                -  resource_name
                -  category
                -  state
                -  parent
                -  severity

                The following fields are supported when compare_duration
                is set:

                -  state_change

                This corresponds to the ``group_by`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.services.security_center.pagers.GroupFindingsAsyncPager:
                Response message for group by
                findings.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, group_by])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.GroupFindingsRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent
        if group_by is not None:
            request.group_by = group_by

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.group_findings,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=480.0,
            ),
            default_timeout=480.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__aiter__` convenience method.
        response = pagers.GroupFindingsAsyncPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    async def list_assets(
        self,
        request: Union[securitycenter_service.ListAssetsRequest, dict] = None,
        *,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListAssetsAsyncPager:
        r"""Lists an organization's assets.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_list_assets():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.ListAssetsRequest(
                    parent="parent_value",
                )

                # Make the request
                page_result = client.list_assets(request=request)

                # Handle the response
                for response in page_result:
                    print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.ListAssetsRequest, dict]):
                The request object. Request message for listing assets.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.services.security_center.pagers.ListAssetsAsyncPager:
                Response message for listing assets.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        request = securitycenter_service.ListAssetsRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.list_assets,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=480.0,
            ),
            default_timeout=480.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__aiter__` convenience method.
        response = pagers.ListAssetsAsyncPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    async def list_findings(
        self,
        request: Union[securitycenter_service.ListFindingsRequest, dict] = None,
        *,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListFindingsAsyncPager:
        r"""Lists an organization or source's findings.

        To list across all sources provide a ``-`` as the source id.
        Example: /v1/organizations/{organization_id}/sources/-/findings


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_list_findings():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.ListFindingsRequest(
                    parent="parent_value",
                )

                # Make the request
                page_result = client.list_findings(request=request)

                # Handle the response
                for response in page_result:
                    print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.ListFindingsRequest, dict]):
                The request object. Request message for listing
                findings.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.services.security_center.pagers.ListFindingsAsyncPager:
                Response message for listing
                findings.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        request = securitycenter_service.ListFindingsRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.list_findings,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=480.0,
            ),
            default_timeout=480.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__aiter__` convenience method.
        response = pagers.ListFindingsAsyncPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    async def list_mute_configs(
        self,
        request: Union[securitycenter_service.ListMuteConfigsRequest, dict] = None,
        *,
        parent: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListMuteConfigsAsyncPager:
        r"""Lists mute configs.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_list_mute_configs():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.ListMuteConfigsRequest(
                    parent="parent_value",
                )

                # Make the request
                page_result = client.list_mute_configs(request=request)

                # Handle the response
                for response in page_result:
                    print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.ListMuteConfigsRequest, dict]):
                The request object. Request message for listing  mute
                configs at a given scope e.g. organization, folder or
                project.
            parent (:class:`str`):
                Required. The parent, which owns the collection of mute
                configs. Its format is
                "organizations/[organization_id]",
                "folders/[folder_id]", "projects/[project_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.services.security_center.pagers.ListMuteConfigsAsyncPager:
                Response message for listing mute
                configs.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.ListMuteConfigsRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.list_mute_configs,
            default_timeout=None,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__aiter__` convenience method.
        response = pagers.ListMuteConfigsAsyncPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    async def list_notification_configs(
        self,
        request: Union[
            securitycenter_service.ListNotificationConfigsRequest, dict
        ] = None,
        *,
        parent: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListNotificationConfigsAsyncPager:
        r"""Lists notification configs.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_list_notification_configs():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.ListNotificationConfigsRequest(
                    parent="parent_value",
                )

                # Make the request
                page_result = client.list_notification_configs(request=request)

                # Handle the response
                for response in page_result:
                    print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.ListNotificationConfigsRequest, dict]):
                The request object. Request message for listing
                notification configs.
            parent (:class:`str`):
                Required. Name of the organization to list notification
                configs. Its format is
                "organizations/[organization_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.services.security_center.pagers.ListNotificationConfigsAsyncPager:
                Response message for listing
                notification configs.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.ListNotificationConfigsRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.list_notification_configs,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=60.0,
            ),
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__aiter__` convenience method.
        response = pagers.ListNotificationConfigsAsyncPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    async def list_sources(
        self,
        request: Union[securitycenter_service.ListSourcesRequest, dict] = None,
        *,
        parent: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListSourcesAsyncPager:
        r"""Lists all sources belonging to an organization.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_list_sources():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.ListSourcesRequest(
                    parent="parent_value",
                )

                # Make the request
                page_result = client.list_sources(request=request)

                # Handle the response
                for response in page_result:
                    print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.ListSourcesRequest, dict]):
                The request object. Request message for listing sources.
            parent (:class:`str`):
                Required. Resource name of the parent of sources to
                list. Its format should be
                "organizations/[organization_id], folders/[folder_id],
                or projects/[project_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.services.security_center.pagers.ListSourcesAsyncPager:
                Response message for listing sources.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.ListSourcesRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.list_sources,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=60.0,
            ),
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__aiter__` convenience method.
        response = pagers.ListSourcesAsyncPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    async def run_asset_discovery(
        self,
        request: Union[securitycenter_service.RunAssetDiscoveryRequest, dict] = None,
        *,
        parent: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> operation_async.AsyncOperation:
        r"""Runs asset discovery. The discovery is tracked with a
        long-running operation.

        This API can only be called with limited frequency for an
        organization. If it is called too frequently the caller will
        receive a TOO_MANY_REQUESTS error.


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_run_asset_discovery():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.RunAssetDiscoveryRequest(
                    parent="parent_value",
                )

                # Make the request
                operation = client.run_asset_discovery(request=request)

                print("Waiting for operation to complete...")

                response = operation.result()

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.RunAssetDiscoveryRequest, dict]):
                The request object. Request message for running asset
                discovery for an organization.
            parent (:class:`str`):
                Required. Name of the organization to run asset
                discovery for. Its format is
                "organizations/[organization_id]".

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.api_core.operation_async.AsyncOperation:
                An object representing a long-running operation.

                The result type for the operation will be
                :class:`google.cloud.securitycenter_v1.types.RunAssetDiscoveryResponse`
                Response of asset discovery run

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.RunAssetDiscoveryRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if parent is not None:
            request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.run_asset_discovery,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Wrap the response in an operation future.
        response = operation_async.from_gapic(
            response,
            self._client._transport.operations_client,
            run_asset_discovery_response.RunAssetDiscoveryResponse,
            metadata_type=empty_pb2.Empty,
        )

        # Done; return the response.
        return response

    async def set_finding_state(
        self,
        request: Union[securitycenter_service.SetFindingStateRequest, dict] = None,
        *,
        name: str = None,
        state: finding.Finding.State = None,
        start_time: timestamp_pb2.Timestamp = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> finding.Finding:
        r"""Updates the state of a finding.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_set_finding_state():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.SetFindingStateRequest(
                    name="name_value",
                    state="INACTIVE",
                )

                # Make the request
                response = client.set_finding_state(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.SetFindingStateRequest, dict]):
                The request object. Request message for updating a
                finding's state.
            name (:class:`str`):
                Required. The relative resource name of the finding.
                See:
                https://cloud.google.com/apis/design/resource_names#relative_resource_name
                Example:
                "organizations/{organization_id}/sources/{source_id}/finding/{finding_id}".

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            state (:class:`google.cloud.securitycenter_v1.types.Finding.State`):
                Required. The desired State of the
                finding.

                This corresponds to the ``state`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            start_time (:class:`google.protobuf.timestamp_pb2.Timestamp`):
                Required. The time at which the
                updated state takes effect.

                This corresponds to the ``start_time`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.Finding:
                Security Command Center finding.
                A finding is a record of assessment data
                like security, risk, health, or privacy,
                that is ingested into Security Command
                Center for presentation, notification,
                analysis, policy testing, and
                enforcement. For example, a cross-site
                scripting (XSS) vulnerability in an App
                Engine application is a finding.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name, state, start_time])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.SetFindingStateRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if name is not None:
            request.name = name
        if state is not None:
            request.state = state
        if start_time is not None:
            request.start_time = start_time

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.set_finding_state,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def set_mute(
        self,
        request: Union[securitycenter_service.SetMuteRequest, dict] = None,
        *,
        name: str = None,
        mute: finding.Finding.Mute = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> finding.Finding:
        r"""Updates the mute state of a finding.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_set_mute():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.SetMuteRequest(
                    name="name_value",
                    mute="UNDEFINED",
                )

                # Make the request
                response = client.set_mute(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.SetMuteRequest, dict]):
                The request object. Request message for updating a
                finding's mute status.
            name (:class:`str`):
                Required. The relative resource name of the finding.
                See:
                https://cloud.google.com/apis/design/resource_names#relative_resource_name
                Example:
                "organizations/{organization_id}/sources/{source_id}/finding/{finding_id}",
                "folders/{folder_id}/sources/{source_id}/finding/{finding_id}",
                "projects/{project_id}/sources/{source_id}/finding/{finding_id}".

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            mute (:class:`google.cloud.securitycenter_v1.types.Finding.Mute`):
                Required. The desired state of the
                Mute.

                This corresponds to the ``mute`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.Finding:
                Security Command Center finding.
                A finding is a record of assessment data
                like security, risk, health, or privacy,
                that is ingested into Security Command
                Center for presentation, notification,
                analysis, policy testing, and
                enforcement. For example, a cross-site
                scripting (XSS) vulnerability in an App
                Engine application is a finding.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name, mute])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.SetMuteRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if name is not None:
            request.name = name
        if mute is not None:
            request.mute = mute

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.set_mute,
            default_timeout=None,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def set_iam_policy(
        self,
        request: Union[iam_policy_pb2.SetIamPolicyRequest, dict] = None,
        *,
        resource: str = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> policy_pb2.Policy:
        r"""Sets the access control policy on the specified
        Source.


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_set_iam_policy():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.SetIamPolicyRequest(
                    resource="resource_value",
                )

                # Make the request
                response = client.set_iam_policy(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.iam.v1.iam_policy_pb2.SetIamPolicyRequest, dict]):
                The request object. Request message for `SetIamPolicy`
                method.
            resource (:class:`str`):
                REQUIRED: The resource for which the
                policy is being specified. See the
                operation documentation for the
                appropriate value for this field.

                This corresponds to the ``resource`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.iam.v1.policy_pb2.Policy:
                Defines an Identity and Access Management (IAM) policy. It is used to
                   specify access control policies for Cloud Platform
                   resources.

                   A Policy is a collection of bindings. A binding binds
                   one or more members to a single role. Members can be
                   user accounts, service accounts, Google groups, and
                   domains (such as G Suite). A role is a named list of
                   permissions (defined by IAM or configured by users).
                   A binding can optionally specify a condition, which
                   is a logic expression that further constrains the
                   role binding based on attributes about the request
                   and/or target resource.

                   **JSON Example**

                      {
                         "bindings": [
                            {
                               "role":
                               "roles/resourcemanager.organizationAdmin",
                               "members": [ "user:mike@example.com",
                               "group:admins@example.com",
                               "domain:google.com",
                               "serviceAccount:my-project-id@appspot.gserviceaccount.com"
                               ]

                            }, { "role":
                            "roles/resourcemanager.organizationViewer",
                            "members": ["user:eve@example.com"],
                            "condition": { "title": "expirable access",
                            "description": "Does not grant access after
                            Sep 2020", "expression": "request.time <
                            timestamp('2020-10-01T00:00:00.000Z')", } }

                         ]

                      }

                   **YAML Example**

                      bindings: - members: - user:\ mike@example.com -
                      group:\ admins@example.com - domain:google.com -
                      serviceAccount:\ my-project-id@appspot.gserviceaccount.com
                      role: roles/resourcemanager.organizationAdmin -
                      members: - user:\ eve@example.com role:
                      roles/resourcemanager.organizationViewer
                      condition: title: expirable access description:
                      Does not grant access after Sep 2020 expression:
                      request.time <
                      timestamp('2020-10-01T00:00:00.000Z')

                   For a description of IAM and its features, see the
                   [IAM developer's
                   guide](\ https://cloud.google.com/iam/docs).

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([resource])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # The request isn't a proto-plus wrapped type,
        # so it must be constructed via keyword expansion.
        if isinstance(request, dict):
            request = iam_policy_pb2.SetIamPolicyRequest(**request)
        elif not request:
            request = iam_policy_pb2.SetIamPolicyRequest(resource=resource,)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.set_iam_policy,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("resource", request.resource),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def test_iam_permissions(
        self,
        request: Union[iam_policy_pb2.TestIamPermissionsRequest, dict] = None,
        *,
        resource: str = None,
        permissions: Sequence[str] = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> iam_policy_pb2.TestIamPermissionsResponse:
        r"""Returns the permissions that a caller has on the
        specified source.


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_test_iam_permissions():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.TestIamPermissionsRequest(
                    resource="resource_value",
                    permissions=['permissions_value_1', 'permissions_value_2'],
                )

                # Make the request
                response = client.test_iam_permissions(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.iam.v1.iam_policy_pb2.TestIamPermissionsRequest, dict]):
                The request object. Request message for
                `TestIamPermissions` method.
            resource (:class:`str`):
                REQUIRED: The resource for which the
                policy detail is being requested. See
                the operation documentation for the
                appropriate value for this field.

                This corresponds to the ``resource`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            permissions (:class:`Sequence[str]`):
                The set of permissions to check for the ``resource``.
                Permissions with wildcards (such as '*' or 'storage.*')
                are not allowed. For more information see `IAM
                Overview <https://cloud.google.com/iam/docs/overview#permissions>`__.

                This corresponds to the ``permissions`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.iam.v1.iam_policy_pb2.TestIamPermissionsResponse:
                Response message for TestIamPermissions method.
        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([resource, permissions])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # The request isn't a proto-plus wrapped type,
        # so it must be constructed via keyword expansion.
        if isinstance(request, dict):
            request = iam_policy_pb2.TestIamPermissionsRequest(**request)
        elif not request:
            request = iam_policy_pb2.TestIamPermissionsRequest(
                resource=resource, permissions=permissions,
            )

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.test_iam_permissions,
            default_retry=retries.Retry(
                initial=0.1,
                maximum=60.0,
                multiplier=1.3,
                predicate=retries.if_exception_type(
                    core_exceptions.DeadlineExceeded,
                    core_exceptions.ServiceUnavailable,
                ),
                deadline=60.0,
            ),
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("resource", request.resource),)),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def update_external_system(
        self,
        request: Union[securitycenter_service.UpdateExternalSystemRequest, dict] = None,
        *,
        external_system: gcs_external_system.ExternalSystem = None,
        update_mask: field_mask_pb2.FieldMask = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_external_system.ExternalSystem:
        r"""Updates external system. This is for a given finding.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_update_external_system():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.UpdateExternalSystemRequest(
                )

                # Make the request
                response = client.update_external_system(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.UpdateExternalSystemRequest, dict]):
                The request object. Request message for updating a
                ExternalSystem resource.
            external_system (:class:`google.cloud.securitycenter_v1.types.ExternalSystem`):
                Required. The external system
                resource to update.

                This corresponds to the ``external_system`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (:class:`google.protobuf.field_mask_pb2.FieldMask`):
                The FieldMask to use when updating
                the external system resource.
                If empty all mutable fields will be
                updated.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.ExternalSystem:
                Representation of third party
                SIEM/SOAR fields within SCC.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([external_system, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.UpdateExternalSystemRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if external_system is not None:
            request.external_system = external_system
        if update_mask is not None:
            request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.update_external_system,
            default_timeout=None,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("external_system.name", request.external_system.name),)
            ),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def update_finding(
        self,
        request: Union[securitycenter_service.UpdateFindingRequest, dict] = None,
        *,
        finding: gcs_finding.Finding = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_finding.Finding:
        r"""Creates or updates a finding. The corresponding
        source must exist for a finding creation to succeed.


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_update_finding():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.UpdateFindingRequest(
                )

                # Make the request
                response = client.update_finding(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.UpdateFindingRequest, dict]):
                The request object. Request message for updating or
                creating a finding.
            finding (:class:`google.cloud.securitycenter_v1.types.Finding`):
                Required. The finding resource to update or create if it
                does not already exist. parent, security_marks, and
                update_time will be ignored.

                In the case of creation, the finding id portion of the
                name must be alphanumeric and less than or equal to 32
                characters and greater than 0 characters in length.

                This corresponds to the ``finding`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.Finding:
                Security Command Center finding.
                A finding is a record of assessment data
                like security, risk, health, or privacy,
                that is ingested into Security Command
                Center for presentation, notification,
                analysis, policy testing, and
                enforcement. For example, a cross-site
                scripting (XSS) vulnerability in an App
                Engine application is a finding.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([finding])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.UpdateFindingRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if finding is not None:
            request.finding = finding

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.update_finding,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("finding.name", request.finding.name),)
            ),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def update_mute_config(
        self,
        request: Union[securitycenter_service.UpdateMuteConfigRequest, dict] = None,
        *,
        mute_config: gcs_mute_config.MuteConfig = None,
        update_mask: field_mask_pb2.FieldMask = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_mute_config.MuteConfig:
        r"""Updates a mute config.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_update_mute_config():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                mute_config = securitycenter_v1.MuteConfig()
                mute_config.filter = "filter_value"

                request = securitycenter_v1.UpdateMuteConfigRequest(
                    mute_config=mute_config,
                )

                # Make the request
                response = client.update_mute_config(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.UpdateMuteConfigRequest, dict]):
                The request object. Request message for updating a mute
                config.
            mute_config (:class:`google.cloud.securitycenter_v1.types.MuteConfig`):
                Required. The mute config being
                updated.

                This corresponds to the ``mute_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (:class:`google.protobuf.field_mask_pb2.FieldMask`):
                The list of fields to be updated.
                If empty all mutable fields will be
                updated.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.MuteConfig:
                A mute config is a Cloud SCC resource
                that contains the configuration to mute
                create/update events of findings.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([mute_config, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.UpdateMuteConfigRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if mute_config is not None:
            request.mute_config = mute_config
        if update_mask is not None:
            request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.update_mute_config,
            default_timeout=None,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("mute_config.name", request.mute_config.name),)
            ),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def update_notification_config(
        self,
        request: Union[
            securitycenter_service.UpdateNotificationConfigRequest, dict
        ] = None,
        *,
        notification_config: gcs_notification_config.NotificationConfig = None,
        update_mask: field_mask_pb2.FieldMask = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_notification_config.NotificationConfig:
        r"""Updates a notification config. The following update fields are
        allowed: description, pubsub_topic, streaming_config.filter


        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_update_notification_config():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.UpdateNotificationConfigRequest(
                )

                # Make the request
                response = client.update_notification_config(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.UpdateNotificationConfigRequest, dict]):
                The request object. Request message for updating a
                notification config.
            notification_config (:class:`google.cloud.securitycenter_v1.types.NotificationConfig`):
                Required. The notification config to
                update.

                This corresponds to the ``notification_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (:class:`google.protobuf.field_mask_pb2.FieldMask`):
                The FieldMask to use when updating
                the notification config.
                If empty all mutable fields will be
                updated.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.NotificationConfig:
                Cloud Security Command Center (Cloud
                SCC) notification configs.
                A notification config is a Cloud SCC
                resource that contains the configuration
                to send notifications for create/update
                events of findings, assets and etc.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([notification_config, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.UpdateNotificationConfigRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if notification_config is not None:
            request.notification_config = notification_config
        if update_mask is not None:
            request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.update_notification_config,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("notification_config.name", request.notification_config.name),)
            ),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def update_organization_settings(
        self,
        request: Union[
            securitycenter_service.UpdateOrganizationSettingsRequest, dict
        ] = None,
        *,
        organization_settings: gcs_organization_settings.OrganizationSettings = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_organization_settings.OrganizationSettings:
        r"""Updates an organization's settings.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_update_organization_settings():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.UpdateOrganizationSettingsRequest(
                )

                # Make the request
                response = client.update_organization_settings(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.UpdateOrganizationSettingsRequest, dict]):
                The request object. Request message for updating an
                organization's settings.
            organization_settings (:class:`google.cloud.securitycenter_v1.types.OrganizationSettings`):
                Required. The organization settings
                resource to update.

                This corresponds to the ``organization_settings`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.OrganizationSettings:
                User specified settings that are
                attached to the Security Command Center
                organization.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([organization_settings])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.UpdateOrganizationSettingsRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if organization_settings is not None:
            request.organization_settings = organization_settings

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.update_organization_settings,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("organization_settings.name", request.organization_settings.name),)
            ),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def update_source(
        self,
        request: Union[securitycenter_service.UpdateSourceRequest, dict] = None,
        *,
        source: gcs_source.Source = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_source.Source:
        r"""Updates a source.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_update_source():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.UpdateSourceRequest(
                )

                # Make the request
                response = client.update_source(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.UpdateSourceRequest, dict]):
                The request object. Request message for updating a
                source.
            source (:class:`google.cloud.securitycenter_v1.types.Source`):
                Required. The source resource to
                update.

                This corresponds to the ``source`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.Source:
                Security Command Center finding
                source. A finding source is an entity or
                a mechanism that can produce a finding.
                A source is like a container of findings
                that come from the same scanner, logger,
                monitor, and other tools.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([source])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.UpdateSourceRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if source is not None:
            request.source = source

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.update_source,
            default_timeout=60.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("source.name", request.source.name),)
            ),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def update_security_marks(
        self,
        request: Union[securitycenter_service.UpdateSecurityMarksRequest, dict] = None,
        *,
        security_marks: gcs_security_marks.SecurityMarks = None,
        retry: OptionalRetry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_security_marks.SecurityMarks:
        r"""Updates security marks.

        .. code-block:: python

            from google.cloud import securitycenter_v1

            def sample_update_security_marks():
                # Create a client
                client = securitycenter_v1.SecurityCenterClient()

                # Initialize request argument(s)
                request = securitycenter_v1.UpdateSecurityMarksRequest(
                )

                # Make the request
                response = client.update_security_marks(request=request)

                # Handle the response
                print(response)

        Args:
            request (Union[google.cloud.securitycenter_v1.types.UpdateSecurityMarksRequest, dict]):
                The request object. Request message for updating a
                SecurityMarks resource.
            security_marks (:class:`google.cloud.securitycenter_v1.types.SecurityMarks`):
                Required. The security marks resource
                to update.

                This corresponds to the ``security_marks`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.cloud.securitycenter_v1.types.SecurityMarks:
                User specified security marks that
                are attached to the parent Security
                Command Center resource. Security marks
                are scoped within a Security Command
                Center organization -- they can be
                modified and viewed by all users who
                have proper permissions on the
                organization.

        """
        # Create or coerce a protobuf request object.
        # Quick check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([security_marks])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        request = securitycenter_service.UpdateSecurityMarksRequest(request)

        # If we have keyword arguments corresponding to fields on the
        # request, apply these.
        if security_marks is not None:
            request.security_marks = security_marks

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = gapic_v1.method_async.wrap_method(
            self._client._transport.update_security_marks,
            default_timeout=480.0,
            client_info=DEFAULT_CLIENT_INFO,
        )

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("security_marks.name", request.security_marks.name),)
            ),
        )

        # Send the request.
        response = await rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.transport.close()


try:
    DEFAULT_CLIENT_INFO = gapic_v1.client_info.ClientInfo(
        gapic_version=pkg_resources.get_distribution(
            "google-cloud-securitycenter",
        ).version,
    )
except pkg_resources.DistributionNotFound:
    DEFAULT_CLIENT_INFO = gapic_v1.client_info.ClientInfo()


__all__ = ("SecurityCenterAsyncClient",)
