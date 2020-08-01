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

from collections import OrderedDict
import os
import re
from typing import Callable, Dict, Sequence, Tuple, Type, Union
import pkg_resources

import google.api_core.client_options as ClientOptions  # type: ignore
from google.api_core import exceptions  # type: ignore
from google.api_core import gapic_v1  # type: ignore
from google.api_core import retry as retries  # type: ignore
from google.auth import credentials  # type: ignore
from google.auth.transport import mtls  # type: ignore
from google.auth.exceptions import MutualTLSChannelError  # type: ignore
from google.oauth2 import service_account  # type: ignore

from google.api_core import operation
from google.api_core import operation_async
from google.cloud.securitycenter_v1p1beta1.services.security_center import pagers
from google.cloud.securitycenter_v1p1beta1.types import finding
from google.cloud.securitycenter_v1p1beta1.types import finding as gcs_finding
from google.cloud.securitycenter_v1p1beta1.types import notification_config
from google.cloud.securitycenter_v1p1beta1.types import (
    notification_config as gcs_notification_config,
)
from google.cloud.securitycenter_v1p1beta1.types import organization_settings
from google.cloud.securitycenter_v1p1beta1.types import (
    organization_settings as gcs_organization_settings,
)
from google.cloud.securitycenter_v1p1beta1.types import run_asset_discovery_response
from google.cloud.securitycenter_v1p1beta1.types import security_marks
from google.cloud.securitycenter_v1p1beta1.types import (
    security_marks as gcs_security_marks,
)
from google.cloud.securitycenter_v1p1beta1.types import securitycenter_service
from google.cloud.securitycenter_v1p1beta1.types import source
from google.cloud.securitycenter_v1p1beta1.types import source as gcs_source
from google.iam.v1 import iam_policy_pb2 as iam_policy  # type: ignore
from google.iam.v1 import policy_pb2 as policy  # type: ignore
from google.protobuf import empty_pb2 as empty  # type: ignore
from google.protobuf import field_mask_pb2 as field_mask  # type: ignore
from google.protobuf import timestamp_pb2 as timestamp  # type: ignore

from .transports.base import SecurityCenterTransport
from .transports.grpc import SecurityCenterGrpcTransport
from .transports.grpc_asyncio import SecurityCenterGrpcAsyncIOTransport


class SecurityCenterClientMeta(type):
    """Metaclass for the SecurityCenter client.

    This provides class-level methods for building and retrieving
    support objects (e.g. transport) without polluting the client instance
    objects.
    """

    _transport_registry = (
        OrderedDict()
    )  # type: Dict[str, Type[SecurityCenterTransport]]
    _transport_registry["grpc"] = SecurityCenterGrpcTransport
    _transport_registry["grpc_asyncio"] = SecurityCenterGrpcAsyncIOTransport

    def get_transport_class(cls, label: str = None,) -> Type[SecurityCenterTransport]:
        """Return an appropriate transport class.

        Args:
            label: The name of the desired transport. If none is
                provided, then the first transport in the registry is used.

        Returns:
            The transport class to use.
        """
        # If a specific transport is requested, return that one.
        if label:
            return cls._transport_registry[label]

        # No transport is requested; return the default (that is, the first one
        # in the dictionary).
        return next(iter(cls._transport_registry.values()))


class SecurityCenterClient(metaclass=SecurityCenterClientMeta):
    """V1p1Beta1 APIs for Security Center service."""

    @staticmethod
    def _get_default_mtls_endpoint(api_endpoint):
        """Convert api endpoint to mTLS endpoint.
        Convert "*.sandbox.googleapis.com" and "*.googleapis.com" to
        "*.mtls.sandbox.googleapis.com" and "*.mtls.googleapis.com" respectively.
        Args:
            api_endpoint (Optional[str]): the api endpoint to convert.
        Returns:
            str: converted mTLS api endpoint.
        """
        if not api_endpoint:
            return api_endpoint

        mtls_endpoint_re = re.compile(
            r"(?P<name>[^.]+)(?P<mtls>\.mtls)?(?P<sandbox>\.sandbox)?(?P<googledomain>\.googleapis\.com)?"
        )

        m = mtls_endpoint_re.match(api_endpoint)
        name, mtls, sandbox, googledomain = m.groups()
        if mtls or not googledomain:
            return api_endpoint

        if sandbox:
            return api_endpoint.replace(
                "sandbox.googleapis.com", "mtls.sandbox.googleapis.com"
            )

        return api_endpoint.replace(".googleapis.com", ".mtls.googleapis.com")

    DEFAULT_ENDPOINT = "securitycenter.googleapis.com"
    DEFAULT_MTLS_ENDPOINT = _get_default_mtls_endpoint.__func__(  # type: ignore
        DEFAULT_ENDPOINT
    )

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
            {@api.name}: The constructed client.
        """
        credentials = service_account.Credentials.from_service_account_file(filename)
        kwargs["credentials"] = credentials
        return cls(*args, **kwargs)

    from_service_account_json = from_service_account_file

    @staticmethod
    def finding_path(organization: str, source: str, finding: str,) -> str:
        """Return a fully-qualified finding string."""
        return "organizations/{organization}/sources/{source}/findings/{finding}".format(
            organization=organization, source=source, finding=finding,
        )

    @staticmethod
    def parse_finding_path(path: str) -> Dict[str, str]:
        """Parse a finding path into its component segments."""
        m = re.match(
            r"^organizations/(?P<organization>.+?)/sources/(?P<source>.+?)/findings/(?P<finding>.+?)$",
            path,
        )
        return m.groupdict() if m else {}

    @staticmethod
    def notification_config_path(organization: str, notification_config: str,) -> str:
        """Return a fully-qualified notification_config string."""
        return "organizations/{organization}/notificationConfigs/{notification_config}".format(
            organization=organization, notification_config=notification_config,
        )

    @staticmethod
    def parse_notification_config_path(path: str) -> Dict[str, str]:
        """Parse a notification_config path into its component segments."""
        m = re.match(
            r"^organizations/(?P<organization>.+?)/notificationConfigs/(?P<notification_config>.+?)$",
            path,
        )
        return m.groupdict() if m else {}

    @staticmethod
    def organization_settings_path(organization: str,) -> str:
        """Return a fully-qualified organization_settings string."""
        return "organizations/{organization}/organizationSettings".format(
            organization=organization,
        )

    @staticmethod
    def parse_organization_settings_path(path: str) -> Dict[str, str]:
        """Parse a organization_settings path into its component segments."""
        m = re.match(
            r"^organizations/(?P<organization>.+?)/organizationSettings$", path
        )
        return m.groupdict() if m else {}

    @staticmethod
    def security_marks_path(organization: str, asset: str,) -> str:
        """Return a fully-qualified security_marks string."""
        return "organizations/{organization}/assets/{asset}/securityMarks".format(
            organization=organization, asset=asset,
        )

    @staticmethod
    def parse_security_marks_path(path: str) -> Dict[str, str]:
        """Parse a security_marks path into its component segments."""
        m = re.match(
            r"^organizations/(?P<organization>.+?)/assets/(?P<asset>.+?)/securityMarks$",
            path,
        )
        return m.groupdict() if m else {}

    @staticmethod
    def source_path(organization: str, source: str,) -> str:
        """Return a fully-qualified source string."""
        return "organizations/{organization}/sources/{source}".format(
            organization=organization, source=source,
        )

    @staticmethod
    def parse_source_path(path: str) -> Dict[str, str]:
        """Parse a source path into its component segments."""
        m = re.match(
            r"^organizations/(?P<organization>.+?)/sources/(?P<source>.+?)$", path
        )
        return m.groupdict() if m else {}

    def __init__(
        self,
        *,
        credentials: credentials.Credentials = None,
        transport: Union[str, SecurityCenterTransport] = None,
        client_options: ClientOptions = None,
    ) -> None:
        """Instantiate the security center client.

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
                default endpoint provided by the client. GOOGLE_API_USE_MTLS
                environment variable can also be used to override the endpoint:
                "always" (always use the default mTLS endpoint), "never" (always
                use the default regular endpoint, this is the default value for
                the environment variable) and "auto" (auto switch to the default
                mTLS endpoint if client SSL credentials is present). However,
                the ``api_endpoint`` property takes precedence if provided.
                (2) The ``client_cert_source`` property is used to provide client
                SSL credentials for mutual TLS transport. If not provided, the
                default SSL credentials will be used if present.

        Raises:
            google.auth.exceptions.MutualTLSChannelError: If mutual TLS transport
                creation failed for any reason.
        """
        if isinstance(client_options, dict):
            client_options = ClientOptions.from_dict(client_options)
        if client_options is None:
            client_options = ClientOptions.ClientOptions()

        if client_options.api_endpoint is None:
            use_mtls_env = os.getenv("GOOGLE_API_USE_MTLS", "never")
            if use_mtls_env == "never":
                client_options.api_endpoint = self.DEFAULT_ENDPOINT
            elif use_mtls_env == "always":
                client_options.api_endpoint = self.DEFAULT_MTLS_ENDPOINT
            elif use_mtls_env == "auto":
                has_client_cert_source = (
                    client_options.client_cert_source is not None
                    or mtls.has_default_client_cert_source()
                )
                client_options.api_endpoint = (
                    self.DEFAULT_MTLS_ENDPOINT
                    if has_client_cert_source
                    else self.DEFAULT_ENDPOINT
                )
            else:
                raise MutualTLSChannelError(
                    "Unsupported GOOGLE_API_USE_MTLS value. Accepted values: never, auto, always"
                )

        # Save or instantiate the transport.
        # Ordinarily, we provide the transport, but allowing a custom transport
        # instance provides an extensibility point for unusual situations.
        if isinstance(transport, SecurityCenterTransport):
            # transport is a SecurityCenterTransport instance.
            if credentials or client_options.credentials_file:
                raise ValueError(
                    "When providing a transport instance, "
                    "provide its credentials directly."
                )
            if client_options.scopes:
                raise ValueError(
                    "When providing a transport instance, "
                    "provide its scopes directly."
                )
            self._transport = transport
        else:
            Transport = type(self).get_transport_class(transport)
            self._transport = Transport(
                credentials=credentials,
                credentials_file=client_options.credentials_file,
                host=client_options.api_endpoint,
                scopes=client_options.scopes,
                api_mtls_endpoint=client_options.api_endpoint,
                client_cert_source=client_options.client_cert_source,
                quota_project_id=client_options.quota_project_id,
            )

    def create_source(
        self,
        request: securitycenter_service.CreateSourceRequest = None,
        *,
        parent: str = None,
        source: gcs_source.Source = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_source.Source:
        r"""Creates a source.

        Args:
            request (:class:`~.securitycenter_service.CreateSourceRequest`):
                The request object. Request message for creating a
                source.
            parent (:class:`str`):
                Required. Resource name of the new source's parent. Its
                format should be "organizations/[organization_id]".
                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            source (:class:`~.gcs_source.Source`):
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
            ~.gcs_source.Source:
                Security Command Center finding
                source. A finding source is an entity or
                a mechanism that can produce a finding.
                A source is like a container of findings
                that come from the same scanner, logger,
                monitor, etc.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, source])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.CreateSourceRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.CreateSourceRequest):
            request = securitycenter_service.CreateSourceRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if parent is not None:
                request.parent = parent
            if source is not None:
                request.source = source

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.create_source]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def create_finding(
        self,
        request: securitycenter_service.CreateFindingRequest = None,
        *,
        parent: str = None,
        finding_id: str = None,
        finding: gcs_finding.Finding = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_finding.Finding:
        r"""Creates a finding. The corresponding source must
        exist for finding creation to succeed.

        Args:
            request (:class:`~.securitycenter_service.CreateFindingRequest`):
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
            finding (:class:`~.gcs_finding.Finding`):
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
            ~.gcs_finding.Finding:
                Security Command Center finding.
                A finding is a record of assessment data
                (security, risk, health or privacy)
                ingested into Security Command Center
                for presentation, notification,
                analysis, policy testing, and
                enforcement. For example, an XSS
                vulnerability in an App Engine
                application is a finding.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, finding_id, finding])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.CreateFindingRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.CreateFindingRequest):
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
        rpc = self._transport._wrapped_methods[self._transport.create_finding]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def create_notification_config(
        self,
        request: securitycenter_service.CreateNotificationConfigRequest = None,
        *,
        parent: str = None,
        config_id: str = None,
        notification_config: gcs_notification_config.NotificationConfig = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_notification_config.NotificationConfig:
        r"""Creates a notification config.

        Args:
            request (:class:`~.securitycenter_service.CreateNotificationConfigRequest`):
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
            notification_config (:class:`~.gcs_notification_config.NotificationConfig`):
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
            ~.gcs_notification_config.NotificationConfig:
                Security Command Center notification
                configs.
                A notification config is a Security
                Command Center resource that contains
                the configuration to send notifications
                for create/update events of findings,
                assets and etc.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, config_id, notification_config])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.CreateNotificationConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(
            request, securitycenter_service.CreateNotificationConfigRequest
        ):
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
        rpc = self._transport._wrapped_methods[
            self._transport.create_notification_config
        ]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def delete_notification_config(
        self,
        request: securitycenter_service.DeleteNotificationConfigRequest = None,
        *,
        name: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> None:
        r"""Deletes a notification config.

        Args:
            request (:class:`~.securitycenter_service.DeleteNotificationConfigRequest`):
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
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.DeleteNotificationConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(
            request, securitycenter_service.DeleteNotificationConfigRequest
        ):
            request = securitycenter_service.DeleteNotificationConfigRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[
            self._transport.delete_notification_config
        ]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        rpc(
            request, retry=retry, timeout=timeout, metadata=metadata,
        )

    def get_iam_policy(
        self,
        request: iam_policy.GetIamPolicyRequest = None,
        *,
        resource: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> policy.Policy:
        r"""Gets the access control policy on the specified
        Source.

        Args:
            request (:class:`~.iam_policy.GetIamPolicyRequest`):
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
            ~.policy.Policy:
                Defines an Identity and Access Management (IAM) policy.
                It is used to specify access control policies for Cloud
                Platform resources.

                A ``Policy`` is a collection of ``bindings``. A
                ``binding`` binds one or more ``members`` to a single
                ``role``. Members can be user accounts, service
                accounts, Google groups, and domains (such as G Suite).
                A ``role`` is a named list of permissions (defined by
                IAM or configured by users). A ``binding`` can
                optionally specify a ``condition``, which is a logic
                expression that further constrains the role binding
                based on attributes about the request and/or target
                resource.

                **JSON Example**

                ::

                    {
                      "bindings": [
                        {
                          "role": "roles/resourcemanager.organizationAdmin",
                          "members": [
                            "user:mike@example.com",
                            "group:admins@example.com",
                            "domain:google.com",
                            "serviceAccount:my-project-id@appspot.gserviceaccount.com"
                          ]
                        },
                        {
                          "role": "roles/resourcemanager.organizationViewer",
                          "members": ["user:eve@example.com"],
                          "condition": {
                            "title": "expirable access",
                            "description": "Does not grant access after Sep 2020",
                            "expression": "request.time <
                            timestamp('2020-10-01T00:00:00.000Z')",
                          }
                        }
                      ]
                    }

                **YAML Example**

                ::

                    bindings:
                    - members:
                      - user:mike@example.com
                      - group:admins@example.com
                      - domain:google.com
                      - serviceAccount:my-project-id@appspot.gserviceaccount.com
                      role: roles/resourcemanager.organizationAdmin
                    - members:
                      - user:eve@example.com
                      role: roles/resourcemanager.organizationViewer
                      condition:
                        title: expirable access
                        description: Does not grant access after Sep 2020
                        expression: request.time < timestamp('2020-10-01T00:00:00.000Z')

                For a description of IAM and its features, see the `IAM
                developer's
                guide <https://cloud.google.com/iam/docs>`__.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
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
            request = iam_policy.GetIamPolicyRequest(**request)

        elif not request:
            request = iam_policy.GetIamPolicyRequest()

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if resource is not None:
                request.resource = resource

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_iam_policy]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("resource", request.resource),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def get_notification_config(
        self,
        request: securitycenter_service.GetNotificationConfigRequest = None,
        *,
        name: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> notification_config.NotificationConfig:
        r"""Gets a notification config.

        Args:
            request (:class:`~.securitycenter_service.GetNotificationConfigRequest`):
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
            ~.notification_config.NotificationConfig:
                Security Command Center notification
                configs.
                A notification config is a Security
                Command Center resource that contains
                the configuration to send notifications
                for create/update events of findings,
                assets and etc.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.GetNotificationConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.GetNotificationConfigRequest):
            request = securitycenter_service.GetNotificationConfigRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_notification_config]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def get_organization_settings(
        self,
        request: securitycenter_service.GetOrganizationSettingsRequest = None,
        *,
        name: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> organization_settings.OrganizationSettings:
        r"""Gets the settings for an organization.

        Args:
            request (:class:`~.securitycenter_service.GetOrganizationSettingsRequest`):
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
            ~.organization_settings.OrganizationSettings:
                User specified settings that are
                attached to the Security Command Center
                organization.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.GetOrganizationSettingsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(
            request, securitycenter_service.GetOrganizationSettingsRequest
        ):
            request = securitycenter_service.GetOrganizationSettingsRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[
            self._transport.get_organization_settings
        ]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def get_source(
        self,
        request: securitycenter_service.GetSourceRequest = None,
        *,
        name: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> source.Source:
        r"""Gets a source.

        Args:
            request (:class:`~.securitycenter_service.GetSourceRequest`):
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
            ~.source.Source:
                Security Command Center finding
                source. A finding source is an entity or
                a mechanism that can produce a finding.
                A source is like a container of findings
                that come from the same scanner, logger,
                monitor, etc.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.GetSourceRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.GetSourceRequest):
            request = securitycenter_service.GetSourceRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_source]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def group_assets(
        self,
        request: securitycenter_service.GroupAssetsRequest = None,
        *,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.GroupAssetsPager:
        r"""Filters an organization's assets and  groups them by
        their specified properties.

        Args:
            request (:class:`~.securitycenter_service.GroupAssetsRequest`):
                The request object. Request message for grouping by
                assets.

            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.pagers.GroupAssetsPager:
                Response message for grouping by
                assets.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.GroupAssetsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.GroupAssetsRequest):
            request = securitycenter_service.GroupAssetsRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.group_assets]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__iter__` convenience method.
        response = pagers.GroupAssetsPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    def group_findings(
        self,
        request: securitycenter_service.GroupFindingsRequest = None,
        *,
        parent: str = None,
        group_by: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.GroupFindingsPager:
        r"""Filters an organization or source's findings and groups them by
        their specified properties.

        To group across all sources provide a ``-`` as the source id.
        Example:
        /v1p1beta1/organizations/{organization_id}/sources/-/findings

        Args:
            request (:class:`~.securitycenter_service.GroupFindingsRequest`):
                The request object. Request message for grouping by
                findings.
            parent (:class:`str`):
                Required. Name of the source to groupBy. Its format is
                "organizations/[organization_id]/sources/[source_id]".
                To groupBy across all sources provide a source_id of
                ``-``. For example:
                organizations/{organization_id}/sources/-
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
            ~.pagers.GroupFindingsPager:
                Response message for group by
                findings.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, group_by])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.GroupFindingsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.GroupFindingsRequest):
            request = securitycenter_service.GroupFindingsRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if parent is not None:
                request.parent = parent
            if group_by is not None:
                request.group_by = group_by

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.group_findings]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__iter__` convenience method.
        response = pagers.GroupFindingsPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    def list_assets(
        self,
        request: securitycenter_service.ListAssetsRequest = None,
        *,
        parent: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListAssetsPager:
        r"""Lists an organization's assets.

        Args:
            request (:class:`~.securitycenter_service.ListAssetsRequest`):
                The request object. Request message for listing assets.
            parent (:class:`str`):
                Required. Name of the organization assets should belong
                to. Its format is "organizations/[organization_id]".
                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.

            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.pagers.ListAssetsPager:
                Response message for listing assets.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.ListAssetsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.ListAssetsRequest):
            request = securitycenter_service.ListAssetsRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.list_assets]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__iter__` convenience method.
        response = pagers.ListAssetsPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    def list_findings(
        self,
        request: securitycenter_service.ListFindingsRequest = None,
        *,
        parent: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListFindingsPager:
        r"""Lists an organization or source's findings.

        To list across all sources provide a ``-`` as the source id.
        Example:
        /v1p1beta1/organizations/{organization_id}/sources/-/findings

        Args:
            request (:class:`~.securitycenter_service.ListFindingsRequest`):
                The request object. Request message for listing
                findings.
            parent (:class:`str`):
                Required. Name of the source the findings belong to. Its
                format is
                "organizations/[organization_id]/sources/[source_id]".
                To list across all sources provide a source_id of ``-``.
                For example: organizations/{organization_id}/sources/-
                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.

            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.pagers.ListFindingsPager:
                Response message for listing
                findings.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.ListFindingsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.ListFindingsRequest):
            request = securitycenter_service.ListFindingsRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.list_findings]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__iter__` convenience method.
        response = pagers.ListFindingsPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    def list_notification_configs(
        self,
        request: securitycenter_service.ListNotificationConfigsRequest = None,
        *,
        parent: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListNotificationConfigsPager:
        r"""Lists notification configs.

        Args:
            request (:class:`~.securitycenter_service.ListNotificationConfigsRequest`):
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
            ~.pagers.ListNotificationConfigsPager:
                Response message for listing
                notification configs.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.ListNotificationConfigsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(
            request, securitycenter_service.ListNotificationConfigsRequest
        ):
            request = securitycenter_service.ListNotificationConfigsRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[
            self._transport.list_notification_configs
        ]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__iter__` convenience method.
        response = pagers.ListNotificationConfigsPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    def list_sources(
        self,
        request: securitycenter_service.ListSourcesRequest = None,
        *,
        parent: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> pagers.ListSourcesPager:
        r"""Lists all sources belonging to an organization.

        Args:
            request (:class:`~.securitycenter_service.ListSourcesRequest`):
                The request object. Request message for listing sources.
            parent (:class:`str`):
                Required. Resource name of the parent of sources to
                list. Its format should be
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
            ~.pagers.ListSourcesPager:
                Response message for listing sources.
                Iterating over this object will yield
                results and resolve additional pages
                automatically.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.ListSourcesRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.ListSourcesRequest):
            request = securitycenter_service.ListSourcesRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.list_sources]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # This method is paged; wrap the response in a pager, which provides
        # an `__iter__` convenience method.
        response = pagers.ListSourcesPager(
            method=rpc, request=request, response=response, metadata=metadata,
        )

        # Done; return the response.
        return response

    def run_asset_discovery(
        self,
        request: securitycenter_service.RunAssetDiscoveryRequest = None,
        *,
        parent: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> operation.Operation:
        r"""Runs asset discovery. The discovery is tracked with a
        long-running operation.

        This API can only be called with limited frequency for an
        organization. If it is called too frequently the caller will
        receive a TOO_MANY_REQUESTS error.

        Args:
            request (:class:`~.securitycenter_service.RunAssetDiscoveryRequest`):
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
            ~.operation.Operation:
                An object representing a long-running operation.

                The result type for the operation will be
                :class:``~.run_asset_discovery_response.RunAssetDiscoveryResponse``:
                Response of asset discovery run

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.RunAssetDiscoveryRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.RunAssetDiscoveryRequest):
            request = securitycenter_service.RunAssetDiscoveryRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.run_asset_discovery]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", request.parent),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Wrap the response in an operation future.
        response = operation.from_gapic(
            response,
            self._transport.operations_client,
            run_asset_discovery_response.RunAssetDiscoveryResponse,
            metadata_type=empty.Empty,
        )

        # Done; return the response.
        return response

    def set_finding_state(
        self,
        request: securitycenter_service.SetFindingStateRequest = None,
        *,
        name: str = None,
        state: finding.Finding.State = None,
        start_time: timestamp.Timestamp = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> finding.Finding:
        r"""Updates the state of a finding.

        Args:
            request (:class:`~.securitycenter_service.SetFindingStateRequest`):
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
            state (:class:`~.finding.Finding.State`):
                Required. The desired State of the
                finding.
                This corresponds to the ``state`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            start_time (:class:`~.timestamp.Timestamp`):
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
            ~.finding.Finding:
                Security Command Center finding.
                A finding is a record of assessment data
                (security, risk, health or privacy)
                ingested into Security Command Center
                for presentation, notification,
                analysis, policy testing, and
                enforcement. For example, an XSS
                vulnerability in an App Engine
                application is a finding.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name, state, start_time])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.SetFindingStateRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.SetFindingStateRequest):
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
        rpc = self._transport._wrapped_methods[self._transport.set_finding_state]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("name", request.name),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def set_iam_policy(
        self,
        request: iam_policy.SetIamPolicyRequest = None,
        *,
        resource: str = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> policy.Policy:
        r"""Sets the access control policy on the specified
        Source.

        Args:
            request (:class:`~.iam_policy.SetIamPolicyRequest`):
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
            ~.policy.Policy:
                Defines an Identity and Access Management (IAM) policy.
                It is used to specify access control policies for Cloud
                Platform resources.

                A ``Policy`` is a collection of ``bindings``. A
                ``binding`` binds one or more ``members`` to a single
                ``role``. Members can be user accounts, service
                accounts, Google groups, and domains (such as G Suite).
                A ``role`` is a named list of permissions (defined by
                IAM or configured by users). A ``binding`` can
                optionally specify a ``condition``, which is a logic
                expression that further constrains the role binding
                based on attributes about the request and/or target
                resource.

                **JSON Example**

                ::

                    {
                      "bindings": [
                        {
                          "role": "roles/resourcemanager.organizationAdmin",
                          "members": [
                            "user:mike@example.com",
                            "group:admins@example.com",
                            "domain:google.com",
                            "serviceAccount:my-project-id@appspot.gserviceaccount.com"
                          ]
                        },
                        {
                          "role": "roles/resourcemanager.organizationViewer",
                          "members": ["user:eve@example.com"],
                          "condition": {
                            "title": "expirable access",
                            "description": "Does not grant access after Sep 2020",
                            "expression": "request.time <
                            timestamp('2020-10-01T00:00:00.000Z')",
                          }
                        }
                      ]
                    }

                **YAML Example**

                ::

                    bindings:
                    - members:
                      - user:mike@example.com
                      - group:admins@example.com
                      - domain:google.com
                      - serviceAccount:my-project-id@appspot.gserviceaccount.com
                      role: roles/resourcemanager.organizationAdmin
                    - members:
                      - user:eve@example.com
                      role: roles/resourcemanager.organizationViewer
                      condition:
                        title: expirable access
                        description: Does not grant access after Sep 2020
                        expression: request.time < timestamp('2020-10-01T00:00:00.000Z')

                For a description of IAM and its features, see the `IAM
                developer's
                guide <https://cloud.google.com/iam/docs>`__.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
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
            request = iam_policy.SetIamPolicyRequest(**request)

        elif not request:
            request = iam_policy.SetIamPolicyRequest()

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if resource is not None:
                request.resource = resource

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.set_iam_policy]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("resource", request.resource),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def test_iam_permissions(
        self,
        request: iam_policy.TestIamPermissionsRequest = None,
        *,
        resource: str = None,
        permissions: Sequence[str] = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> iam_policy.TestIamPermissionsResponse:
        r"""Returns the permissions that a caller has on the
        specified source.

        Args:
            request (:class:`~.iam_policy.TestIamPermissionsRequest`):
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
            ~.iam_policy.TestIamPermissionsResponse:
                Response message for ``TestIamPermissions`` method.
        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
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
            request = iam_policy.TestIamPermissionsRequest(**request)

        elif not request:
            request = iam_policy.TestIamPermissionsRequest()

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if resource is not None:
                request.resource = resource

            if permissions:
                request.permissions.extend(permissions)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.test_iam_permissions]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("resource", request.resource),)),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def update_finding(
        self,
        request: securitycenter_service.UpdateFindingRequest = None,
        *,
        finding: gcs_finding.Finding = None,
        update_mask: field_mask.FieldMask = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_finding.Finding:
        r"""Creates or updates a finding. The corresponding
        source must exist for a finding creation to succeed.

        Args:
            request (:class:`~.securitycenter_service.UpdateFindingRequest`):
                The request object. Request message for updating or
                creating a finding.
            finding (:class:`~.gcs_finding.Finding`):
                Required. The finding resource to update or create if it
                does not already exist. parent, security_marks, and
                update_time will be ignored.

                In the case of creation, the finding id portion of the
                name must be alphanumeric and less than or equal to 32
                characters and greater than 0 characters in length.
                This corresponds to the ``finding`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (:class:`~.field_mask.FieldMask`):
                The FieldMask to use when updating the finding resource.
                This field should not be specified when creating a
                finding.

                When updating a finding, an empty mask is treated as
                updating all mutable fields and replacing
                source_properties. Individual source_properties can be
                added/updated by using "source_properties." in the field
                mask.
                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.

            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.gcs_finding.Finding:
                Security Command Center finding.
                A finding is a record of assessment data
                (security, risk, health or privacy)
                ingested into Security Command Center
                for presentation, notification,
                analysis, policy testing, and
                enforcement. For example, an XSS
                vulnerability in an App Engine
                application is a finding.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([finding, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.UpdateFindingRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.UpdateFindingRequest):
            request = securitycenter_service.UpdateFindingRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if finding is not None:
                request.finding = finding
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_finding]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("finding.name", request.finding.name),)
            ),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def update_notification_config(
        self,
        request: securitycenter_service.UpdateNotificationConfigRequest = None,
        *,
        notification_config: gcs_notification_config.NotificationConfig = None,
        update_mask: field_mask.FieldMask = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_notification_config.NotificationConfig:
        r"""Updates a notification config. The following update fields are
        allowed: description, pubsub_topic, streaming_config.filter

        Args:
            request (:class:`~.securitycenter_service.UpdateNotificationConfigRequest`):
                The request object. Request message for updating a
                notification config.
            notification_config (:class:`~.gcs_notification_config.NotificationConfig`):
                Required. The notification config to
                update.
                This corresponds to the ``notification_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (:class:`~.field_mask.FieldMask`):
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
            ~.gcs_notification_config.NotificationConfig:
                Security Command Center notification
                configs.
                A notification config is a Security
                Command Center resource that contains
                the configuration to send notifications
                for create/update events of findings,
                assets and etc.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([notification_config, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.UpdateNotificationConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(
            request, securitycenter_service.UpdateNotificationConfigRequest
        ):
            request = securitycenter_service.UpdateNotificationConfigRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if notification_config is not None:
                request.notification_config = notification_config
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[
            self._transport.update_notification_config
        ]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("notification_config.name", request.notification_config.name),)
            ),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def update_organization_settings(
        self,
        request: securitycenter_service.UpdateOrganizationSettingsRequest = None,
        *,
        organization_settings: gcs_organization_settings.OrganizationSettings = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_organization_settings.OrganizationSettings:
        r"""Updates an organization's settings.

        Args:
            request (:class:`~.securitycenter_service.UpdateOrganizationSettingsRequest`):
                The request object. Request message for updating an
                organization's settings.
            organization_settings (:class:`~.gcs_organization_settings.OrganizationSettings`):
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
            ~.gcs_organization_settings.OrganizationSettings:
                User specified settings that are
                attached to the Security Command Center
                organization.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([organization_settings])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.UpdateOrganizationSettingsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(
            request, securitycenter_service.UpdateOrganizationSettingsRequest
        ):
            request = securitycenter_service.UpdateOrganizationSettingsRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if organization_settings is not None:
                request.organization_settings = organization_settings

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[
            self._transport.update_organization_settings
        ]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("organization_settings.name", request.organization_settings.name),)
            ),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def update_source(
        self,
        request: securitycenter_service.UpdateSourceRequest = None,
        *,
        source: gcs_source.Source = None,
        update_mask: field_mask.FieldMask = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_source.Source:
        r"""Updates a source.

        Args:
            request (:class:`~.securitycenter_service.UpdateSourceRequest`):
                The request object. Request message for updating a
                source.
            source (:class:`~.gcs_source.Source`):
                Required. The source resource to
                update.
                This corresponds to the ``source`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (:class:`~.field_mask.FieldMask`):
                The FieldMask to use when updating
                the source resource.
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
            ~.gcs_source.Source:
                Security Command Center finding
                source. A finding source is an entity or
                a mechanism that can produce a finding.
                A source is like a container of findings
                that come from the same scanner, logger,
                monitor, etc.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([source, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.UpdateSourceRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.UpdateSourceRequest):
            request = securitycenter_service.UpdateSourceRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if source is not None:
                request.source = source
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_source]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("source.name", request.source.name),)
            ),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response

    def update_security_marks(
        self,
        request: securitycenter_service.UpdateSecurityMarksRequest = None,
        *,
        security_marks: gcs_security_marks.SecurityMarks = None,
        update_mask: field_mask.FieldMask = None,
        retry: retries.Retry = gapic_v1.method.DEFAULT,
        timeout: float = None,
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> gcs_security_marks.SecurityMarks:
        r"""Updates security marks.

        Args:
            request (:class:`~.securitycenter_service.UpdateSecurityMarksRequest`):
                The request object. Request message for updating a
                SecurityMarks resource.
            security_marks (:class:`~.gcs_security_marks.SecurityMarks`):
                Required. The security marks resource
                to update.
                This corresponds to the ``security_marks`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (:class:`~.field_mask.FieldMask`):
                The FieldMask to use when updating the security marks
                resource.

                The field mask must not contain duplicate fields. If
                empty or set to "marks", all marks will be replaced.
                Individual marks can be updated using
                "marks.<mark_key>".
                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.

            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.gcs_security_marks.SecurityMarks:
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
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([security_marks, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError(
                "If the `request` argument is set, then none of "
                "the individual field arguments should be set."
            )

        # Minor optimization to avoid making a copy if the user passes
        # in a securitycenter_service.UpdateSecurityMarksRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, securitycenter_service.UpdateSecurityMarksRequest):
            request = securitycenter_service.UpdateSecurityMarksRequest(request)

            # If we have keyword arguments corresponding to fields on the
            # request, apply these.

            if security_marks is not None:
                request.security_marks = security_marks
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_security_marks]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata(
                (("security_marks.name", request.security_marks.name),)
            ),
        )

        # Send the request.
        response = rpc(request, retry=retry, timeout=timeout, metadata=metadata,)

        # Done; return the response.
        return response


try:
    _client_info = gapic_v1.client_info.ClientInfo(
        gapic_version=pkg_resources.get_distribution(
            "google-cloud-securitycenter",
        ).version,
    )
except pkg_resources.DistributionNotFound:
    _client_info = gapic_v1.client_info.ClientInfo()


__all__ = ("SecurityCenterClient",)
