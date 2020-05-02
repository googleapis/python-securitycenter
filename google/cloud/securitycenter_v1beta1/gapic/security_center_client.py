# -*- coding: utf-8 -*-
#
# Copyright 2020 Google LLC
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

"""Accesses the google.cloud.securitycenter.v1beta1 SecurityCenter API."""

import functools
import pkg_resources
import warnings

from google.oauth2 import service_account
import google.api_core.client_options
import google.api_core.gapic_v1.client_info
import google.api_core.gapic_v1.config
import google.api_core.gapic_v1.method
import google.api_core.gapic_v1.routing_header
import google.api_core.grpc_helpers
import google.api_core.operation
import google.api_core.operations_v1
import google.api_core.page_iterator
import google.api_core.path_template
import grpc

from google.cloud.securitycenter_v1beta1.gapic import enums
from google.cloud.securitycenter_v1beta1.gapic import security_center_client_config
from google.cloud.securitycenter_v1beta1.gapic.transports import (
    security_center_grpc_transport,
)
from google.cloud.securitycenter_v1beta1.proto import finding_pb2
from google.cloud.securitycenter_v1beta1.proto import organization_settings_pb2
from google.cloud.securitycenter_v1beta1.proto import security_marks_pb2
from google.cloud.securitycenter_v1beta1.proto import securitycenter_service_pb2
from google.cloud.securitycenter_v1beta1.proto import securitycenter_service_pb2_grpc
from google.cloud.securitycenter_v1beta1.proto import source_pb2
from google.iam.v1 import iam_policy_pb2
from google.iam.v1 import options_pb2
from google.iam.v1 import policy_pb2
from google.longrunning import operations_pb2
from google.protobuf import duration_pb2
from google.protobuf import empty_pb2
from google.protobuf import field_mask_pb2
from google.protobuf import timestamp_pb2


_GAPIC_LIBRARY_VERSION = pkg_resources.get_distribution(
    "google-cloud-securitycenter",
).version


class SecurityCenterClient(object):
    """V1 Beta APIs for Security Center service."""

    SERVICE_ADDRESS = "securitycenter.googleapis.com:443"
    """The default address of the service."""

    # The name of the interface for this client. This is the key used to
    # find the method configuration in the client_config dictionary.
    _INTERFACE_NAME = "google.cloud.securitycenter.v1beta1.SecurityCenter"

    @classmethod
    def from_service_account_file(cls, filename, *args, **kwargs):
        """Creates an instance of this client using the provided credentials
        file.

        Args:
            filename (str): The path to the service account private key json
                file.
            args: Additional arguments to pass to the constructor.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            SecurityCenterClient: The constructed client.
        """
        credentials = service_account.Credentials.from_service_account_file(filename)
        kwargs["credentials"] = credentials
        return cls(*args, **kwargs)

    from_service_account_json = from_service_account_file

    @classmethod
    def asset_security_marks_path(cls, organization, asset):
        """Return a fully-qualified asset_security_marks string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}/assets/{asset}/securityMarks",
            organization=organization,
            asset=asset,
        )

    @classmethod
    def finding_path(cls, organization, source, finding):
        """Return a fully-qualified finding string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}/sources/{source}/findings/{finding}",
            organization=organization,
            source=source,
            finding=finding,
        )

    @classmethod
    def finding_security_marks_path(cls, organization, source, finding):
        """Return a fully-qualified finding_security_marks string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}/sources/{source}/findings/{finding}/securityMarks",
            organization=organization,
            source=source,
            finding=finding,
        )

    @classmethod
    def organization_path(cls, organization):
        """Return a fully-qualified organization string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}", organization=organization,
        )

    @classmethod
    def organization_settings_path(cls, organization):
        """Return a fully-qualified organization_settings string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}/organizationSettings",
            organization=organization,
        )

    @classmethod
    def source_path(cls, organization, source):
        """Return a fully-qualified source string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}/sources/{source}",
            organization=organization,
            source=source,
        )

    def __init__(
        self,
        transport=None,
        channel=None,
        credentials=None,
        client_config=None,
        client_info=None,
        client_options=None,
    ):
        """Constructor.

        Args:
            transport (Union[~.SecurityCenterGrpcTransport,
                    Callable[[~.Credentials, type], ~.SecurityCenterGrpcTransport]): A transport
                instance, responsible for actually making the API calls.
                The default transport uses the gRPC protocol.
                This argument may also be a callable which returns a
                transport instance. Callables will be sent the credentials
                as the first argument and the default transport class as
                the second argument.
            channel (grpc.Channel): DEPRECATED. A ``Channel`` instance
                through which to make calls. This argument is mutually exclusive
                with ``credentials``; providing both will raise an exception.
            credentials (google.auth.credentials.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
                This argument is mutually exclusive with providing a
                transport instance to ``transport``; doing so will raise
                an exception.
            client_config (dict): DEPRECATED. A dictionary of call options for
                each method. If not specified, the default configuration is used.
            client_info (google.api_core.gapic_v1.client_info.ClientInfo):
                The client info used to send a user-agent string along with
                API requests. If ``None``, then default info will be used.
                Generally, you only need to set this if you're developing
                your own client library.
            client_options (Union[dict, google.api_core.client_options.ClientOptions]):
                Client options used to set user options on the client. API Endpoint
                should be set through client_options.
        """
        # Raise deprecation warnings for things we want to go away.
        if client_config is not None:
            warnings.warn(
                "The `client_config` argument is deprecated.",
                PendingDeprecationWarning,
                stacklevel=2,
            )
        else:
            client_config = security_center_client_config.config

        if channel:
            warnings.warn(
                "The `channel` argument is deprecated; use " "`transport` instead.",
                PendingDeprecationWarning,
                stacklevel=2,
            )

        api_endpoint = self.SERVICE_ADDRESS
        if client_options:
            if type(client_options) == dict:
                client_options = google.api_core.client_options.from_dict(
                    client_options
                )
            if client_options.api_endpoint:
                api_endpoint = client_options.api_endpoint

        # Instantiate the transport.
        # The transport is responsible for handling serialization and
        # deserialization and actually sending data to the service.
        if transport:
            if callable(transport):
                self.transport = transport(
                    credentials=credentials,
                    default_class=security_center_grpc_transport.SecurityCenterGrpcTransport,
                    address=api_endpoint,
                )
            else:
                if credentials:
                    raise ValueError(
                        "Received both a transport instance and "
                        "credentials; these are mutually exclusive."
                    )
                self.transport = transport
        else:
            self.transport = security_center_grpc_transport.SecurityCenterGrpcTransport(
                address=api_endpoint, channel=channel, credentials=credentials,
            )

        if client_info is None:
            client_info = google.api_core.gapic_v1.client_info.ClientInfo(
                gapic_version=_GAPIC_LIBRARY_VERSION,
            )
        else:
            client_info.gapic_version = _GAPIC_LIBRARY_VERSION
        self._client_info = client_info

        # Parse out the default settings for retry and timeout for each RPC
        # from the client configuration.
        # (Ordinarily, these are the defaults specified in the `*_config.py`
        # file next to this one.)
        self._method_configs = google.api_core.gapic_v1.config.parse_method_configs(
            client_config["interfaces"][self._INTERFACE_NAME],
        )

        # Save a dictionary of cached API call functions.
        # These are the actual callables which invoke the proper
        # transport methods, wrapped with `wrap_method` to add retry,
        # timeout, and the like.
        self._inner_api_calls = {}

    # Service calls
    def create_source(
        self,
        parent,
        source,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Creates a source.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> parent = client.organization_path('[ORGANIZATION]')
            >>>
            >>> # TODO: Initialize `source`:
            >>> source = {}
            >>>
            >>> response = client.create_source(parent, source)

        Args:
            parent (str): Source specific properties. These properties are managed by the
                source that writes the finding. The key names in the source_properties
                map must be between 1 and 255 characters, and must start with a letter
                and contain alphanumeric characters or underscores only.
            source (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Source]): The value returned by the last ``GroupFindingsResponse``; indicates
                that this is a continuation of a prior ``GroupFindings`` call, and that
                the system should return the next page of data.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Source`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.Source` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "create_source" not in self._inner_api_calls:
            self._inner_api_calls[
                "create_source"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.create_source,
                default_retry=self._method_configs["CreateSource"].retry,
                default_timeout=self._method_configs["CreateSource"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.CreateSourceRequest(
            parent=parent, source=source,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["create_source"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def create_finding(
        self,
        parent,
        finding_id,
        finding,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Creates a finding. The corresponding source must exist for finding creation
        to succeed.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> parent = client.source_path('[ORGANIZATION]', '[SOURCE]')
            >>>
            >>> # TODO: Initialize `finding_id`:
            >>> finding_id = ''
            >>>
            >>> # TODO: Initialize `finding`:
            >>> finding = {}
            >>>
            >>> response = client.create_finding(parent, finding_id, finding)

        Args:
            parent (str): Filters an organization or source's findings and groups them by
                their specified properties.

                To group across all sources provide a ``-`` as the source id. Example:
                /v1beta1/organizations/{organization_id}/sources/-/findings
            finding_id (str): Required. Unique identifier provided by the client within the parent scope.
                It must be alphanumeric and less than or equal to 32 characters and
                greater than 0 characters in length.
            finding (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Finding]): The request message for ``Operations.ListOperations``.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Finding`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.Finding` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "create_finding" not in self._inner_api_calls:
            self._inner_api_calls[
                "create_finding"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.create_finding,
                default_retry=self._method_configs["CreateFinding"].retry,
                default_timeout=self._method_configs["CreateFinding"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.CreateFindingRequest(
            parent=parent, finding_id=finding_id, finding=finding,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["create_finding"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_iam_policy(
        self,
        resource,
        options_=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Gets the access control policy on the specified Source.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> resource = client.source_path('[ORGANIZATION]', '[SOURCE]')
            >>>
            >>> response = client.get_iam_policy(resource)

        Args:
            resource (str): REQUIRED: The resource for which the policy is being requested.
                See the operation documentation for the appropriate value for this field.
            options_ (Union[dict, ~google.cloud.securitycenter_v1beta1.types.GetPolicyOptions]): Required. Name of the organization to run asset discovery for. Its
                format is "organizations/[organization_id]".

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.GetPolicyOptions`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.Policy` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_iam_policy" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_iam_policy"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_iam_policy,
                default_retry=self._method_configs["GetIamPolicy"].retry,
                default_timeout=self._method_configs["GetIamPolicy"].timeout,
                client_info=self._client_info,
            )

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=resource, options=options_,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("resource", resource)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_iam_policy"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_organization_settings(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Gets the settings for an organization.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> name = client.organization_settings_path('[ORGANIZATION]')
            >>>
            >>> response = client.get_organization_settings(name)

        Args:
            name (str): If this SourceCodeInfo represents a complete declaration, these are
                any comments appearing before and after the declaration which appear to
                be attached to the declaration.

                A series of line comments appearing on consecutive lines, with no other
                tokens appearing on those lines, will be treated as a single comment.

                leading_detached_comments will keep paragraphs of comments that appear
                before (but not connected to) the current element. Each paragraph,
                separated by empty lines, will be one comment element in the repeated
                field.

                Only the comment content is provided; comment markers (e.g. //) are
                stripped out. For block comments, leading whitespace and an asterisk
                will be stripped from the beginning of each line other than the first.
                Newlines are included in the output.

                Examples:

                optional int32 foo = 1; // Comment attached to foo. // Comment attached
                to bar. optional int32 bar = 2;

                optional string baz = 3; // Comment attached to baz. // Another line
                attached to baz.

                // Comment attached to qux. // // Another line attached to qux. optional
                double qux = 4;

                // Detached comment for corge. This is not leading or trailing comments
                // to qux or corge because there are blank lines separating it from //
                both.

                // Detached comment for corge paragraph 2.

                optional string corge = 5; /\* Block comment attached \* to corge.
                Leading asterisks \* will be removed. */ /* Block comment attached to \*
                grault. \*/ optional int32 grault = 6;

                // ignored detached comments.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.OrganizationSettings` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_organization_settings" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_organization_settings"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_organization_settings,
                default_retry=self._method_configs["GetOrganizationSettings"].retry,
                default_timeout=self._method_configs["GetOrganizationSettings"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.GetOrganizationSettingsRequest(name=name,)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_organization_settings"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_source(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Gets a source.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> name = client.source_path('[ORGANIZATION]', '[SOURCE]')
            >>>
            >>> response = client.get_source(name)

        Args:
            name (str): Required. Resource name of the new finding's parent. Its format
                should be "organizations/[organization_id]/sources/[source_id]".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.Source` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_source" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_source"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_source,
                default_retry=self._method_configs["GetSource"].retry,
                default_timeout=self._method_configs["GetSource"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.GetSourceRequest(name=name,)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_source"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def group_assets(
        self,
        parent,
        group_by,
        filter_=None,
        compare_duration=None,
        read_time=None,
        page_size=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Filters an organization's assets and  groups them by their specified
        properties.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> parent = client.organization_path('[ORGANIZATION]')
            >>>
            >>> # TODO: Initialize `group_by`:
            >>> group_by = ''
            >>>
            >>> # Iterate over all results
            >>> for element in client.group_assets(parent, group_by):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.group_assets(parent, group_by).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): Protocol Buffers - Google's data interchange format Copyright 2008
                Google Inc. All rights reserved.
                https://developers.google.com/protocol-buffers/

                Redistribution and use in source and binary forms, with or without
                modification, are permitted provided that the following conditions are
                met:

                ::

                    * Redistributions of source code must retain the above copyright

                notice, this list of conditions and the following disclaimer. \*
                Redistributions in binary form must reproduce the above copyright
                notice, this list of conditions and the following disclaimer in the
                documentation and/or other materials provided with the distribution. \*
                Neither the name of Google Inc. nor the names of its contributors may be
                used to endorse or promote products derived from this software without
                specific prior written permission.

                THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
                IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
                TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
                PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
                OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
                EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
                PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
                PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
                LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
                NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
                SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
            group_by (str): Not ZigZag encoded. Negative numbers take 10 bytes. Use TYPE_SINT64
                if negative values are likely.
            filter_ (str): The resource has one pattern, but the API owner expects to add more
                later. (This is the inverse of ORIGINALLY_SINGLE_PATTERN, and prevents
                that from being necessary once there are multiple patterns.)
            compare_duration (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Duration]): javalite_serializable

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Duration`
            read_time (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Timestamp]): Time used as a reference point when filtering assets. The filter is limited
                to assets existing at the supplied time and their values are those at that
                specific time. Absence of this field will default to the API's version of
                NOW.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Timestamp`
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.securitycenter_v1beta1.types.GroupResult` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "group_assets" not in self._inner_api_calls:
            self._inner_api_calls[
                "group_assets"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.group_assets,
                default_retry=self._method_configs["GroupAssets"].retry,
                default_timeout=self._method_configs["GroupAssets"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.GroupAssetsRequest(
            parent=parent,
            group_by=group_by,
            filter=filter_,
            compare_duration=compare_duration,
            read_time=read_time,
            page_size=page_size,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["group_assets"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="group_by_results",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def group_findings(
        self,
        parent,
        group_by,
        filter_=None,
        read_time=None,
        page_size=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        A Timestamp represents a point in time independent of any time zone
        or local calendar, encoded as a count of seconds and fractions of
        seconds at nanosecond resolution. The count is relative to an epoch at
        UTC midnight on January 1, 1970, in the proleptic Gregorian calendar
        which extends the Gregorian calendar backwards to year one.

        All minutes are 60 seconds long. Leap seconds are "smeared" so that no
        leap second table is needed for interpretation, using a `24-hour linear
        smear <https://developers.google.com/time/smear>`__.

        The range is from 0001-01-01T00:00:00Z to
        9999-12-31T23:59:59.999999999Z. By restricting to that range, we ensure
        that we can convert to and from `RFC
        3339 <https://www.ietf.org/rfc/rfc3339.txt>`__ date strings.

        # Examples

        Example 1: Compute Timestamp from POSIX ``time()``.

        ::

            Timestamp timestamp;
            timestamp.set_seconds(time(NULL));
            timestamp.set_nanos(0);

        Example 2: Compute Timestamp from POSIX ``gettimeofday()``.

        ::

            struct timeval tv;
            gettimeofday(&tv, NULL);

            Timestamp timestamp;
            timestamp.set_seconds(tv.tv_sec);
            timestamp.set_nanos(tv.tv_usec * 1000);

        Example 3: Compute Timestamp from Win32 ``GetSystemTimeAsFileTime()``.

        ::

            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            UINT64 ticks = (((UINT64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

            // A Windows tick is 100 nanoseconds. Windows epoch 1601-01-01T00:00:00Z
            // is 11644473600 seconds before Unix epoch 1970-01-01T00:00:00Z.
            Timestamp timestamp;
            timestamp.set_seconds((INT64) ((ticks / 10000000) - 11644473600LL));
            timestamp.set_nanos((INT32) ((ticks % 10000000) * 100));

        Example 4: Compute Timestamp from Java ``System.currentTimeMillis()``.

        ::

            long millis = System.currentTimeMillis();

            Timestamp timestamp = Timestamp.newBuilder().setSeconds(millis / 1000)
                .setNanos((int) ((millis % 1000) * 1000000)).build();

        Example 5: Compute Timestamp from current time in Python.

        ::

            timestamp = Timestamp()
            timestamp.GetCurrentTime()

        # JSON Mapping

        In JSON format, the Timestamp type is encoded as a string in the `RFC
        3339 <https://www.ietf.org/rfc/rfc3339.txt>`__ format. That is, the
        format is "{year}-{month}-{day}T{hour}:{min}:{sec}[.{frac_sec}]Z" where
        {year} is always expressed using four digits while {month}, {day},
        {hour}, {min}, and {sec} are zero-padded to two digits each. The
        fractional seconds, which can go up to 9 digits (i.e. up to 1 nanosecond
        resolution), are optional. The "Z" suffix indicates the timezone
        ("UTC"); the timezone is required. A proto3 JSON serializer should
        always use UTC (as indicated by "Z") when printing the Timestamp type
        and a proto3 JSON parser should be able to accept both UTC and other
        timezones (as indicated by an offset).

        For example, "2017-01-15T01:30:15.01Z" encodes 15.01 seconds past 01:30
        UTC on January 15, 2017.

        In JavaScript, one can convert a Date object to this format using the
        standard
        `toISOString() <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/toISOString>`__
        method. In Python, a standard ``datetime.datetime`` object can be
        converted to this format using
        ```strftime`` <https://docs.python.org/2/library/time.html#time.strftime>`__
        with the time format spec '%Y-%m-%dT%H:%M:%S.%fZ'. Likewise, in Java,
        one can use the Joda Time's
        ```ISODateTimeFormat.dateTime()`` <http://www.joda.org/joda-time/apidocs/org/joda/time/format/ISODateTimeFormat.html#dateTime%2D%2D>`__
        to obtain a formatter capable of generating timestamps in this format.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> parent = client.source_path('[ORGANIZATION]', '[SOURCE]')
            >>>
            >>> # TODO: Initialize `group_by`:
            >>> group_by = ''
            >>>
            >>> # Iterate over all results
            >>> for element in client.group_findings(parent, group_by):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.group_findings(parent, group_by).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): Required. Name of the organization to groupBy. Its format is
                "organizations/[organization_id]".
            group_by (str): Optional. The relative resource name pattern associated with this
                resource type. The DNS prefix of the full resource name shouldn't be
                specified here.

                The path pattern must follow the syntax, which aligns with HTTP binding
                syntax:

                ::

                    Template = Segment { "/" Segment } ;
                    Segment = LITERAL | Variable ;
                    Variable = "{" LITERAL "}" ;

                Examples:

                ::

                    - "projects/{project}/topics/{topic}"
                    - "projects/{project}/knowledgeBases/{knowledge_base}"

                The components in braces correspond to the IDs for each resource in the
                hierarchy. It is expected that, if multiple patterns are provided, the
                same component name (e.g. "project") refers to IDs of the same type of
                resource.
            filter_ (str): Specifies the format of the policy.

                Valid values are 0, 1, and 3. Requests specifying an invalid value will
                be rejected.

                Operations affecting conditional bindings must specify version 3. This
                can be either setting a conditional policy, modifying a conditional
                binding, or removing a binding (conditional or unconditional) from the
                stored conditional policy. Operations on non-conditional policies may
                specify any valid value or leave the field unset.

                If no etag is provided in the call to ``setIamPolicy``, version
                compliance checks against the stored policy is skipped.
            read_time (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Timestamp]): Time used as a reference point when filtering findings. The filter is
                limited to findings existing at the supplied time and their values are
                those at that specific time. Absence of this field will default to the
                API's version of NOW.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Timestamp`
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.securitycenter_v1beta1.types.GroupResult` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "group_findings" not in self._inner_api_calls:
            self._inner_api_calls[
                "group_findings"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.group_findings,
                default_retry=self._method_configs["GroupFindings"].retry,
                default_timeout=self._method_configs["GroupFindings"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.GroupFindingsRequest(
            parent=parent,
            group_by=group_by,
            filter=filter_,
            read_time=read_time,
            page_size=page_size,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["group_findings"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="group_by_results",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def list_assets(
        self,
        parent,
        filter_=None,
        order_by=None,
        read_time=None,
        compare_duration=None,
        field_mask=None,
        page_size=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Lists an organization's assets.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> parent = client.organization_path('[ORGANIZATION]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_assets(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_assets(parent).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): Associates a list of ``members`` to a ``role``. Optionally may
                specify a ``condition`` that determines when binding is in effect.
                ``bindings`` with no members will result in an error.
            filter_ (str): Required. The Finding being created. The name and security_marks
                will be ignored as they are both output only fields on this resource.
            order_by (str): The response message for ``Operations.ListOperations``.
            read_time (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Timestamp]): Time used as a reference point when filtering assets. The filter is limited
                to assets existing at the supplied time and their values are those at that
                specific time. Absence of this field will default to the API's version of
                NOW.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Timestamp`
            compare_duration (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Duration]): A definition of a client library method signature.

                In client libraries, each proto RPC corresponds to one or more methods
                which the end user is able to call, and calls the underlying RPC.
                Normally, this method receives a single argument (a struct or instance
                corresponding to the RPC request object). Defining this field will add
                one or more overloads providing flattened or simpler method signatures
                in some languages.

                The fields on the method signature are provided as a comma-separated
                string.

                For example, the proto RPC and annotation:

                rpc CreateSubscription(CreateSubscriptionRequest) returns (Subscription)
                { option (google.api.method_signature) = "name,topic"; }

                Would add the following Java overload (in addition to the method
                accepting the request object):

                public final Subscription createSubscription(String name, String topic)

                The following backwards-compatibility guidelines apply:

                -  Adding this annotation to an unannotated method is backwards
                   compatible.
                -  Adding this annotation to a method which already has existing method
                   signature annotations is backwards compatible if and only if the new
                   method signature annotation is last in the sequence.
                -  Modifying or removing an existing method signature annotation is a
                   breaking change.
                -  Re-ordering existing method signature annotations is a breaking
                   change.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Duration`
            field_mask (Union[dict, ~google.cloud.securitycenter_v1beta1.types.FieldMask]): Optional. A field mask to specify the ListAssetsResult fields to be listed in the
                response.
                An empty field mask will list all fields.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.FieldMask`
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.securitycenter_v1beta1.types.ListAssetsResult` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "list_assets" not in self._inner_api_calls:
            self._inner_api_calls[
                "list_assets"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.list_assets,
                default_retry=self._method_configs["ListAssets"].retry,
                default_timeout=self._method_configs["ListAssets"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.ListAssetsRequest(
            parent=parent,
            filter=filter_,
            order_by=order_by,
            read_time=read_time,
            compare_duration=compare_duration,
            field_mask=field_mask,
            page_size=page_size,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["list_assets"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="list_assets_results",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def list_findings(
        self,
        parent,
        filter_=None,
        order_by=None,
        read_time=None,
        field_mask=None,
        page_size=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        A simple descriptor of a resource type.

        ResourceDescriptor annotates a resource message (either by means of a
        protobuf annotation or use in the service config), and associates the
        resource's schema, the resource type, and the pattern of the resource
        name.

        Example:

        ::

            message Topic {
              // Indicates this message defines a resource schema.
              // Declares the resource type in the format of {service}/{kind}.
              // For Kubernetes resources, the format is {api group}/{kind}.
              option (google.api.resource) = {
                type: "pubsub.googleapis.com/Topic"
                name_descriptor: {
                  pattern: "projects/{project}/topics/{topic}"
                  parent_type: "cloudresourcemanager.googleapis.com/Project"
                  parent_name_extractor: "projects/{project}"
                }
              };
            }

        The ResourceDescriptor Yaml config will look like:

        ::

            resources:
            - type: "pubsub.googleapis.com/Topic"
              name_descriptor:
                - pattern: "projects/{project}/topics/{topic}"
                  parent_type: "cloudresourcemanager.googleapis.com/Project"
                  parent_name_extractor: "projects/{project}"

        Sometimes, resources have multiple patterns, typically because they can
        live under multiple parents.

        Example:

        ::

            message LogEntry {
              option (google.api.resource) = {
                type: "logging.googleapis.com/LogEntry"
                name_descriptor: {
                  pattern: "projects/{project}/logs/{log}"
                  parent_type: "cloudresourcemanager.googleapis.com/Project"
                  parent_name_extractor: "projects/{project}"
                }
                name_descriptor: {
                  pattern: "folders/{folder}/logs/{log}"
                  parent_type: "cloudresourcemanager.googleapis.com/Folder"
                  parent_name_extractor: "folders/{folder}"
                }
                name_descriptor: {
                  pattern: "organizations/{organization}/logs/{log}"
                  parent_type: "cloudresourcemanager.googleapis.com/Organization"
                  parent_name_extractor: "organizations/{organization}"
                }
                name_descriptor: {
                  pattern: "billingAccounts/{billing_account}/logs/{log}"
                  parent_type: "billing.googleapis.com/BillingAccount"
                  parent_name_extractor: "billingAccounts/{billing_account}"
                }
              };
            }

        The ResourceDescriptor Yaml config will look like:

        ::

            resources:
            - type: 'logging.googleapis.com/LogEntry'
              name_descriptor:
                - pattern: "projects/{project}/logs/{log}"
                  parent_type: "cloudresourcemanager.googleapis.com/Project"
                  parent_name_extractor: "projects/{project}"
                - pattern: "folders/{folder}/logs/{log}"
                  parent_type: "cloudresourcemanager.googleapis.com/Folder"
                  parent_name_extractor: "folders/{folder}"
                - pattern: "organizations/{organization}/logs/{log}"
                  parent_type: "cloudresourcemanager.googleapis.com/Organization"
                  parent_name_extractor: "organizations/{organization}"
                - pattern: "billingAccounts/{billing_account}/logs/{log}"
                  parent_type: "billing.googleapis.com/BillingAccount"
                  parent_name_extractor: "billingAccounts/{billing_account}"

        For flexible resources, the resource name doesn't contain parent names,
        but the resource itself has parents for policy evaluation.

        Example:

        ::

            message Shelf {
              option (google.api.resource) = {
                type: "library.googleapis.com/Shelf"
                name_descriptor: {
                  pattern: "shelves/{shelf}"
                  parent_type: "cloudresourcemanager.googleapis.com/Project"
                }
                name_descriptor: {
                  pattern: "shelves/{shelf}"
                  parent_type: "cloudresourcemanager.googleapis.com/Folder"
                }
              };
            }

        The ResourceDescriptor Yaml config will look like:

        ::

            resources:
            - type: 'library.googleapis.com/Shelf'
              name_descriptor:
                - pattern: "shelves/{shelf}"
                  parent_type: "cloudresourcemanager.googleapis.com/Project"
                - pattern: "shelves/{shelf}"
                  parent_type: "cloudresourcemanager.googleapis.com/Folder"

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> parent = client.source_path('[ORGANIZATION]', '[SOURCE]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_findings(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_findings(parent).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): ``etag`` is used for optimistic concurrency control as a way to help
                prevent simultaneous updates of a policy from overwriting each other. It
                is strongly suggested that systems make use of the ``etag`` in the
                read-modify-write cycle to perform policy updates in order to avoid race
                conditions: An ``etag`` is returned in the response to ``getIamPolicy``,
                and systems are expected to put that etag in the request to
                ``setIamPolicy`` to ensure that their change will be applied to the same
                version of the policy.

                If no ``etag`` is provided in the call to ``setIamPolicy``, then the
                existing policy is overwritten. Due to blind-set semantics of an
                etag-less policy, 'setIamPolicy' will not fail even if the incoming
                policy version does not meet the requirements for modifying the stored
                policy.
            filter_ (str): Returns permissions that a caller has on the specified resource. If
                the resource does not exist, this will return an empty set of
                permissions, not a NOT_FOUND error.

                Note: This operation is designed to be used for building
                permission-aware UIs and command-line tools, not for authorization
                checking. This operation may "fail open" without warning.
            order_by (str): The jstype option determines the JavaScript type used for values of
                the field. The option is permitted only for 64 bit integral and fixed
                types (int64, uint64, sint64, fixed64, sfixed64). A field with jstype
                JS_STRING is represented as JavaScript string, which avoids loss of
                precision that can happen when a large value is converted to a floating
                point JavaScript. Specifying JS_NUMBER for the jstype causes the
                generated JavaScript code to use the JavaScript "number" type. The
                behavior of the default option JS_NORMAL is implementation dependent.

                This option is an enum to permit additional types to be added, e.g.
                goog.math.Integer.
            read_time (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Timestamp]): Time used as a reference point when filtering findings. The filter is
                limited to findings existing at the supplied time and their values are
                those at that specific time. Absence of this field will default to the
                API's version of NOW.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Timestamp`
            field_mask (Union[dict, ~google.cloud.securitycenter_v1beta1.types.FieldMask]): Optional. A field mask to specify the Finding fields to be listed in the response.
                An empty field mask will list all fields.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.FieldMask`
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.securitycenter_v1beta1.types.Finding` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "list_findings" not in self._inner_api_calls:
            self._inner_api_calls[
                "list_findings"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.list_findings,
                default_retry=self._method_configs["ListFindings"].retry,
                default_timeout=self._method_configs["ListFindings"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.ListFindingsRequest(
            parent=parent,
            filter=filter_,
            order_by=order_by,
            read_time=read_time,
            field_mask=field_mask,
            page_size=page_size,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["list_findings"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="findings",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def list_sources(
        self,
        parent,
        page_size=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Lists all sources belonging to an organization.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> parent = client.organization_path('[ORGANIZATION]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_sources(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_sources(parent).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): See ``HttpRule``.
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.securitycenter_v1beta1.types.Source` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "list_sources" not in self._inner_api_calls:
            self._inner_api_calls[
                "list_sources"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.list_sources,
                default_retry=self._method_configs["ListSources"].retry,
                default_timeout=self._method_configs["ListSources"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.ListSourcesRequest(
            parent=parent, page_size=page_size,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["list_sources"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="sources",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def run_asset_discovery(
        self,
        parent,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        The value returned by the last ``ListSourcesResponse``; indicates
        that this is a continuation of a prior ``ListSources`` call, and that
        the system should return the next page of data.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> parent = client.organization_path('[ORGANIZATION]')
            >>>
            >>> response = client.run_asset_discovery(parent)
            >>>
            >>> def callback(operation_future):
            ...     # Handle result.
            ...     result = operation_future.result()
            >>>
            >>> response.add_done_callback(callback)
            >>>
            >>> # Handle metadata.
            >>> metadata = response.metadata()

        Args:
            parent (str): Associates ``members`` with a ``role``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types._OperationFuture` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "run_asset_discovery" not in self._inner_api_calls:
            self._inner_api_calls[
                "run_asset_discovery"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.run_asset_discovery,
                default_retry=self._method_configs["RunAssetDiscovery"].retry,
                default_timeout=self._method_configs["RunAssetDiscovery"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.RunAssetDiscoveryRequest(parent=parent,)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        operation = self._inner_api_calls["run_asset_discovery"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )
        return google.api_core.operation.from_gapic(
            operation,
            self.transport._operations_client,
            empty_pb2.Empty,
            metadata_type=empty_pb2.Empty,
        )

    def set_finding_state(
        self,
        name,
        state,
        start_time,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Updates the state of a finding.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>> from google.cloud.securitycenter_v1beta1 import enums
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> name = client.finding_path('[ORGANIZATION]', '[SOURCE]', '[FINDING]')
            >>>
            >>> # TODO: Initialize `state`:
            >>> state = enums.Finding.State.STATE_UNSPECIFIED
            >>>
            >>> # TODO: Initialize `start_time`:
            >>> start_time = {}
            >>>
            >>> response = client.set_finding_state(name, state, start_time)

        Args:
            name (str): Immutable. The full resource name of the GCP resource this asset
                represents. This field is immutable after create time. See:
                https://cloud.google.com/apis/design/resource_names#full_resource_name
            state (~google.cloud.securitycenter_v1beta1.types.State): Required. The desired State of the finding.
            start_time (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Timestamp]): Required. The time at which the updated state takes effect.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Timestamp`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.Finding` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "set_finding_state" not in self._inner_api_calls:
            self._inner_api_calls[
                "set_finding_state"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.set_finding_state,
                default_retry=self._method_configs["SetFindingState"].retry,
                default_timeout=self._method_configs["SetFindingState"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.SetFindingStateRequest(
            name=name, state=state, start_time=start_time,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["set_finding_state"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def set_iam_policy(
        self,
        resource,
        policy,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Sets the access control policy on the specified Source.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> resource = client.source_path('[ORGANIZATION]', '[SOURCE]')
            >>>
            >>> # TODO: Initialize `policy`:
            >>> policy = {}
            >>>
            >>> response = client.set_iam_policy(resource, policy)

        Args:
            resource (str): REQUIRED: The resource for which the policy is being specified.
                See the operation documentation for the appropriate value for this field.
            policy (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Policy]): ``Any`` contains an arbitrary serialized protocol buffer message
                along with a URL that describes the type of the serialized message.

                Protobuf library provides support to pack/unpack Any values in the form
                of utility functions or additional generated methods of the Any type.

                Example 1: Pack and unpack a message in C++.

                ::

                    Foo foo = ...;
                    Any any;
                    any.PackFrom(foo);
                    ...
                    if (any.UnpackTo(&foo)) {
                      ...
                    }

                Example 2: Pack and unpack a message in Java.

                ::

                    Foo foo = ...;
                    Any any = Any.pack(foo);
                    ...
                    if (any.is(Foo.class)) {
                      foo = any.unpack(Foo.class);
                    }

                Example 3: Pack and unpack a message in Python.

                ::

                    foo = Foo(...)
                    any = Any()
                    any.Pack(foo)
                    ...
                    if any.Is(Foo.DESCRIPTOR):
                      any.Unpack(foo)
                      ...

                Example 4: Pack and unpack a message in Go

                ::

                     foo := &pb.Foo{...}
                     any, err := ptypes.MarshalAny(foo)
                     ...
                     foo := &pb.Foo{}
                     if err := ptypes.UnmarshalAny(any, foo); err != nil {
                       ...
                     }

                The pack methods provided by protobuf library will by default use
                'type.googleapis.com/full.type.name' as the type URL and the unpack
                methods only use the fully qualified type name after the last '/' in the
                type URL, for example "foo.bar.com/x/y.z" will yield type name "y.z".

                # JSON

                The JSON representation of an ``Any`` value uses the regular
                representation of the deserialized, embedded message, with an additional
                field ``@type`` which contains the type URL. Example:

                ::

                    package google.profile;
                    message Person {
                      string first_name = 1;
                      string last_name = 2;
                    }

                    {
                      "@type": "type.googleapis.com/google.profile.Person",
                      "firstName": <string>,
                      "lastName": <string>
                    }

                If the embedded message type is well-known and has a custom JSON
                representation, that representation will be embedded adding a field
                ``value`` which holds the custom JSON in addition to the ``@type``
                field. Example (for message ``google.protobuf.Duration``):

                ::

                    {
                      "@type": "type.googleapis.com/google.protobuf.Duration",
                      "value": "1.212s"
                    }

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Policy`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.Policy` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "set_iam_policy" not in self._inner_api_calls:
            self._inner_api_calls[
                "set_iam_policy"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.set_iam_policy,
                default_retry=self._method_configs["SetIamPolicy"].retry,
                default_timeout=self._method_configs["SetIamPolicy"].timeout,
                client_info=self._client_info,
            )

        request = iam_policy_pb2.SetIamPolicyRequest(resource=resource, policy=policy,)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("resource", resource)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["set_iam_policy"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def test_iam_permissions(
        self,
        resource,
        permissions,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Returns the permissions that a caller has on the specified source.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> resource = client.source_path('[ORGANIZATION]', '[SOURCE]')
            >>>
            >>> # TODO: Initialize `permissions`:
            >>> permissions = []
            >>>
            >>> response = client.test_iam_permissions(resource, permissions)

        Args:
            resource (str): REQUIRED: The resource for which the policy detail is being requested.
                See the operation documentation for the appropriate value for this field.
            permissions (list[str]): Specifies a service that was configured for Cloud Audit Logging. For
                example, ``storage.googleapis.com``, ``cloudsql.googleapis.com``.
                ``allServices`` is a special value that covers all services. Required
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.TestIamPermissionsResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "test_iam_permissions" not in self._inner_api_calls:
            self._inner_api_calls[
                "test_iam_permissions"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.test_iam_permissions,
                default_retry=self._method_configs["TestIamPermissions"].retry,
                default_timeout=self._method_configs["TestIamPermissions"].timeout,
                client_info=self._client_info,
            )

        request = iam_policy_pb2.TestIamPermissionsRequest(
            resource=resource, permissions=permissions,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("resource", resource)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["test_iam_permissions"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def update_finding(
        self,
        finding,
        update_mask=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Creates or updates a finding. The corresponding source must exist for a
        finding creation to succeed.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `finding`:
            >>> finding = {}
            >>>
            >>> response = client.update_finding(finding)

        Args:
            finding (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Finding]): Expression that defines what fields and order to use for sorting.
                The string value should follow SQL syntax: comma separated list of
                fields. For example: "name,resource_properties.a_property". The default
                sorting order is ascending. To specify descending order for a field, a
                suffix " desc" should be appended to the field name. For example: "name
                desc,resource_properties.a_property". Redundant space characters in the
                syntax are insignificant. "name desc,resource_properties.a_property" and
                " name desc , resource_properties.a_property " are equivalent.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Finding`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1beta1.types.FieldMask]): The FieldMask to use when updating the finding resource. This field should
                not be specified when creating a finding.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.Finding` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "update_finding" not in self._inner_api_calls:
            self._inner_api_calls[
                "update_finding"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.update_finding,
                default_retry=self._method_configs["UpdateFinding"].retry,
                default_timeout=self._method_configs["UpdateFinding"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.UpdateFindingRequest(
            finding=finding, update_mask=update_mask,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("finding.name", finding.name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["update_finding"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def update_organization_settings(
        self,
        organization_settings,
        update_mask=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Updates an organization's settings.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `organization_settings`:
            >>> organization_settings = {}
            >>>
            >>> response = client.update_organization_settings(organization_settings)

        Args:
            organization_settings (Union[dict, ~google.cloud.securitycenter_v1beta1.types.OrganizationSettings]): Required. The organization settings resource to update.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.OrganizationSettings`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1beta1.types.FieldMask]): The FieldMask to use when updating the settings resource.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.OrganizationSettings` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "update_organization_settings" not in self._inner_api_calls:
            self._inner_api_calls[
                "update_organization_settings"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.update_organization_settings,
                default_retry=self._method_configs["UpdateOrganizationSettings"].retry,
                default_timeout=self._method_configs[
                    "UpdateOrganizationSettings"
                ].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.UpdateOrganizationSettingsRequest(
            organization_settings=organization_settings, update_mask=update_mask,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [
                ("organization_settings.name", organization_settings.name)
            ]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["update_organization_settings"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def update_source(
        self,
        source,
        update_mask=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Updates a source.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `source`:
            >>> source = {}
            >>>
            >>> response = client.update_source(source)

        Args:
            source (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Source]): Required. The source resource to update.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Source`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1beta1.types.FieldMask]): The FieldMask to use when updating the source resource.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.Source` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "update_source" not in self._inner_api_calls:
            self._inner_api_calls[
                "update_source"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.update_source,
                default_retry=self._method_configs["UpdateSource"].retry,
                default_timeout=self._method_configs["UpdateSource"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.UpdateSourceRequest(
            source=source, update_mask=update_mask,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("source.name", source.name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["update_source"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def update_security_marks(
        self,
        security_marks,
        update_mask=None,
        start_time=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Updates security marks.

        Example:
            >>> from google.cloud import securitycenter_v1beta1
            >>>
            >>> client = securitycenter_v1beta1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `security_marks`:
            >>> security_marks = {}
            >>>
            >>> response = client.update_security_marks(security_marks)

        Args:
            security_marks (Union[dict, ~google.cloud.securitycenter_v1beta1.types.SecurityMarks]): Required. The security marks resource to update.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.SecurityMarks`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1beta1.types.FieldMask]): The FieldMask to use when updating the security marks resource.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.FieldMask`
            start_time (Union[dict, ~google.cloud.securitycenter_v1beta1.types.Timestamp]): The time at which the updated SecurityMarks take effect.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1beta1.types.Timestamp`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1beta1.types.SecurityMarks` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "update_security_marks" not in self._inner_api_calls:
            self._inner_api_calls[
                "update_security_marks"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.update_security_marks,
                default_retry=self._method_configs["UpdateSecurityMarks"].retry,
                default_timeout=self._method_configs["UpdateSecurityMarks"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.UpdateSecurityMarksRequest(
            security_marks=security_marks,
            update_mask=update_mask,
            start_time=start_time,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("security_marks.name", security_marks.name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["update_security_marks"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )
