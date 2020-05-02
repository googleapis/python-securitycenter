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

"""Accesses the google.cloud.securitycenter.v1 SecurityCenter API."""

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

from google.cloud.securitycenter_v1.gapic import enums
from google.cloud.securitycenter_v1.gapic import security_center_client_config
from google.cloud.securitycenter_v1.gapic.transports import (
    security_center_grpc_transport,
)
from google.cloud.securitycenter_v1.proto import finding_pb2
from google.cloud.securitycenter_v1.proto import notification_config_pb2
from google.cloud.securitycenter_v1.proto import organization_settings_pb2
from google.cloud.securitycenter_v1.proto import run_asset_discovery_response_pb2
from google.cloud.securitycenter_v1.proto import security_marks_pb2
from google.cloud.securitycenter_v1.proto import securitycenter_service_pb2
from google.cloud.securitycenter_v1.proto import securitycenter_service_pb2_grpc
from google.cloud.securitycenter_v1.proto import source_pb2
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
    """V1 APIs for Security Center service."""

    SERVICE_ADDRESS = "securitycenter.googleapis.com:443"
    """The default address of the service."""

    # The name of the interface for this client. This is the key used to
    # find the method configuration in the client_config dictionary.
    _INTERFACE_NAME = "google.cloud.securitycenter.v1.SecurityCenter"

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
    def notification_config_path(cls, organization, notification_config):
        """Return a fully-qualified notification_config string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}/notificationConfigs/{notification_config}",
            organization=organization,
            notification_config=notification_config,
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
    def security_marks_path(cls, organization, asset):
        """Return a fully-qualified security_marks string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}/assets/{asset}/securityMarks",
            organization=organization,
            asset=asset,
        )

    @classmethod
    def source_path(cls, organization, source):
        """Return a fully-qualified source string."""
        return google.api_core.path_template.expand(
            "organizations/{organization}/sources/{source}",
            organization=organization,
            source=source,
        )

    @classmethod
    def topic_path(cls, project, topic):
        """Return a fully-qualified topic string."""
        return google.api_core.path_template.expand(
            "projects/{project}/topics/{topic}", project=project, topic=topic,
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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `resource`:
            >>> resource = ''
            >>>
            >>> response = client.get_iam_policy(resource)

        Args:
            resource (str): REQUIRED: The resource for which the policy is being requested.
                See the operation documentation for the appropriate value for this field.
            options_ (Union[dict, ~google.cloud.securitycenter_v1.types.GetPolicyOptions]): For findings on Google Cloud Platform (GCP) resources, the full
                resource name of the GCP resource this finding is for. See:
                https://cloud.google.com/apis/design/resource_names#full_resource_name
                When the finding is for a non-GCP resource, the resourceName can be a
                customer or partner defined string. This field is immutable after
                creation time.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.GetPolicyOptions`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.Policy` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
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
            parent (str): Response message for ``TestIamPermissions`` method.
            group_by (str): Expression that defines the filter to apply across assets. The
                expression is a list of zero or more restrictions combined via logical
                operators ``AND`` and ``OR``. Parentheses are supported, and ``OR`` has
                higher precedence than ``AND``.

                Restrictions have the form ``<field> <operator> <value>`` and may have a
                ``-`` character in front of them to indicate negation. The fields map to
                those defined in the Asset resource. Examples include:

                -  name
                -  security_center_properties.resource_name
                -  resource_properties.a_property
                -  security_marks.marks.marka

                The supported operators are:

                -  ``=`` for all value types.
                -  ``>``, ``<``, ``>=``, ``<=`` for integer values.
                -  ``:``, meaning substring matching, for strings.

                The supported value types are:

                -  string literals in quotes.
                -  integer literals without quotes.
                -  boolean literals ``true`` and ``false`` without quotes.

                The following are the allowed field and operator combinations:

                -  name: ``=``

                -  update_time: ``=``, ``>``, ``<``, ``>=``, ``<=``

                   Usage: This should be milliseconds since epoch or an RFC3339 string.
                   Examples: "update_time = "2019-06-10T16:07:18-07:00"" "update_time =
                   1560208038000"

                -  create_time: ``=``, ``>``, ``<``, ``>=``, ``<=``

                   Usage: This should be milliseconds since epoch or an RFC3339 string.
                   Examples: "create_time = "2019-06-10T16:07:18-07:00"" "create_time =
                   1560208038000"

                -  iam_policy.policy_blob: ``=``, ``:``

                -  resource_properties: ``=``, ``:``, ``>``, ``<``, ``>=``, ``<=``

                -  security_marks.marks: ``=``, ``:``

                -  security_center_properties.resource_name: ``=``, ``:``

                -  security_center_properties.resource_display_name: ``=``, ``:``

                -  security_center_properties.resource_type: ``=``, ``:``

                -  security_center_properties.resource_parent: ``=``, ``:``

                -  security_center_properties.resource_parent_display_name: ``=``, ``:``

                -  security_center_properties.resource_project: ``=``, ``:``

                -  security_center_properties.resource_project_display_name: ``=``,
                   ``:``

                -  security_center_properties.resource_owners: ``=``, ``:``

                For example, ``resource_properties.size = 100`` is a valid filter
                string.
            filter_ (str): A subset of ``TestPermissionsRequest.permissions`` that the caller
                is allowed.
            compare_duration (Union[dict, ~google.cloud.securitycenter_v1.types.Duration]): The FieldMask to use when updating the finding resource. This field
                should not be specified when creating a finding.

                When updating a finding, an empty mask is treated as updating all
                mutable fields and replacing source_properties. Individual
                source_properties can be added/updated by using "source_properties." in
                the field mask.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Duration`
            read_time (Union[dict, ~google.cloud.securitycenter_v1.types.Timestamp]): Time used as a reference point when filtering assets. The filter is limited
                to assets existing at the supplied time and their values are those at that
                specific time. Absence of this field will default to the API's version of
                NOW.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Timestamp`
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
            An iterable of :class:`~google.cloud.securitycenter_v1.types.GroupResult` instances.
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
        compare_duration=None,
        page_size=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Protocol Buffers - Google's data interchange format Copyright 2008
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

        Example:
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
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
            parent (str): ``FieldMask`` represents a set of symbolic field paths, for example:

                ::

                    paths: "f.a"
                    paths: "f.b.d"

                Here ``f`` represents a field in some root message, ``a`` and ``b``
                fields in the message found in ``f``, and ``d`` a field found in the
                message in ``f.b``.

                Field masks are used to specify a subset of fields that should be
                returned by a get operation or modified by an update operation. Field
                masks also have a custom JSON encoding (see below).

                # Field Masks in Projections

                When used in the context of a projection, a response message or
                sub-message is filtered by the API to only contain those fields as
                specified in the mask. For example, if the mask in the previous example
                is applied to a response message as follows:

                ::

                    f {
                      a : 22
                      b {
                        d : 1
                        x : 2
                      }
                      y : 13
                    }
                    z: 8

                The result will not contain specific values for fields x,y and z (their
                value will be set to the default, and omitted in proto text output):

                ::

                    f {
                      a : 22
                      b {
                        d : 1
                      }
                    }

                A repeated field is not allowed except at the last position of a paths
                string.

                If a FieldMask object is not present in a get operation, the operation
                applies to all fields (as if a FieldMask of all fields had been
                specified).

                Note that a field mask does not necessarily apply to the top-level
                response message. In case of a REST get operation, the field mask
                applies directly to the response, but in case of a REST list operation,
                the mask instead applies to each individual message in the returned
                resource list. In case of a REST custom method, other definitions may be
                used. Where the mask applies will be clearly documented together with
                its declaration in the API. In any case, the effect on the returned
                resource/resources is required behavior for APIs.

                # Field Masks in Update Operations

                A field mask in update operations specifies which fields of the targeted
                resource are going to be updated. The API is required to only change the
                values of the fields as specified in the mask and leave the others
                untouched. If a resource is passed in to describe the updated values,
                the API ignores the values of all fields not covered by the mask.

                If a repeated field is specified for an update operation, new values
                will be appended to the existing repeated field in the target resource.
                Note that a repeated field is only allowed in the last position of a
                ``paths`` string.

                If a sub-message is specified in the last position of the field mask for
                an update operation, then new value will be merged into the existing
                sub-message in the target resource.

                For example, given the target message:

                ::

                    f {
                      b {
                        d: 1
                        x: 2
                      }
                      c: [1]
                    }

                And an update message:

                ::

                    f {
                      b {
                        d: 10
                      }
                      c: [2]
                    }

                then if the field mask is:

                paths: ["f.b", "f.c"]

                then the result will be:

                ::

                    f {
                      b {
                        d: 10
                        x: 2
                      }
                      c: [1, 2]
                    }

                An implementation may provide options to override this default behavior
                for repeated and message fields.

                In order to reset a field's value to the default, the field must be in
                the mask and set to the default value in the provided resource. Hence,
                in order to reset all fields of a resource, provide a default instance
                of the resource and set all fields in the mask, or do not provide a mask
                as described below.

                If a field mask is not present on update, the operation applies to all
                fields (as if a field mask of all fields has been specified). Note that
                in the presence of schema evolution, this may mean that fields the
                client does not know and has therefore not filled into the request will
                be reset to their default. If this is unwanted behavior, a specific
                service may require a client to always specify a field mask, producing
                an error if not.

                As with get operations, the location of the resource which describes the
                updated values in the request message depends on the operation kind. In
                any case, the effect of the field mask is required to be honored by the
                API.

                ## Considerations for HTTP REST

                The HTTP kind of an update operation which uses a field mask must be set
                to PATCH instead of PUT in order to satisfy HTTP semantics (PUT must
                only be used for full updates).

                # JSON Encoding of Field Masks

                In JSON, a field mask is encoded as a single string where paths are
                separated by a comma. Fields name in each path are converted to/from
                lower-camel naming conventions.

                As an example, consider the following message declarations:

                ::

                    message Profile {
                      User user = 1;
                      Photo photo = 2;
                    }
                    message User {
                      string display_name = 1;
                      string address = 2;
                    }

                In proto a field mask for ``Profile`` may look as such:

                ::

                    mask {
                      paths: "user.display_name"
                      paths: "photo"
                    }

                In JSON, the same mask is represented as below:

                ::

                    {
                      mask: "user.displayName,photo"
                    }

                # Field Masks and Oneof Fields

                Field masks treat fields in oneofs just as regular fields. Consider the
                following message:

                ::

                    message SampleMessage {
                      oneof test_oneof {
                        string name = 4;
                        SubMessage sub_message = 9;
                      }
                    }

                The field mask can be:

                ::

                    mask {
                      paths: "name"
                    }

                Or:

                ::

                    mask {
                      paths: "sub_message"
                    }

                Note that oneof type names ("test_oneof" in this case) cannot be used in
                paths.

                ## Field Mask Verification

                The implementation of any API method which has a FieldMask type field in
                the request should verify the included field paths, and return an
                ``INVALID_ARGUMENT`` error if any path is unmappable.
            group_by (str): Protocol Buffers - Google's data interchange format Copyright 2008
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
            filter_ (str): Expression that defines what fields and order to use for sorting.
                The string value should follow SQL syntax: comma separated list of
                fields. For example: "name,resource_properties.a_property". The default
                sorting order is ascending. To specify descending order for a field, a
                suffix " desc" should be appended to the field name. For example: "name
                desc,resource_properties.a_property". Redundant space characters in the
                syntax are insignificant. "name desc,resource_properties.a_property" and
                " name desc , resource_properties.a_property " are equivalent.

                The following fields are supported: name update_time resource_properties
                security_marks.marks security_center_properties.resource_name
                security_center_properties.resource_display_name
                security_center_properties.resource_parent
                security_center_properties.resource_parent_display_name
                security_center_properties.resource_project
                security_center_properties.resource_project_display_name
                security_center_properties.resource_type
            read_time (Union[dict, ~google.cloud.securitycenter_v1.types.Timestamp]): Time used as a reference point when filtering findings. The filter is
                limited to findings existing at the supplied time and their values are
                those at that specific time. Absence of this field will default to the
                API's version of NOW.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Timestamp`
            compare_duration (Union[dict, ~google.cloud.securitycenter_v1.types.Duration]): The change in state of the finding.

                When querying across two points in time this describes the change in the
                finding between the two points: CHANGED, UNCHANGED, ADDED, or REMOVED.
                Findings can not be deleted, so REMOVED implies that the finding at
                timestamp does not match the filter specified, but it did at timestamp -
                compare_duration. If there was no compare_duration supplied in the
                request the state change will be: UNUSED

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Duration`
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
            An iterable of :class:`~google.cloud.securitycenter_v1.types.GroupResult` instances.
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
            compare_duration=compare_duration,
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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `resource`:
            >>> resource = ''
            >>>
            >>> # TODO: Initialize `permissions`:
            >>> permissions = []
            >>>
            >>> response = client.test_iam_permissions(resource, permissions)

        Args:
            resource (str): REQUIRED: The resource for which the policy detail is being requested.
                See the operation documentation for the appropriate value for this field.
            permissions (list[str]): ``Struct`` represents a structured data value, consisting of fields
                which map to dynamically typed values. In some languages, ``Struct``
                might be supported by a native representation. For example, in scripting
                languages like JS a struct is represented as an object. The details of
                that representation are described together with the proto support for
                the language.

                The JSON representation for ``Struct`` is JSON object.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.TestIamPermissionsResponse` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> parent = client.organization_path('[ORGANIZATION]')
            >>>
            >>> # TODO: Initialize `source`:
            >>> source = {}
            >>>
            >>> response = client.create_source(parent, source)

        Args:
            parent (str): If this SourceCodeInfo represents a complete declaration, these are
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
            source (Union[dict, ~google.cloud.securitycenter_v1.types.Source]): Expression that defines the filter to apply across create/update
                events of assets or findings as specified by the event type. The
                expression is a list of zero or more restrictions combined via logical
                operators ``AND`` and ``OR``. Parentheses are supported, and ``OR`` has
                higher precedence than ``AND``.

                Restrictions have the form ``<field> <operator> <value>`` and may have a
                ``-`` character in front of them to indicate negation. The fields map to
                those defined in the corresponding resource.

                The supported operators are:

                -  ``=`` for all value types.
                -  ``>``, ``<``, ``>=``, ``<=`` for integer values.
                -  ``:``, meaning substring matching, for strings.

                The supported value types are:

                -  string literals in quotes.
                -  integer literals without quotes.
                -  boolean literals ``true`` and ``false`` without quotes.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Source`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.Source` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
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
            parent (str): See ``HttpRule``.
            finding_id (str): Required. Unique identifier provided by the client within the parent scope.
                It must be alphanumeric and less than or equal to 32 characters and
                greater than 0 characters in length.
            finding (Union[dict, ~google.cloud.securitycenter_v1.types.Finding]): Protocol Buffers - Google's data interchange format Copyright 2008
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

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Finding`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.Finding` instance.

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

    def create_notification_config(
        self,
        parent,
        config_id,
        notification_config,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Creates a notification config.

        Example:
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> parent = client.organization_path('[ORGANIZATION]')
            >>>
            >>> # TODO: Initialize `config_id`:
            >>> config_id = ''
            >>>
            >>> # TODO: Initialize `notification_config`:
            >>> notification_config = {}
            >>>
            >>> response = client.create_notification_config(parent, config_id, notification_config)

        Args:
            parent (str): The set of permissions to check for the ``resource``. Permissions
                with wildcards (such as '*' or 'storage.*') are not allowed. For more
                information see `IAM
                Overview <https://cloud.google.com/iam/docs/overview#permissions>`__.
            config_id (str): Required.
                Unique identifier provided by the client within the parent scope.
                It must be between 1 and 128 characters, and contains alphanumeric
                characters, underscores or hyphens only.
            notification_config (Union[dict, ~google.cloud.securitycenter_v1.types.NotificationConfig]): Required. The notification config being created. The name and the service
                account will be ignored as they are both output only fields on this
                resource.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.NotificationConfig`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.NotificationConfig` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "create_notification_config" not in self._inner_api_calls:
            self._inner_api_calls[
                "create_notification_config"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.create_notification_config,
                default_retry=self._method_configs["CreateNotificationConfig"].retry,
                default_timeout=self._method_configs[
                    "CreateNotificationConfig"
                ].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.CreateNotificationConfigRequest(
            parent=parent, config_id=config_id, notification_config=notification_config,
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

        return self._inner_api_calls["create_notification_config"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def delete_notification_config(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Deletes a notification config.

        Example:
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> name = client.notification_config_path('[ORGANIZATION]', '[NOTIFICATION_CONFIG]')
            >>>
            >>> client.delete_notification_config(name)

        Args:
            name (str): The ``Status`` type defines a logical error model that is suitable
                for different programming environments, including REST APIs and RPC
                APIs. It is used by `gRPC <https://github.com/grpc>`__. Each ``Status``
                message contains three pieces of data: error code, error message, and
                error details.

                You can find out more about this error model and how to work with it in
                the `API Design Guide <https://cloud.google.com/apis/design/errors>`__.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "delete_notification_config" not in self._inner_api_calls:
            self._inner_api_calls[
                "delete_notification_config"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.delete_notification_config,
                default_retry=self._method_configs["DeleteNotificationConfig"].retry,
                default_timeout=self._method_configs[
                    "DeleteNotificationConfig"
                ].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.DeleteNotificationConfigRequest(name=name,)
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

        self._inner_api_calls["delete_notification_config"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_notification_config(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Gets a notification config.

        Example:
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> name = client.notification_config_path('[ORGANIZATION]', '[NOTIFICATION_CONFIG]')
            >>>
            >>> response = client.get_notification_config(name)

        Args:
            name (str): Required. Name of the organization assets should belong to. Its
                format is "organizations/[organization_id]".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.NotificationConfig` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_notification_config" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_notification_config"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_notification_config,
                default_retry=self._method_configs["GetNotificationConfig"].retry,
                default_timeout=self._method_configs["GetNotificationConfig"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.GetNotificationConfigRequest(name=name,)
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

        return self._inner_api_calls["get_notification_config"](
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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> name = client.organization_settings_path('[ORGANIZATION]')
            >>>
            >>> response = client.get_organization_settings(name)

        Args:
            name (str): Required. The Finding being created. The name and security_marks
                will be ignored as they are both output only fields on this resource.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.OrganizationSettings` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> name = client.source_path('[ORGANIZATION]', '[SOURCE]')
            >>>
            >>> response = client.get_source(name)

        Args:
            name (str): The relative resource name of this notification config. See:
                https://cloud.google.com/apis/design/resource_names#relative_resource_name
                Example:
                "organizations/{organization_id}/notificationConfigs/notify_public_bucket".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.Source` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
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
            parent (str): Input and output type names. These are resolved in the same way as
                FieldDescriptorProto.type_name, but must refer to a message type.
            filter_ (str): A URL/resource name that uniquely identifies the type of the
                serialized protocol buffer message. This string must contain at least
                one "/" character. The last segment of the URL's path must represent the
                fully qualified name of the type (as in
                ``path/google.protobuf.Duration``). The name should be in a canonical
                form (e.g., leading "." is not accepted).

                In practice, teams usually precompile into the binary all types that
                they expect it to use in the context of Any. However, for URLs which use
                the scheme ``http``, ``https``, or no scheme, one can optionally set up
                a type server that maps type URLs to message definitions as follows:

                -  If no scheme is provided, ``https`` is assumed.
                -  An HTTP GET on the URL must yield a ``google.protobuf.Type`` value in
                   binary format, or produce an error.
                -  Applications are allowed to cache lookup results based on the URL, or
                   have them precompiled into a binary to avoid any lookup. Therefore,
                   binary compatibility needs to be preserved on changes to types. (Use
                   versioned type names to manage breaking changes.)

                Note: this functionality is not currently available in the official
                protobuf release, and it is not used for type URLs beginning with
                type.googleapis.com.

                Schemes other than ``http``, ``https`` (or the empty scheme) might be
                used with implementation specific semantics.
            order_by (str): The value returned by the last ``ListAssetsResponse``; indicates
                that this is a continuation of a prior ``ListAssets`` call, and that the
                system should return the next page of data.
            read_time (Union[dict, ~google.cloud.securitycenter_v1.types.Timestamp]): Time used as a reference point when filtering assets. The filter is limited
                to assets existing at the supplied time and their values are those at that
                specific time. Absence of this field will default to the API's version of
                NOW.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Timestamp`
            compare_duration (Union[dict, ~google.cloud.securitycenter_v1.types.Duration]): Required. Resource name of the new source's parent. Its format
                should be "organizations/[organization_id]".

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Duration`
            field_mask (Union[dict, ~google.cloud.securitycenter_v1.types.FieldMask]): Optional. A field mask to specify the ListAssetsResult fields to be listed
                in the response. An empty field mask will list all fields.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.FieldMask`
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
            An iterable of :class:`~google.cloud.securitycenter_v1.types.ListAssetsResult` instances.
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
        compare_duration=None,
        field_mask=None,
        page_size=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Request message for ``TestIamPermissions`` method.

        Example:
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
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
            filter_ (str): The full resource name of the GCP resource this asset represents.
                This field is immutable after create time. See:
                https://cloud.google.com/apis/design/resource_names#full_resource_name
            order_by (str): The change in state of the asset.

                When querying across two points in time this describes the change
                between the two points: ADDED, REMOVED, or ACTIVE. If there was no
                compare_duration supplied in the request the state change will be:
                UNUSED
            read_time (Union[dict, ~google.cloud.securitycenter_v1.types.Timestamp]): Time used as a reference point when filtering findings. The filter is
                limited to findings existing at the supplied time and their values are
                those at that specific time. Absence of this field will default to the
                API's version of NOW.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Timestamp`
            compare_duration (Union[dict, ~google.cloud.securitycenter_v1.types.Duration]): Required. Name of the notification config to delete. Its format is
                "organizations/[organization_id]/notificationConfigs/[config_id]".

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Duration`
            field_mask (Union[dict, ~google.cloud.securitycenter_v1.types.FieldMask]): Optional. A field mask to specify the Finding fields to be listed in the
                response. An empty field mask will list all fields.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.FieldMask`
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
            An iterable of :class:`~google.cloud.securitycenter_v1.types.ListFindingsResult` instances.
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
                self._inner_api_calls["list_findings"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="list_findings_results",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def list_notification_configs(
        self,
        parent,
        page_size=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Lists notification configs.

        Example:
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> parent = client.organization_path('[ORGANIZATION]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_notification_configs(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_notification_configs(parent).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): When compare_duration is set, the ListAssetsResult's "state_change"
                attribute is updated to indicate whether the asset was added, removed,
                or remained present during the compare_duration period of time that
                precedes the read_time. This is the time between (read_time -
                compare_duration) and read_time.

                The state_change value is derived based on the presence of the asset at
                the two points in time. Intermediate state changes between the two times
                don't affect the result. For example, the results aren't affected if the
                asset is removed and re-created again.

                Possible "state_change" values when compare_duration is specified:

                -  "ADDED": indicates that the asset was not present at the start of
                   compare_duration, but present at read_time.
                -  "REMOVED": indicates that the asset was present at the start of
                   compare_duration, but not present at read_time.
                -  "ACTIVE": indicates that the asset was present at both the start and
                   the end of the time period defined by compare_duration and read_time.

                If compare_duration is not specified, then the only possible
                state_change is "UNUSED", which will be the state_change set for all
                assets present at read_time.
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
            An iterable of :class:`~google.cloud.securitycenter_v1.types.NotificationConfig` instances.
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
        if "list_notification_configs" not in self._inner_api_calls:
            self._inner_api_calls[
                "list_notification_configs"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.list_notification_configs,
                default_retry=self._method_configs["ListNotificationConfigs"].retry,
                default_timeout=self._method_configs["ListNotificationConfigs"].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.ListNotificationConfigsRequest(
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
                self._inner_api_calls["list_notification_configs"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="notification_configs",
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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
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
            parent (str): The FieldMask to use when updating the security marks resource.

                The field mask must not contain duplicate fields. If empty or set to
                "marks", all marks will be replaced. Individual marks can be updated
                using "marks.<mark_key>".
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
            An iterable of :class:`~google.cloud.securitycenter_v1.types.Source` instances.
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
        Required. Resource name of the new finding's parent. Its format
        should be "organizations/[organization_id]/sources/[source_id]".

        Example:
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
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
            parent (str): Required. The message name of the metadata type for this
                long-running operation.

                If the response is in a different package from the rpc, a
                fully-qualified message name must be used (e.g.
                ``google.protobuf.Struct``).

                Note: Altering this value constitutes a breaking change.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types._OperationFuture` instance.

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
            run_asset_discovery_response_pb2.RunAssetDiscoveryResponse,
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
            >>> from google.cloud import securitycenter_v1
            >>> from google.cloud.securitycenter_v1 import enums
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
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
            name (str): Each of the definitions above may have "options" attached. These are
                just annotations which may cause code to be generated slightly
                differently or may contain hints for code that manipulates protocol
                messages.

                Clients may define custom options as extensions of the \*Options
                messages. These extensions may not yet be known at parsing time, so the
                parser cannot store the values in them. Instead it stores them in a
                field in the \*Options message called uninterpreted_option. This field
                must have the same name across all \*Options messages. We then use this
                field to populate the extensions when we build a descriptor, at which
                point all protos have been parsed and so all extensions are known.

                Extension numbers for custom options may be chosen as follows:

                -  For options which will only be used within a single application or
                   organization, or for experimental options, use field numbers 50000
                   through 99999. It is up to you to ensure that you do not use the same
                   number for multiple options.
                -  For options which will be published and used publicly by multiple
                   independent entities, e-mail
                   protobuf-global-extension-registry@google.com to reserve extension
                   numbers. Simply provide your project name (e.g. Objective-C plugin)
                   and your project website (if available) -- there's no need to explain
                   how you intend to use them. Usually you only need one extension
                   number. You can declare multiple options with only one extension
                   number by putting them in a sub-message. See the Custom Options
                   section of the docs for examples:
                   https://developers.google.com/protocol-buffers/docs/proto#options If
                   this turns out to be popular, a web service will be set up to
                   automatically assign option numbers.
            state (~google.cloud.securitycenter_v1.types.State): Required. The desired State of the finding.
            start_time (Union[dict, ~google.cloud.securitycenter_v1.types.Timestamp]): Required. The time at which the updated state takes effect.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Timestamp`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.Finding` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `resource`:
            >>> resource = ''
            >>>
            >>> # TODO: Initialize `policy`:
            >>> policy = {}
            >>>
            >>> response = client.set_iam_policy(resource, policy)

        Args:
            resource (str): REQUIRED: The resource for which the policy is being specified.
                See the operation documentation for the appropriate value for this field.
            policy (Union[dict, ~google.cloud.securitycenter_v1.types.Policy]): Required. The finding resource to update or create if it does not
                already exist. parent, security_marks, and update_time will be ignored.

                In the case of creation, the finding id portion of the name must be
                alphanumeric and less than or equal to 32 characters and greater than 0
                characters in length.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Policy`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.Policy` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `finding`:
            >>> finding = {}
            >>>
            >>> response = client.update_finding(finding)

        Args:
            finding (Union[dict, ~google.cloud.securitycenter_v1.types.Finding]): Required. Name of the organization to get organization settings for.
                Its format is "organizations/[organization_id]/organizationSettings".

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Finding`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1.types.FieldMask]): If set, all the classes from the .proto file are wrapped in a single
                outer class with the given name. This applies to both Proto1 (equivalent
                to the old "--one_java_file" option) and Proto2 (where a .proto always
                translates to a single class, but you may want to explicitly choose the
                class name).

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.Finding` instance.

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

    def update_notification_config(
        self,
        notification_config,
        update_mask=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Updates a notification config.

        Example:
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `notification_config`:
            >>> notification_config = {}
            >>>
            >>> response = client.update_notification_config(notification_config)

        Args:
            notification_config (Union[dict, ~google.cloud.securitycenter_v1.types.NotificationConfig]): Required. The notification config to update.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.NotificationConfig`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1.types.FieldMask]): The FieldMask to use when updating the notification config.

                If empty all mutable fields will be updated.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.NotificationConfig` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "update_notification_config" not in self._inner_api_calls:
            self._inner_api_calls[
                "update_notification_config"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.update_notification_config,
                default_retry=self._method_configs["UpdateNotificationConfig"].retry,
                default_timeout=self._method_configs[
                    "UpdateNotificationConfig"
                ].timeout,
                client_info=self._client_info,
            )

        request = securitycenter_service_pb2.UpdateNotificationConfigRequest(
            notification_config=notification_config, update_mask=update_mask,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("notification_config.name", notification_config.name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["update_notification_config"](
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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `organization_settings`:
            >>> organization_settings = {}
            >>>
            >>> response = client.update_organization_settings(organization_settings)

        Args:
            organization_settings (Union[dict, ~google.cloud.securitycenter_v1.types.OrganizationSettings]): Required. The organization settings resource to update.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.OrganizationSettings`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1.types.FieldMask]): The FieldMask to use when updating the settings resource.

                 If empty all mutable fields will be updated.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.OrganizationSettings` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `source`:
            >>> source = {}
            >>>
            >>> response = client.update_source(source)

        Args:
            source (Union[dict, ~google.cloud.securitycenter_v1.types.Source]): Required. The source resource to update.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Source`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1.types.FieldMask]): The FieldMask to use when updating the source resource.

                If empty all mutable fields will be updated.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.Source` instance.

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
            >>> from google.cloud import securitycenter_v1
            >>>
            >>> client = securitycenter_v1.SecurityCenterClient()
            >>>
            >>> # TODO: Initialize `security_marks`:
            >>> security_marks = {}
            >>>
            >>> response = client.update_security_marks(security_marks)

        Args:
            security_marks (Union[dict, ~google.cloud.securitycenter_v1.types.SecurityMarks]): Required. The security marks resource to update.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.SecurityMarks`
            update_mask (Union[dict, ~google.cloud.securitycenter_v1.types.FieldMask]): A message representing the message types used by a long-running
                operation.

                Example:

                rpc LongRunningRecognize(LongRunningRecognizeRequest) returns
                (google.longrunning.Operation) { option
                (google.longrunning.operation_info) = { response_type:
                "LongRunningRecognizeResponse" metadata_type:
                "LongRunningRecognizeMetadata" }; }

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.FieldMask`
            start_time (Union[dict, ~google.cloud.securitycenter_v1.types.Timestamp]): The time at which the updated SecurityMarks take effect.
                If not set uses current server time.  Updates will be applied to the
                SecurityMarks that are active immediately preceding this time.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.securitycenter_v1.types.Timestamp`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.securitycenter_v1.types.SecurityMarks` instance.

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
