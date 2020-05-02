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


import google.api_core.grpc_helpers
import google.api_core.operations_v1

from google.cloud.securitycenter_v1beta1.proto import securitycenter_service_pb2_grpc


class SecurityCenterGrpcTransport(object):
    """gRPC transport class providing stubs for
    google.cloud.securitycenter.v1beta1 SecurityCenter API.

    The transport provides access to the raw gRPC stubs,
    which can be used to take advantage of advanced
    features of gRPC.
    """

    # The scopes needed to make gRPC calls to all of the methods defined
    # in this service.
    _OAUTH_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)

    def __init__(
        self,
        channel=None,
        credentials=None,
        address="securitycenter.googleapis.com:443",
    ):
        """Instantiate the transport class.

        Args:
            channel (grpc.Channel): A ``Channel`` instance through
                which to make calls. This argument is mutually exclusive
                with ``credentials``; providing both will raise an exception.
            credentials (google.auth.credentials.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            address (str): The address where the service is hosted.
        """
        # If both `channel` and `credentials` are specified, raise an
        # exception (channels come with credentials baked in already).
        if channel is not None and credentials is not None:
            raise ValueError(
                "The `channel` and `credentials` arguments are mutually " "exclusive.",
            )

        # Create the channel.
        if channel is None:
            channel = self.create_channel(
                address=address,
                credentials=credentials,
                options={
                    "grpc.max_send_message_length": -1,
                    "grpc.max_receive_message_length": -1,
                }.items(),
            )

        self._channel = channel

        # gRPC uses objects called "stubs" that are bound to the
        # channel and provide a basic method for each RPC.
        self._stubs = {
            "security_center_stub": securitycenter_service_pb2_grpc.SecurityCenterStub(
                channel
            ),
        }

        # Because this API includes a method that returns a
        # long-running operation (proto: google.longrunning.Operation),
        # instantiate an LRO client.
        self._operations_client = google.api_core.operations_v1.OperationsClient(
            channel
        )

    @classmethod
    def create_channel(
        cls, address="securitycenter.googleapis.com:443", credentials=None, **kwargs
    ):
        """Create and return a gRPC channel object.

        Args:
            address (str): The host for the channel to use.
            credentials (~.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If
                none are specified, the client will attempt to ascertain
                the credentials from the environment.
            kwargs (dict): Keyword arguments, which are passed to the
                channel creation.

        Returns:
            grpc.Channel: A gRPC channel object.
        """
        return google.api_core.grpc_helpers.create_channel(
            address, credentials=credentials, scopes=cls._OAUTH_SCOPES, **kwargs
        )

    @property
    def channel(self):
        """The gRPC channel used by the transport.

        Returns:
            grpc.Channel: A gRPC channel object.
        """
        return self._channel

    @property
    def create_source(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.create_source`.

        Creates a source.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].CreateSource

    @property
    def create_finding(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.create_finding`.

        Creates a finding. The corresponding source must exist for finding creation
        to succeed.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].CreateFinding

    @property
    def get_iam_policy(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.get_iam_policy`.

        Gets the access control policy on the specified Source.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].GetIamPolicy

    @property
    def get_organization_settings(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.get_organization_settings`.

        Gets the settings for an organization.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].GetOrganizationSettings

    @property
    def get_source(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.get_source`.

        Gets a source.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].GetSource

    @property
    def group_assets(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.group_assets`.

        Filters an organization's assets and  groups them by their specified
        properties.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].GroupAssets

    @property
    def group_findings(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.group_findings`.

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

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].GroupFindings

    @property
    def list_assets(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.list_assets`.

        Lists an organization's assets.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].ListAssets

    @property
    def list_findings(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.list_findings`.

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

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].ListFindings

    @property
    def list_sources(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.list_sources`.

        Lists all sources belonging to an organization.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].ListSources

    @property
    def run_asset_discovery(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.run_asset_discovery`.

        The value returned by the last ``ListSourcesResponse``; indicates
        that this is a continuation of a prior ``ListSources`` call, and that
        the system should return the next page of data.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].RunAssetDiscovery

    @property
    def set_finding_state(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.set_finding_state`.

        Updates the state of a finding.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].SetFindingState

    @property
    def set_iam_policy(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.set_iam_policy`.

        Sets the access control policy on the specified Source.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].SetIamPolicy

    @property
    def test_iam_permissions(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.test_iam_permissions`.

        Returns the permissions that a caller has on the specified source.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].TestIamPermissions

    @property
    def update_finding(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.update_finding`.

        Creates or updates a finding. The corresponding source must exist for a
        finding creation to succeed.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].UpdateFinding

    @property
    def update_organization_settings(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.update_organization_settings`.

        Updates an organization's settings.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].UpdateOrganizationSettings

    @property
    def update_source(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.update_source`.

        Updates a source.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].UpdateSource

    @property
    def update_security_marks(self):
        """Return the gRPC stub for :meth:`SecurityCenterClient.update_security_marks`.

        Updates security marks.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["security_center_stub"].UpdateSecurityMarks
