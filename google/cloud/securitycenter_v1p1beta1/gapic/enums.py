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

"""Wrappers for protocol buffer enum types."""

import enum


class NullValue(enum.IntEnum):
    """
    The value returned by the last ``GroupAssetsResponse``; indicates
    that this is a continuation of a prior ``GroupAssets`` call, and that
    the system should return the next page of data.

    Attributes:
      NULL_VALUE (int): Null value.
    """

    NULL_VALUE = 0


class Finding(object):
    class State(enum.IntEnum):
        """
        The state of the finding.

        Attributes:
          STATE_UNSPECIFIED (int): Unspecified state.
          ACTIVE (int): The finding requires attention and has not been addressed yet.
          INACTIVE (int): The finding has been fixed, triaged as a non-issue or otherwise addressed
          and is no longer active.
        """

        STATE_UNSPECIFIED = 0
        ACTIVE = 1
        INACTIVE = 2


class ListAssetsResponse(object):
    class ListAssetsResult(object):
        class StateChange(enum.IntEnum):
            """
            A URL/resource name that uniquely identifies the type of the
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

            Attributes:
              UNUSED (int): State change is unused, this is the canonical default for this enum.
              ADDED (int): Asset was added between the points in time.
              REMOVED (int): Asset was removed between the points in time.
              ACTIVE (int): Asset was present at both point(s) in time.
            """

            UNUSED = 0
            ADDED = 1
            REMOVED = 2
            ACTIVE = 3


class ListFindingsResponse(object):
    class ListFindingsResult(object):
        class StateChange(enum.IntEnum):
            """
            Each of the definitions above may have "options" attached. These are
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

            Attributes:
              UNUSED (int): State change is unused, this is the canonical default for this enum.
              CHANGED (int): The finding has changed state in some way between the points in time
              and existed at both points.
              UNCHANGED (int): The finding has not changed state between the points in time and
              existed at both points.
              ADDED (int): The finding was created between the points in time.
              REMOVED (int): Required. The Source being created, only the display_name and
              description will be used. All other fields will be ignored.
            """

            UNUSED = 0
            CHANGED = 1
            UNCHANGED = 2
            ADDED = 3
            REMOVED = 4


class NotificationConfig(object):
    class EventType(enum.IntEnum):
        """
        The type of events.

        Attributes:
          EVENT_TYPE_UNSPECIFIED (int): Unspecified event type.
          FINDING (int): Events for findings.
        """

        EVENT_TYPE_UNSPECIFIED = 0
        FINDING = 1


class OrganizationSettings(object):
    class AssetDiscoveryConfig(object):
        class InclusionMode(enum.IntEnum):
            """
            If type_name is set, this need not be set. If both this and
            type_name are set, this must be one of TYPE_ENUM, TYPE_MESSAGE or
            TYPE_GROUP.

            Attributes:
              INCLUSION_MODE_UNSPECIFIED (int): Unspecified. Setting the mode with this value will disable
              inclusion/exclusion filtering for Asset Discovery.
              INCLUDE_ONLY (int): Asset Discovery will capture only the resources within the projects
              specified. All other resources will be ignored.
              EXCLUDE (int): Asset Discovery will ignore all resources under the projects specified.
              All other resources will be retrieved.
            """

            INCLUSION_MODE_UNSPECIFIED = 0
            INCLUDE_ONLY = 1
            EXCLUDE = 2


class RunAssetDiscoveryResponse(object):
    class State(enum.IntEnum):
        """
        The state of an asset discovery run.

        Attributes:
          STATE_UNSPECIFIED (int): Asset discovery run state was unspecified.
          COMPLETED (int): Asset discovery run completed successfully.
          SUPERSEDED (int): Asset discovery run was cancelled with tasks still pending, as another
          run for the same organization was started with a higher priority.
          TERMINATED (int): Asset discovery run was killed and terminated.
        """

        STATE_UNSPECIFIED = 0
        COMPLETED = 1
        SUPERSEDED = 2
        TERMINATED = 3
