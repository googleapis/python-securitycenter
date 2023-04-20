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

import proto  # type: ignore

from google.cloud.securitycenter_v1.types import container
from google.cloud.securitycenter_v1.types import label


__protobuf__ = proto.module(
    package='google.cloud.securitycenter.v1',
    manifest={
        'Kubernetes',
    },
)


class Kubernetes(proto.Message):
    r"""Kubernetes-related attributes.

    Attributes:
        pods (MutableSequence[google.cloud.securitycenter_v1.types.Kubernetes.Pod]):
            Kubernetes Pods associated with the finding.
            This field will contain Pod records for each
            container that is owned by a Pod.
        nodes (MutableSequence[google.cloud.securitycenter_v1.types.Kubernetes.Node]):
            Provides Kubernetes Node information.
        node_pools (MutableSequence[google.cloud.securitycenter_v1.types.Kubernetes.NodePool]):
            GKE Node Pools associated with the finding.
            This field will contain NodePool information for
            each Node, when it is available.
        roles (MutableSequence[google.cloud.securitycenter_v1.types.Kubernetes.Role]):
            Provides Kubernetes role information for
            findings that involve Roles or ClusterRoles.
        bindings (MutableSequence[google.cloud.securitycenter_v1.types.Kubernetes.Binding]):
            Provides Kubernetes role binding information
            for findings that involve RoleBindings or
            ClusterRoleBindings.
        access_reviews (MutableSequence[google.cloud.securitycenter_v1.types.Kubernetes.AccessReview]):
            Provides information on any Kubernetes access
            reviews (i.e. privilege checks) relevant to the
            finding.
    """

    class Pod(proto.Message):
        r"""Kubernetes Pod.

        Attributes:
            ns (str):
                Kubernetes Pod namespace.
            name (str):
                Kubernetes Pod name.
            labels (MutableSequence[google.cloud.securitycenter_v1.types.Label]):
                Pod labels.  For Kubernetes containers, these
                are applied to the container.
            containers (MutableSequence[google.cloud.securitycenter_v1.types.Container]):
                Pod containers associated with this finding,
                if any.
        """

        ns: str = proto.Field(
            proto.STRING,
            number=1,
        )
        name: str = proto.Field(
            proto.STRING,
            number=2,
        )
        labels: MutableSequence[label.Label] = proto.RepeatedField(
            proto.MESSAGE,
            number=3,
            message=label.Label,
        )
        containers: MutableSequence[container.Container] = proto.RepeatedField(
            proto.MESSAGE,
            number=4,
            message=container.Container,
        )

    class Node(proto.Message):
        r"""Kubernetes Nodes associated with the finding.

        Attributes:
            name (str):
                Full Resource name of the Compute Engine VM
                running the cluster node.
        """

        name: str = proto.Field(
            proto.STRING,
            number=1,
        )

    class NodePool(proto.Message):
        r"""Provides GKE Node Pool information.

        Attributes:
            name (str):
                Kubernetes Node pool name.
            nodes (MutableSequence[google.cloud.securitycenter_v1.types.Kubernetes.Node]):
                Nodes associated with the finding.
        """

        name: str = proto.Field(
            proto.STRING,
            number=1,
        )
        nodes: MutableSequence['Kubernetes.Node'] = proto.RepeatedField(
            proto.MESSAGE,
            number=2,
            message='Kubernetes.Node',
        )

    class Role(proto.Message):
        r"""Kubernetes Role or ClusterRole.

        Attributes:
            kind (google.cloud.securitycenter_v1.types.Kubernetes.Role.Kind):
                Role type.
            ns (str):
                Role namespace.
            name (str):
                Role name.
        """
        class Kind(proto.Enum):
            r"""Types of Kubernetes roles.

            Values:
                KIND_UNSPECIFIED (0):
                    Role type is not specified.
                ROLE (1):
                    Kubernetes Role.
                CLUSTER_ROLE (2):
                    Kubernetes ClusterRole.
            """
            KIND_UNSPECIFIED = 0
            ROLE = 1
            CLUSTER_ROLE = 2

        kind: 'Kubernetes.Role.Kind' = proto.Field(
            proto.ENUM,
            number=1,
            enum='Kubernetes.Role.Kind',
        )
        ns: str = proto.Field(
            proto.STRING,
            number=2,
        )
        name: str = proto.Field(
            proto.STRING,
            number=3,
        )

    class Binding(proto.Message):
        r"""Represents a Kubernetes RoleBinding or ClusterRoleBinding.

        Attributes:
            ns (str):
                Namespace for binding.
            name (str):
                Name for binding.
            role (google.cloud.securitycenter_v1.types.Kubernetes.Role):
                The Role or ClusterRole referenced by the
                binding.
            subjects (MutableSequence[google.cloud.securitycenter_v1.types.Kubernetes.Subject]):
                Represents one or more subjects that are
                bound to the role. Not always available for
                PATCH requests.
        """

        ns: str = proto.Field(
            proto.STRING,
            number=1,
        )
        name: str = proto.Field(
            proto.STRING,
            number=2,
        )
        role: 'Kubernetes.Role' = proto.Field(
            proto.MESSAGE,
            number=3,
            message='Kubernetes.Role',
        )
        subjects: MutableSequence['Kubernetes.Subject'] = proto.RepeatedField(
            proto.MESSAGE,
            number=4,
            message='Kubernetes.Subject',
        )

    class Subject(proto.Message):
        r"""Represents a Kubernetes Subject.

        Attributes:
            kind (google.cloud.securitycenter_v1.types.Kubernetes.Subject.AuthType):
                Authentication type for subject.
            ns (str):
                Namespace for subject.
            name (str):
                Name for subject.
        """
        class AuthType(proto.Enum):
            r"""Auth types that can be used for Subject's kind field.

            Values:
                AUTH_TYPE_UNSPECIFIED (0):
                    Authentication is not specified.
                USER (1):
                    User with valid certificate.
                SERVICEACCOUNT (2):
                    Users managed by Kubernetes API with
                    credentials stored as Secrets.
                GROUP (3):
                    Collection of users.
            """
            AUTH_TYPE_UNSPECIFIED = 0
            USER = 1
            SERVICEACCOUNT = 2
            GROUP = 3

        kind: 'Kubernetes.Subject.AuthType' = proto.Field(
            proto.ENUM,
            number=1,
            enum='Kubernetes.Subject.AuthType',
        )
        ns: str = proto.Field(
            proto.STRING,
            number=2,
        )
        name: str = proto.Field(
            proto.STRING,
            number=3,
        )

    class AccessReview(proto.Message):
        r"""Conveys information about a Kubernetes access review (e.g.
        kubectl auth can-i ...) that was involved in a finding.

        Attributes:
            group (str):
                Group is the API Group of the Resource. "*" means all.
            ns (str):
                Namespace of the action being requested.
                Currently, there is no distinction between no
                namespace and all namespaces.  Both are
                represented by "" (empty).
            name (str):
                Name is the name of the resource being
                requested. Empty means all.
            resource (str):
                Resource is the optional resource type requested. "*" means
                all.
            subresource (str):
                Subresource is the optional subresource type.
            verb (str):
                Verb is a Kubernetes resource API verb, like: get, list,
                watch, create, update, delete, proxy. "*" means all.
            version (str):
                Version is the API Version of the Resource. "*" means all.
        """

        group: str = proto.Field(
            proto.STRING,
            number=1,
        )
        ns: str = proto.Field(
            proto.STRING,
            number=2,
        )
        name: str = proto.Field(
            proto.STRING,
            number=3,
        )
        resource: str = proto.Field(
            proto.STRING,
            number=4,
        )
        subresource: str = proto.Field(
            proto.STRING,
            number=5,
        )
        verb: str = proto.Field(
            proto.STRING,
            number=6,
        )
        version: str = proto.Field(
            proto.STRING,
            number=7,
        )

    pods: MutableSequence[Pod] = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message=Pod,
    )
    nodes: MutableSequence[Node] = proto.RepeatedField(
        proto.MESSAGE,
        number=2,
        message=Node,
    )
    node_pools: MutableSequence[NodePool] = proto.RepeatedField(
        proto.MESSAGE,
        number=3,
        message=NodePool,
    )
    roles: MutableSequence[Role] = proto.RepeatedField(
        proto.MESSAGE,
        number=4,
        message=Role,
    )
    bindings: MutableSequence[Binding] = proto.RepeatedField(
        proto.MESSAGE,
        number=5,
        message=Binding,
    )
    access_reviews: MutableSequence[AccessReview] = proto.RepeatedField(
        proto.MESSAGE,
        number=6,
        message=AccessReview,
    )


__all__ = tuple(sorted(__protobuf__.manifest))
