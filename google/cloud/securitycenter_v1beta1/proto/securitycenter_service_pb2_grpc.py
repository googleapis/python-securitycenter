# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from google.cloud.securitycenter_v1beta1.proto import (
    finding_pb2 as google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2,
)
from google.cloud.securitycenter_v1beta1.proto import (
    organization_settings_pb2 as google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_organization__settings__pb2,
)
from google.cloud.securitycenter_v1beta1.proto import (
    security_marks_pb2 as google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_security__marks__pb2,
)
from google.cloud.securitycenter_v1beta1.proto import (
    securitycenter_service_pb2 as google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2,
)
from google.cloud.securitycenter_v1beta1.proto import (
    source_pb2 as google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2,
)
from google.iam.v1 import iam_policy_pb2 as google_dot_iam_dot_v1_dot_iam__policy__pb2
from google.iam.v1 import policy_pb2 as google_dot_iam_dot_v1_dot_policy__pb2
from google.longrunning import (
    operations_pb2 as google_dot_longrunning_dot_operations__pb2,
)


class SecurityCenterStub(object):
    """V1 Beta APIs for Security Center service."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.CreateSource = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/CreateSource",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.CreateSourceRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.FromString,
        )
        self.CreateFinding = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/CreateFinding",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.CreateFindingRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.FromString,
        )
        self.GetIamPolicy = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetIamPolicy",
            request_serializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.GetIamPolicyRequest.SerializeToString,
            response_deserializer=google_dot_iam_dot_v1_dot_policy__pb2.Policy.FromString,
        )
        self.GetOrganizationSettings = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetOrganizationSettings",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GetOrganizationSettingsRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_organization__settings__pb2.OrganizationSettings.FromString,
        )
        self.GetSource = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetSource",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GetSourceRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.FromString,
        )
        self.GroupAssets = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GroupAssets",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupAssetsRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupAssetsResponse.FromString,
        )
        self.GroupFindings = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GroupFindings",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupFindingsRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupFindingsResponse.FromString,
        )
        self.ListAssets = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListAssets",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListAssetsRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListAssetsResponse.FromString,
        )
        self.ListFindings = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListFindings",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListFindingsRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListFindingsResponse.FromString,
        )
        self.ListSources = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListSources",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListSourcesRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListSourcesResponse.FromString,
        )
        self.RunAssetDiscovery = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/RunAssetDiscovery",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.RunAssetDiscoveryRequest.SerializeToString,
            response_deserializer=google_dot_longrunning_dot_operations__pb2.Operation.FromString,
        )
        self.SetFindingState = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/SetFindingState",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.SetFindingStateRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.FromString,
        )
        self.SetIamPolicy = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/SetIamPolicy",
            request_serializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.SetIamPolicyRequest.SerializeToString,
            response_deserializer=google_dot_iam_dot_v1_dot_policy__pb2.Policy.FromString,
        )
        self.TestIamPermissions = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/TestIamPermissions",
            request_serializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsRequest.SerializeToString,
            response_deserializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsResponse.FromString,
        )
        self.UpdateFinding = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateFinding",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateFindingRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.FromString,
        )
        self.UpdateOrganizationSettings = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateOrganizationSettings",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateOrganizationSettingsRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_organization__settings__pb2.OrganizationSettings.FromString,
        )
        self.UpdateSource = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateSource",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateSourceRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.FromString,
        )
        self.UpdateSecurityMarks = channel.unary_unary(
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateSecurityMarks",
            request_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateSecurityMarksRequest.SerializeToString,
            response_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_security__marks__pb2.SecurityMarks.FromString,
        )


class SecurityCenterServicer(object):
    """V1 Beta APIs for Security Center service."""

    def CreateSource(self, request, context):
        """Creates a source."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def CreateFinding(self, request, context):
        """Creates a finding. The corresponding source must exist for finding creation
        to succeed.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def GetIamPolicy(self, request, context):
        """Gets the access control policy on the specified Source."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def GetOrganizationSettings(self, request, context):
        """Gets the settings for an organization."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def GetSource(self, request, context):
        """Gets a source."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def GroupAssets(self, request, context):
        """Filters an organization's assets and  groups them by their specified
        properties.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def GroupFindings(self, request, context):
        """Filters an organization or source's findings and  groups them by their
        specified properties.

        To group across all sources provide a `-` as the source id.
        Example: /v1beta1/organizations/{organization_id}/sources/-/findings
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def ListAssets(self, request, context):
        """Lists an organization's assets."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def ListFindings(self, request, context):
        """Lists an organization or source's findings.

        To list across all sources provide a `-` as the source id.
        Example: /v1beta1/organizations/{organization_id}/sources/-/findings
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def ListSources(self, request, context):
        """Lists all sources belonging to an organization."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def RunAssetDiscovery(self, request, context):
        """Runs asset discovery. The discovery is tracked with a long-running
        operation.

        This API can only be called with limited frequency for an organization. If
        it is called too frequently the caller will receive a TOO_MANY_REQUESTS
        error.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def SetFindingState(self, request, context):
        """Updates the state of a finding."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def SetIamPolicy(self, request, context):
        """Sets the access control policy on the specified Source."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def TestIamPermissions(self, request, context):
        """Returns the permissions that a caller has on the specified source."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def UpdateFinding(self, request, context):
        """Creates or updates a finding. The corresponding source must exist for a
        finding creation to succeed.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def UpdateOrganizationSettings(self, request, context):
        """Updates an organization's settings."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def UpdateSource(self, request, context):
        """Updates a source."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def UpdateSecurityMarks(self, request, context):
        """Updates security marks."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")


def add_SecurityCenterServicer_to_server(servicer, server):
    rpc_method_handlers = {
        "CreateSource": grpc.unary_unary_rpc_method_handler(
            servicer.CreateSource,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.CreateSourceRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.SerializeToString,
        ),
        "CreateFinding": grpc.unary_unary_rpc_method_handler(
            servicer.CreateFinding,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.CreateFindingRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.SerializeToString,
        ),
        "GetIamPolicy": grpc.unary_unary_rpc_method_handler(
            servicer.GetIamPolicy,
            request_deserializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.GetIamPolicyRequest.FromString,
            response_serializer=google_dot_iam_dot_v1_dot_policy__pb2.Policy.SerializeToString,
        ),
        "GetOrganizationSettings": grpc.unary_unary_rpc_method_handler(
            servicer.GetOrganizationSettings,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GetOrganizationSettingsRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_organization__settings__pb2.OrganizationSettings.SerializeToString,
        ),
        "GetSource": grpc.unary_unary_rpc_method_handler(
            servicer.GetSource,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GetSourceRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.SerializeToString,
        ),
        "GroupAssets": grpc.unary_unary_rpc_method_handler(
            servicer.GroupAssets,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupAssetsRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupAssetsResponse.SerializeToString,
        ),
        "GroupFindings": grpc.unary_unary_rpc_method_handler(
            servicer.GroupFindings,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupFindingsRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupFindingsResponse.SerializeToString,
        ),
        "ListAssets": grpc.unary_unary_rpc_method_handler(
            servicer.ListAssets,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListAssetsRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListAssetsResponse.SerializeToString,
        ),
        "ListFindings": grpc.unary_unary_rpc_method_handler(
            servicer.ListFindings,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListFindingsRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListFindingsResponse.SerializeToString,
        ),
        "ListSources": grpc.unary_unary_rpc_method_handler(
            servicer.ListSources,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListSourcesRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListSourcesResponse.SerializeToString,
        ),
        "RunAssetDiscovery": grpc.unary_unary_rpc_method_handler(
            servicer.RunAssetDiscovery,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.RunAssetDiscoveryRequest.FromString,
            response_serializer=google_dot_longrunning_dot_operations__pb2.Operation.SerializeToString,
        ),
        "SetFindingState": grpc.unary_unary_rpc_method_handler(
            servicer.SetFindingState,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.SetFindingStateRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.SerializeToString,
        ),
        "SetIamPolicy": grpc.unary_unary_rpc_method_handler(
            servicer.SetIamPolicy,
            request_deserializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.SetIamPolicyRequest.FromString,
            response_serializer=google_dot_iam_dot_v1_dot_policy__pb2.Policy.SerializeToString,
        ),
        "TestIamPermissions": grpc.unary_unary_rpc_method_handler(
            servicer.TestIamPermissions,
            request_deserializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsRequest.FromString,
            response_serializer=google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsResponse.SerializeToString,
        ),
        "UpdateFinding": grpc.unary_unary_rpc_method_handler(
            servicer.UpdateFinding,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateFindingRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.SerializeToString,
        ),
        "UpdateOrganizationSettings": grpc.unary_unary_rpc_method_handler(
            servicer.UpdateOrganizationSettings,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateOrganizationSettingsRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_organization__settings__pb2.OrganizationSettings.SerializeToString,
        ),
        "UpdateSource": grpc.unary_unary_rpc_method_handler(
            servicer.UpdateSource,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateSourceRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.SerializeToString,
        ),
        "UpdateSecurityMarks": grpc.unary_unary_rpc_method_handler(
            servicer.UpdateSecurityMarks,
            request_deserializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateSecurityMarksRequest.FromString,
            response_serializer=google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_security__marks__pb2.SecurityMarks.SerializeToString,
        ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
        "google.cloud.securitycenter.v1beta1.SecurityCenter", rpc_method_handlers
    )
    server.add_generic_rpc_handlers((generic_handler,))


# This class is part of an EXPERIMENTAL API.
class SecurityCenter(object):
    """V1 Beta APIs for Security Center service."""

    @staticmethod
    def CreateSource(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/CreateSource",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.CreateSourceRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def CreateFinding(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/CreateFinding",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.CreateFindingRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def GetIamPolicy(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetIamPolicy",
            google_dot_iam_dot_v1_dot_iam__policy__pb2.GetIamPolicyRequest.SerializeToString,
            google_dot_iam_dot_v1_dot_policy__pb2.Policy.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def GetOrganizationSettings(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetOrganizationSettings",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GetOrganizationSettingsRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_organization__settings__pb2.OrganizationSettings.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def GetSource(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GetSource",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GetSourceRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def GroupAssets(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GroupAssets",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupAssetsRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupAssetsResponse.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def GroupFindings(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/GroupFindings",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupFindingsRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.GroupFindingsResponse.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def ListAssets(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListAssets",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListAssetsRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListAssetsResponse.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def ListFindings(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListFindings",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListFindingsRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListFindingsResponse.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def ListSources(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/ListSources",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListSourcesRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.ListSourcesResponse.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def RunAssetDiscovery(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/RunAssetDiscovery",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.RunAssetDiscoveryRequest.SerializeToString,
            google_dot_longrunning_dot_operations__pb2.Operation.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def SetFindingState(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/SetFindingState",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.SetFindingStateRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def SetIamPolicy(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/SetIamPolicy",
            google_dot_iam_dot_v1_dot_iam__policy__pb2.SetIamPolicyRequest.SerializeToString,
            google_dot_iam_dot_v1_dot_policy__pb2.Policy.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def TestIamPermissions(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/TestIamPermissions",
            google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsRequest.SerializeToString,
            google_dot_iam_dot_v1_dot_iam__policy__pb2.TestIamPermissionsResponse.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def UpdateFinding(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateFinding",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateFindingRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_finding__pb2.Finding.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def UpdateOrganizationSettings(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateOrganizationSettings",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateOrganizationSettingsRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_organization__settings__pb2.OrganizationSettings.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def UpdateSource(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateSource",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateSourceRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_source__pb2.Source.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )

    @staticmethod
    def UpdateSecurityMarks(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return grpc.experimental.unary_unary(
            request,
            target,
            "/google.cloud.securitycenter.v1beta1.SecurityCenter/UpdateSecurityMarks",
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_securitycenter__service__pb2.UpdateSecurityMarksRequest.SerializeToString,
            google_dot_cloud_dot_securitycenter__v1beta1_dot_proto_dot_security__marks__pb2.SecurityMarks.FromString,
            options,
            channel_credentials,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
        )
