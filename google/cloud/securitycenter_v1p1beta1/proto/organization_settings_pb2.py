# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google/cloud/securitycenter_v1p1beta1/proto/organization_settings.proto

import sys

_b = sys.version_info[0] < 3 and (lambda x: x) or (lambda x: x.encode("latin1"))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.api import annotations_pb2 as google_dot_api_dot_annotations__pb2
from google.api import resource_pb2 as google_dot_api_dot_resource__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
    name="google/cloud/securitycenter_v1p1beta1/proto/organization_settings.proto",
    package="google.cloud.securitycenter.v1p1beta1",
    syntax="proto3",
    serialized_options=_b(
        "\n)com.google.cloud.securitycenter.v1p1beta1P\001ZSgoogle.golang.org/genproto/googleapis/cloud/securitycenter/v1p1beta1;securitycenter\252\002%Google.Cloud.SecurityCenter.V1P1Beta1\312\002%Google\\Cloud\\SecurityCenter\\V1p1beta1\352\002(Google::Cloud::SecurityCenter::V1p1beta1"
    ),
    serialized_pb=_b(
        '\nGgoogle/cloud/securitycenter_v1p1beta1/proto/organization_settings.proto\x12%google.cloud.securitycenter.v1p1beta1\x1a\x1cgoogle/api/annotations.proto\x1a\x19google/api/resource.proto"\x98\x04\n\x14OrganizationSettings\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x1e\n\x16\x65nable_asset_discovery\x18\x02 \x01(\x08\x12p\n\x16\x61sset_discovery_config\x18\x03 \x01(\x0b\x32P.google.cloud.securitycenter.v1p1beta1.OrganizationSettings.AssetDiscoveryConfig\x1a\xf3\x01\n\x14\x41ssetDiscoveryConfig\x12\x13\n\x0bproject_ids\x18\x01 \x03(\t\x12v\n\x0einclusion_mode\x18\x02 \x01(\x0e\x32^.google.cloud.securitycenter.v1p1beta1.OrganizationSettings.AssetDiscoveryConfig.InclusionMode"N\n\rInclusionMode\x12\x1e\n\x1aINCLUSION_MODE_UNSPECIFIED\x10\x00\x12\x10\n\x0cINCLUDE_ONLY\x10\x01\x12\x0b\n\x07\x45XCLUDE\x10\x02:j\xea\x41g\n2securitycenter.googleapis.com/OrganizationSettings\x12\x31organizations/{organization}/organizationSettingsB\xfd\x01\n)com.google.cloud.securitycenter.v1p1beta1P\x01ZSgoogle.golang.org/genproto/googleapis/cloud/securitycenter/v1p1beta1;securitycenter\xaa\x02%Google.Cloud.SecurityCenter.V1P1Beta1\xca\x02%Google\\Cloud\\SecurityCenter\\V1p1beta1\xea\x02(Google::Cloud::SecurityCenter::V1p1beta1b\x06proto3'
    ),
    dependencies=[
        google_dot_api_dot_annotations__pb2.DESCRIPTOR,
        google_dot_api_dot_resource__pb2.DESCRIPTOR,
    ],
)


_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG_INCLUSIONMODE = _descriptor.EnumDescriptor(
    name="InclusionMode",
    full_name="google.cloud.securitycenter.v1p1beta1.OrganizationSettings.AssetDiscoveryConfig.InclusionMode",
    filename=None,
    file=DESCRIPTOR,
    values=[
        _descriptor.EnumValueDescriptor(
            name="INCLUSION_MODE_UNSPECIFIED",
            index=0,
            number=0,
            serialized_options=None,
            type=None,
        ),
        _descriptor.EnumValueDescriptor(
            name="INCLUDE_ONLY", index=1, number=1, serialized_options=None, type=None
        ),
        _descriptor.EnumValueDescriptor(
            name="EXCLUDE", index=2, number=2, serialized_options=None, type=None
        ),
    ],
    containing_type=None,
    serialized_options=None,
    serialized_start=522,
    serialized_end=600,
)
_sym_db.RegisterEnumDescriptor(_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG_INCLUSIONMODE)


_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG = _descriptor.Descriptor(
    name="AssetDiscoveryConfig",
    full_name="google.cloud.securitycenter.v1p1beta1.OrganizationSettings.AssetDiscoveryConfig",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    fields=[
        _descriptor.FieldDescriptor(
            name="project_ids",
            full_name="google.cloud.securitycenter.v1p1beta1.OrganizationSettings.AssetDiscoveryConfig.project_ids",
            index=0,
            number=1,
            type=9,
            cpp_type=9,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="inclusion_mode",
            full_name="google.cloud.securitycenter.v1p1beta1.OrganizationSettings.AssetDiscoveryConfig.inclusion_mode",
            index=1,
            number=2,
            type=14,
            cpp_type=8,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG_INCLUSIONMODE,],
    serialized_options=None,
    is_extendable=False,
    syntax="proto3",
    extension_ranges=[],
    oneofs=[],
    serialized_start=357,
    serialized_end=600,
)

_ORGANIZATIONSETTINGS = _descriptor.Descriptor(
    name="OrganizationSettings",
    full_name="google.cloud.securitycenter.v1p1beta1.OrganizationSettings",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    fields=[
        _descriptor.FieldDescriptor(
            name="name",
            full_name="google.cloud.securitycenter.v1p1beta1.OrganizationSettings.name",
            index=0,
            number=1,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="enable_asset_discovery",
            full_name="google.cloud.securitycenter.v1p1beta1.OrganizationSettings.enable_asset_discovery",
            index=1,
            number=2,
            type=8,
            cpp_type=7,
            label=1,
            has_default_value=False,
            default_value=False,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="asset_discovery_config",
            full_name="google.cloud.securitycenter.v1p1beta1.OrganizationSettings.asset_discovery_config",
            index=2,
            number=3,
            type=11,
            cpp_type=10,
            label=1,
            has_default_value=False,
            default_value=None,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
    ],
    extensions=[],
    nested_types=[_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG,],
    enum_types=[],
    serialized_options=_b(
        "\352Ag\n2securitycenter.googleapis.com/OrganizationSettings\0221organizations/{organization}/organizationSettings"
    ),
    is_extendable=False,
    syntax="proto3",
    extension_ranges=[],
    oneofs=[],
    serialized_start=172,
    serialized_end=708,
)

_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG.fields_by_name[
    "inclusion_mode"
].enum_type = _ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG_INCLUSIONMODE
_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG.containing_type = _ORGANIZATIONSETTINGS
_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG_INCLUSIONMODE.containing_type = (
    _ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG
)
_ORGANIZATIONSETTINGS.fields_by_name[
    "asset_discovery_config"
].message_type = _ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG
DESCRIPTOR.message_types_by_name["OrganizationSettings"] = _ORGANIZATIONSETTINGS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

OrganizationSettings = _reflection.GeneratedProtocolMessageType(
    "OrganizationSettings",
    (_message.Message,),
    dict(
        AssetDiscoveryConfig=_reflection.GeneratedProtocolMessageType(
            "AssetDiscoveryConfig",
            (_message.Message,),
            dict(
                DESCRIPTOR=_ORGANIZATIONSETTINGS_ASSETDISCOVERYCONFIG,
                __module__="google.cloud.securitycenter_v1p1beta1.proto.organization_settings_pb2",
                __doc__="""The configuration used for Asset Discovery runs.
    
    
    Attributes:
        project_ids:
            The project ids to use for filtering asset discovery.
        inclusion_mode:
            The mode to use for filtering asset discovery.
    """,
                # @@protoc_insertion_point(class_scope:google.cloud.securitycenter.v1p1beta1.OrganizationSettings.AssetDiscoveryConfig)
            ),
        ),
        DESCRIPTOR=_ORGANIZATIONSETTINGS,
        __module__="google.cloud.securitycenter_v1p1beta1.proto.organization_settings_pb2",
        __doc__="""User specified settings that are attached to the Cloud
  Security Command Center (Cloud SCC) organization.
  
  
  Attributes:
      name:
          The relative resource name of the settings. See: https://cloud
          .google.com/apis/design/resource\_names#relative\_resource\_na
          me Example:
          "organizations/{organization\_id}/organizationSettings".
      enable_asset_discovery:
          A flag that indicates if Asset Discovery should be enabled. If
          the flag is set to ``true``, then discovery of assets will
          occur. If it is set to \`false, all historical assets will
          remain, but discovery of future assets will not occur.
      asset_discovery_config:
          The configuration used for Asset Discovery runs.
  """,
        # @@protoc_insertion_point(class_scope:google.cloud.securitycenter.v1p1beta1.OrganizationSettings)
    ),
)
_sym_db.RegisterMessage(OrganizationSettings)
_sym_db.RegisterMessage(OrganizationSettings.AssetDiscoveryConfig)


DESCRIPTOR._options = None
_ORGANIZATIONSETTINGS._options = None
# @@protoc_insertion_point(module_scope)
