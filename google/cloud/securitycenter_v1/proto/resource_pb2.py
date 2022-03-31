# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google/cloud/securitycenter_v1/proto/resource.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.api import annotations_pb2 as google_dot_api_dot_annotations__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
    name="google/cloud/securitycenter_v1/proto/resource.proto",
    package="google.cloud.securitycenter.v1",
    syntax="proto3",
    serialized_options=b'\n"com.google.cloud.securitycenter.v1B\rResourceProtoP\001ZLgoogle.golang.org/genproto/googleapis/cloud/securitycenter/v1;securitycenter\252\002\036Google.Cloud.SecurityCenter.V1\312\002\036Google\\Cloud\\SecurityCenter\\V1\352\002!Google::Cloud::SecurityCenter::V1',
    create_key=_descriptor._internal_create_key,
    serialized_pb=b'\n3google/cloud/securitycenter_v1/proto/resource.proto\x12\x1egoogle.cloud.securitycenter.v1\x1a\x1cgoogle/api/annotations.proto"t\n\x08Resource\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0f\n\x07project\x18\x02 \x01(\t\x12\x1c\n\x14project_display_name\x18\x03 \x01(\t\x12\x0e\n\x06parent\x18\x04 \x01(\t\x12\x1b\n\x13parent_display_name\x18\x05 \x01(\tB\xe9\x01\n"com.google.cloud.securitycenter.v1B\rResourceProtoP\x01ZLgoogle.golang.org/genproto/googleapis/cloud/securitycenter/v1;securitycenter\xaa\x02\x1eGoogle.Cloud.SecurityCenter.V1\xca\x02\x1eGoogle\\Cloud\\SecurityCenter\\V1\xea\x02!Google::Cloud::SecurityCenter::V1b\x06proto3',
    dependencies=[
        google_dot_api_dot_annotations__pb2.DESCRIPTOR,
    ],
)


_RESOURCE = _descriptor.Descriptor(
    name="Resource",
    full_name="google.cloud.securitycenter.v1.Resource",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    create_key=_descriptor._internal_create_key,
    fields=[
        _descriptor.FieldDescriptor(
            name="name",
            full_name="google.cloud.securitycenter.v1.Resource.name",
            index=0,
            number=1,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=b"".decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
            create_key=_descriptor._internal_create_key,
        ),
        _descriptor.FieldDescriptor(
            name="project",
            full_name="google.cloud.securitycenter.v1.Resource.project",
            index=1,
            number=2,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=b"".decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
            create_key=_descriptor._internal_create_key,
        ),
        _descriptor.FieldDescriptor(
            name="project_display_name",
            full_name="google.cloud.securitycenter.v1.Resource.project_display_name",
            index=2,
            number=3,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=b"".decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
            create_key=_descriptor._internal_create_key,
        ),
        _descriptor.FieldDescriptor(
            name="parent",
            full_name="google.cloud.securitycenter.v1.Resource.parent",
            index=3,
            number=4,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=b"".decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
            create_key=_descriptor._internal_create_key,
        ),
        _descriptor.FieldDescriptor(
            name="parent_display_name",
            full_name="google.cloud.securitycenter.v1.Resource.parent_display_name",
            index=4,
            number=5,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=b"".decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
            create_key=_descriptor._internal_create_key,
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[],
    serialized_options=None,
    is_extendable=False,
    syntax="proto3",
    extension_ranges=[],
    oneofs=[],
    serialized_start=117,
    serialized_end=233,
)

DESCRIPTOR.message_types_by_name["Resource"] = _RESOURCE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Resource = _reflection.GeneratedProtocolMessageType(
    "Resource",
    (_message.Message,),
    {
        "DESCRIPTOR": _RESOURCE,
        "__module__": "google.cloud.securitycenter_v1.proto.resource_pb2",
        "__doc__": """Information related to the Google Cloud resource.
  
  Attributes:
      name:
          The full resource name of the resource. See: https://cloud.goo
          gle.com/apis/design/resource_names#full_resource_name
      project:
          The full resource name of project that the resource belongs
          to.
      project_display_name:
          The human readable name of project that the resource belongs
          to.
      parent:
          The full resource name of resource’s parent.
      parent_display_name:
          The human readable name of resource’s parent.
  """,
        # @@protoc_insertion_point(class_scope:google.cloud.securitycenter.v1.Resource)
    },
)
_sym_db.RegisterMessage(Resource)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
