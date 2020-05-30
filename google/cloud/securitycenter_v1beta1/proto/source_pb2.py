# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google/cloud/securitycenter_v1beta1/proto/source.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.api import resource_pb2 as google_dot_api_dot_resource__pb2
from google.api import annotations_pb2 as google_dot_api_dot_annotations__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
    name="google/cloud/securitycenter_v1beta1/proto/source.proto",
    package="google.cloud.securitycenter.v1beta1",
    syntax="proto3",
    serialized_options=b"\n'com.google.cloud.securitycenter.v1beta1P\001ZQgoogle.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1;securitycenter",
    serialized_pb=b"\n6google/cloud/securitycenter_v1beta1/proto/source.proto\x12#google.cloud.securitycenter.v1beta1\x1a\x19google/api/resource.proto\x1a\x1cgoogle/api/annotations.proto\"\x9b\x01\n\x06Source\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x14\n\x0c\x64isplay_name\x18\x02 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x03 \x01(\t:X\xea\x41U\n$securitycenter.googleapis.com/Source\x12-organizations/{organization}/sources/{source}B~\n'com.google.cloud.securitycenter.v1beta1P\x01ZQgoogle.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1;securitycenterb\x06proto3",
    dependencies=[
        google_dot_api_dot_resource__pb2.DESCRIPTOR,
        google_dot_api_dot_annotations__pb2.DESCRIPTOR,
    ],
)


_SOURCE = _descriptor.Descriptor(
    name="Source",
    full_name="google.cloud.securitycenter.v1beta1.Source",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    fields=[
        _descriptor.FieldDescriptor(
            name="name",
            full_name="google.cloud.securitycenter.v1beta1.Source.name",
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
        ),
        _descriptor.FieldDescriptor(
            name="display_name",
            full_name="google.cloud.securitycenter.v1beta1.Source.display_name",
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
        ),
        _descriptor.FieldDescriptor(
            name="description",
            full_name="google.cloud.securitycenter.v1beta1.Source.description",
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
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[],
    serialized_options=b"\352AU\n$securitycenter.googleapis.com/Source\022-organizations/{organization}/sources/{source}",
    is_extendable=False,
    syntax="proto3",
    extension_ranges=[],
    oneofs=[],
    serialized_start=153,
    serialized_end=308,
)

DESCRIPTOR.message_types_by_name["Source"] = _SOURCE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Source = _reflection.GeneratedProtocolMessageType(
    "Source",
    (_message.Message,),
    {
        "DESCRIPTOR": _SOURCE,
        "__module__": "google.cloud.securitycenter_v1beta1.proto.source_pb2",
        "__doc__": """Cloud Security Command Center’s (Cloud SCC) finding
  source. A finding source is an entity or a mechanism that can produce a
  finding. A source is like a container of findings that come from the
  same scanner, logger, monitor, etc.
  
  
  Attributes:
      name:
          The relative resource name of this source. See: https://cloud.
          google.com/apis/design/resource_names#relative_resource_name
          Example: “organizations/{organization_id}/sources/{source_id}”
      display_name:
          The source’s display name. A source’s display name must be
          unique amongst its siblings, for example, two sources with the
          same parent can’t share the same display name. The display
          name must have a length between 1 and 64 characters
          (inclusive).
      description:
          The description of the source (max of 1024 characters).
          Example: “Cloud Security Scanner is a web security scanner for
          common vulnerabilities in App Engine applications. It can
          automatically scan and detect four common vulnerabilities,
          including cross-site-scripting (XSS), Flash injection, mixed
          content (HTTP in HTTPS), and outdated/insecure libraries.”
  """,
        # @@protoc_insertion_point(class_scope:google.cloud.securitycenter.v1beta1.Source)
    },
)
_sym_db.RegisterMessage(Source)


DESCRIPTOR._options = None
_SOURCE._options = None
# @@protoc_insertion_point(module_scope)
