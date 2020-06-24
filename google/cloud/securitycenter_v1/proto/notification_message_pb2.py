# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google/cloud/securitycenter_v1/proto/notification_message.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.api import annotations_pb2 as google_dot_api_dot_annotations__pb2
from google.cloud.securitycenter_v1.proto import (
    finding_pb2 as google_dot_cloud_dot_securitycenter__v1_dot_proto_dot_finding__pb2,
)
from google.cloud.securitycenter_v1.proto import (
    resource_pb2 as google_dot_cloud_dot_securitycenter__v1_dot_proto_dot_resource__pb2,
)


DESCRIPTOR = _descriptor.FileDescriptor(
    name="google/cloud/securitycenter_v1/proto/notification_message.proto",
    package="google.cloud.securitycenter.v1",
    syntax="proto3",
    serialized_options=b'\n"com.google.cloud.securitycenter.v1B\030NotificationMessageProtoP\001ZLgoogle.golang.org/genproto/googleapis/cloud/securitycenter/v1;securitycenter\252\002\036Google.Cloud.SecurityCenter.V1\312\002\036Google\\Cloud\\SecurityCenter\\V1\352\002!Google::Cloud::SecurityCenter::V1',
    create_key=_descriptor._internal_create_key,
    serialized_pb=b'\n?google/cloud/securitycenter_v1/proto/notification_message.proto\x12\x1egoogle.cloud.securitycenter.v1\x1a\x1cgoogle/api/annotations.proto\x1a\x32google/cloud/securitycenter_v1/proto/finding.proto\x1a\x33google/cloud/securitycenter_v1/proto/resource.proto"\xb8\x01\n\x13NotificationMessage\x12 \n\x18notification_config_name\x18\x01 \x01(\t\x12:\n\x07\x66inding\x18\x02 \x01(\x0b\x32\'.google.cloud.securitycenter.v1.FindingH\x00\x12:\n\x08resource\x18\x03 \x01(\x0b\x32(.google.cloud.securitycenter.v1.ResourceB\x07\n\x05\x65ventB\xf4\x01\n"com.google.cloud.securitycenter.v1B\x18NotificationMessageProtoP\x01ZLgoogle.golang.org/genproto/googleapis/cloud/securitycenter/v1;securitycenter\xaa\x02\x1eGoogle.Cloud.SecurityCenter.V1\xca\x02\x1eGoogle\\Cloud\\SecurityCenter\\V1\xea\x02!Google::Cloud::SecurityCenter::V1b\x06proto3',
    dependencies=[
        google_dot_api_dot_annotations__pb2.DESCRIPTOR,
        google_dot_cloud_dot_securitycenter__v1_dot_proto_dot_finding__pb2.DESCRIPTOR,
        google_dot_cloud_dot_securitycenter__v1_dot_proto_dot_resource__pb2.DESCRIPTOR,
    ],
)


_NOTIFICATIONMESSAGE = _descriptor.Descriptor(
    name="NotificationMessage",
    full_name="google.cloud.securitycenter.v1.NotificationMessage",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    create_key=_descriptor._internal_create_key,
    fields=[
        _descriptor.FieldDescriptor(
            name="notification_config_name",
            full_name="google.cloud.securitycenter.v1.NotificationMessage.notification_config_name",
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
            name="finding",
            full_name="google.cloud.securitycenter.v1.NotificationMessage.finding",
            index=1,
            number=2,
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
            create_key=_descriptor._internal_create_key,
        ),
        _descriptor.FieldDescriptor(
            name="resource",
            full_name="google.cloud.securitycenter.v1.NotificationMessage.resource",
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
    oneofs=[
        _descriptor.OneofDescriptor(
            name="event",
            full_name="google.cloud.securitycenter.v1.NotificationMessage.event",
            index=0,
            containing_type=None,
            create_key=_descriptor._internal_create_key,
            fields=[],
        ),
    ],
    serialized_start=235,
    serialized_end=419,
)

_NOTIFICATIONMESSAGE.fields_by_name[
    "finding"
].message_type = (
    google_dot_cloud_dot_securitycenter__v1_dot_proto_dot_finding__pb2._FINDING
)
_NOTIFICATIONMESSAGE.fields_by_name[
    "resource"
].message_type = (
    google_dot_cloud_dot_securitycenter__v1_dot_proto_dot_resource__pb2._RESOURCE
)
_NOTIFICATIONMESSAGE.oneofs_by_name["event"].fields.append(
    _NOTIFICATIONMESSAGE.fields_by_name["finding"]
)
_NOTIFICATIONMESSAGE.fields_by_name[
    "finding"
].containing_oneof = _NOTIFICATIONMESSAGE.oneofs_by_name["event"]
DESCRIPTOR.message_types_by_name["NotificationMessage"] = _NOTIFICATIONMESSAGE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

NotificationMessage = _reflection.GeneratedProtocolMessageType(
    "NotificationMessage",
    (_message.Message,),
    {
        "DESCRIPTOR": _NOTIFICATIONMESSAGE,
        "__module__": "google.cloud.securitycenter_v1.proto.notification_message_pb2",
        "__doc__": """Cloud SCC’s Notification
  Attributes:
      notification_config_name:
          Name of the notification config that generated current
          notification.
      event:
          Notification Event.
      finding:
          If it’s a Finding based notification config, this field will
          be populated.
      resource:
          The Cloud resource tied to this notification’s Finding.
  """,
        # @@protoc_insertion_point(class_scope:google.cloud.securitycenter.v1.NotificationMessage)
    },
)
_sym_db.RegisterMessage(NotificationMessage)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
