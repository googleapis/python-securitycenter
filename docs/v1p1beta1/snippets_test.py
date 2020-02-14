#!/usr/bin/env python
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
"""Tests for snippets."""

import os

from google.cloud import securitycenter as securitycenter
from google.cloud.securitycenter_v1p1beta1.proto.notification_config_pb2 import (
    NotificationConfig,
)
import pytest

import snippets_notification_configs
import snippets_notification_receiver

ORG_ID = os.environ["GCLOUD_ORGANIZATION"]
PROJECT_ID = os.environ["GCLOUD_PROJECT"]
PUBSUB_TOPIC = os.environ["GLCOUD_PUBSUB_TOPIC"]
PUBSUB_SUBSCRIPTION = os.environ["GCLOUD_PUSBUSB_SUBSCRIPTION"]

CONFIG_ID = "new-notification-pytest"


def cleanup_notification_config(notification_config_id):
    client = securitycenter.SecurityCenterClient()

    notification_config_name = "organizations/{org_id}/notificationConfigs/{config_id}".format(
        org_id=ORG_ID, config_id=notification_config_id
    )
    client.delete_notification_config(notification_config_name)


@pytest.fixture
def new_notification_config():
    client = securitycenter.SecurityCenterClient()

    org_name = "organizations/{org_id}".format(org_id=ORG_ID)

    created_notification_config = client.create_notification_config(
        org_name,
        CONFIG_ID,
        {
            "description": "Notification for active findings",
            "pubsub_topic": PUBSUB_TOPIC,
            "event_type": NotificationConfig.FINDING,
            "streaming_config": {"filter": "",},
        },
    )
    yield created_notification_config
    cleanup_notification_config(CONFIG_ID)


@pytest.fixture
def deleted_notification_config():
    client = securitycenter.SecurityCenterClient()

    org_name = "organizations/{org_id}".format(org_id=ORG_ID)

    created_notification_config = client.create_notification_config(
        org_name,
        CONFIG_ID,
        {
            "description": "Notification for active findings",
            "pubsub_topic": PUBSUB_TOPIC,
            "event_type": NotificationConfig.FINDING,
            "streaming_config": {"filter": "",},
        },
    )
    return created_notification_config


def test_create_notification_config():
    created_notification_config = snippets_notification_configs.create_notification_config(
        ORG_ID, CONFIG_ID, PUBSUB_TOPIC
    )
    assert created_notification_config is not None

    cleanup_notification_config(CONFIG_ID)


def test_delete_notification_config(deleted_notification_config):
    assert (
        snippets_notification_configs.delete_notification_config(ORG_ID, CONFIG_ID)
        is True
    )


def test_get_notification_config(new_notification_config):
    retrieved_config = snippets_notification_configs.get_notification_config(
        ORG_ID, CONFIG_ID
    )
    assert retrieved_config is not None

    cleanup_notification_config(CONFIG_ID)


def test_list_notification_configs():
    iterator = snippets_notification_configs.list_notification_configs(ORG_ID)
    assert iterator is not None


def test_update_notification_config(new_notification_config):
    updated_config = snippets_notification_configs.update_notification_config(
        ORG_ID, CONFIG_ID, PUBSUB_TOPIC
    )
    assert updated_config is not None

    cleanup_notification_config(CONFIG_ID)


def test_receive_notifications():
    assert (
        snippets_notification_receiver.receive_notifications(
            PROJECT_ID, PUBSUB_SUBSCRIPTION
        )
        is True
    )
