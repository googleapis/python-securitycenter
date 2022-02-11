# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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
# Generated code. DO NOT EDIT!
#
# Snippet for UpdateExternalSystem
# NOTE: This snippet has been automatically generated for illustrative purposes only.
# It may require modifications to work in your environment.

# To install the latest published package dependency, execute the following:
#   python3 -m pip install google-cloud-securitycenter


# [START securitycenter_generated_securitycenter_v1_SecurityCenter_UpdateExternalSystem_sync]
from google.cloud import securitycenter_v1


def sample_update_external_system():
    # Create a client
    client = securitycenter_v1.SecurityCenterClient()

    # Initialize request argument(s)
    request = securitycenter_v1.UpdateExternalSystemRequest(
    )

    # Make the request
    response = client.update_external_system(request=request)

    # Handle the response
    print(response)

# [END securitycenter_generated_securitycenter_v1_SecurityCenter_UpdateExternalSystem_sync]