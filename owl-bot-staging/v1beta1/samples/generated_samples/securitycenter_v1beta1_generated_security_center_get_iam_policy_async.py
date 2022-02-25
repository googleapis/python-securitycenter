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
# Snippet for GetIamPolicy
# NOTE: This snippet has been automatically generated for illustrative purposes only.
# It may require modifications to work in your environment.

# To install the latest published package dependency, execute the following:
#   python3 -m pip install google-cloud-securitycenter


# [START securitycenter_v1beta1_generated_SecurityCenter_GetIamPolicy_async]
from google.cloud import securitycenter_v1beta1


async def sample_get_iam_policy():
    # Create a client
    client = securitycenter_v1beta1.SecurityCenterAsyncClient()

    # Initialize request argument(s)
    request = securitycenter_v1beta1.GetIamPolicyRequest(
        resource="resource_value",
    )

    # Make the request
    response = await client.get_iam_policy(request=request)

    # Handle the response
    print(response)

# [END securitycenter_v1beta1_generated_SecurityCenter_GetIamPolicy_async]
