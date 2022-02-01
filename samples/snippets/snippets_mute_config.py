#!/usr/bin/env python
#
# Copyright 2022 Google LLC
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


# [START securitycenter_create_mute_config]
from google.cloud.securitycenter_v1 import Finding


def create_mute_rule(parent_path: str, mute_config_id: str) -> None:
    """
    Creates a mute configuration under a given scope that will mute
    all new finding which match the filter/ mute rule.
    Existing findings will NOT BE muted.
    Args:
        parent_path: use any one of the following three options,
                    organizations/{organization} or
                    folders/{folder} or
                    projects/{project}
        mute_config_id: Set a unique id; max of 63 chars.
    """

    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()

    mute_config = securitycenter.MuteConfig()
    mute_config.description = "Mute low-medium IAM grants excluding 'compute' "
    # Set mute rule(s).
    # To construct mute rules and for supported properties, see:
    # https://cloud.google.com/security-command-center/docs/how-to-mute-findings#console_3
    mute_config.filter = (
        'severity="LOW" OR severity="MEDIUM" AND '
        'category="Persistence: IAM Anomalous Grant" AND '
        '-resource.type:"compute"'
    )

    request = securitycenter.CreateMuteConfigRequest()
    request.parent = parent_path
    request.mute_config_id = mute_config_id
    request.mute_config = mute_config

    mute_config = client.create_mute_config(request=request)
    print(f"Mute Config Rule created successfully: {mute_config.name}")


# [END securitycenter_create_mute_config]


# [START securitycenter_delete_mute_config]
def delete_mute_rule(mute_config_name: str) -> None:
    """
    Deletes a mute configuration given its resource name.
    Note: Already muted findings are not affected when a mute config is deleted.
    Args:
        mute_config_name: Specify the name of the mute config to delete.
        Its format is:
        organizations/{organization}/muteConfigs/{config_id} or
        folders/{folder}/muteConfigs/{config_id} or
        projects/{project}/muteConfigs/{config_id}
    """
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()

    request = securitycenter.DeleteMuteConfigRequest()
    request.name = mute_config_name

    client.delete_mute_config(request)
    print(f"Mute Config Rule deleted successfully: {mute_config_name}")


# [END securitycenter_delete_mute_config]


# [START securitycenter_get_mute_config]
def get_mute_rule(mute_config_name: str) -> None:
    """
    Retrieves mute configuration given its resource name.
    Args:
        mute_config_name: Name of the mute config to retrieve.
        Its format is:
        organizations/{organization}/muteConfigs/{config_id} or
        folders/{folder}/muteConfigs/{config_id} or
        projects/{project}/muteConfigs/{config_id}
    """
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()

    request = securitycenter.GetMuteConfigRequest()
    request.name = mute_config_name

    mute_config = client.get_mute_config(request)
    print(f"Retrieved the mute config: {mute_config}")


# [END securitycenter_get_mute_config]


# [START securitycenter_list_mute_configs]
def list_mute_rules(parent: str) -> None:
    """
    Listing mute configs at organization level will give all the configs
    at org, folder and project levels.
    Similarly, listing configs at folder level will list all the configs
    at folder + projects (within that folder) level.
    Args:
        parent: Use any one of the following three resource paths to list mute configurations.
        "organizations/{organization_id}" or
        "folders/{folder_id}" or
        "projects/{project_id}"
    """
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()

    request = securitycenter.ListMuteConfigsRequest()
    request.parent = parent

    # List all Mute Configs present in the resource.
    for mute_config in client.list_mute_configs(request):
        print(mute_config.name)


# [END securitycenter_list_mute_configs]


# [START securitycenter_update_mute_config]
def update_mute_rule(mute_config_name: str) -> None:
    """
    Updates an existing mute configuration.
    The following can be updated in a mute config: description, and filter/ mute rule.
    Args:
        mute_config_name: Specify the name of the mute config to delete.
        Its format is:
        organizations/{organization}/muteConfigs/{config_id} or
        folders/{folder}/muteConfigs/{config_id} or
        projects/{project}/muteConfigs/{config_id}
    """
    from google.cloud import securitycenter
    from google.protobuf import field_mask_pb2

    client = securitycenter.SecurityCenterClient()

    update_mute_config = securitycenter.MuteConfig()
    update_mute_config.name = mute_config_name
    update_mute_config.description = "Updated mute config description"

    field_mask = field_mask_pb2.FieldMask(paths=["description"])

    request = securitycenter.UpdateMuteConfigRequest()
    request.mute_config = update_mute_config
    # Set the update mask to specify which properties of the Mute Config should be updated.
    # If empty all mutable fields will be updated.
    # Make sure that the mask fields match the properties changed in 'update_mute_config'.
    # For more info on constructing update mask path, see the proto or:
    # https://cloud.google.com/security-command-center/docs/reference/rest/v1/folders.muteConfigs/patch?hl=en#query-parameters
    request.update_mask = field_mask

    mute_config = client.update_mute_config(request)
    print(f"Updated mute config : {mute_config}")


# [END securitycenter_update_mute_config]


# [START securitycenter_set_mute_unmute]
def set_mute_unmute_finding(finding_path: str) -> None:
    """
      Mute/unmute an individual finding.
      If a finding is already muted, muting it again (or vice versa) is a no-op.
      Various mute states are: MUTE_UNSPECIFIED/ MUTE/ UNMUTE.
    Args:
        finding_path: The relative resource name of the finding. See:
        https://cloud.google.com/apis/design/resource_names#relative_resource_name
        Example:
        "organizations/{organization_id}/sources/{source_id}/finding/{finding_id}",
        "folders/{folder_id}/sources/{source_id}/finding/{finding_id}",
        "projects/{project_id}/sources/{source_id}/finding/{finding_id}".
    """
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()

    request = securitycenter.SetMuteRequest()
    request.name = finding_path
    request.mute = Finding.Mute.MUTED

    finding = client.set_mute(request)
    print(f"Mute value for the finding: {finding.mute}")


# [END securitycenter_set_mute_unmute]


# [START securitycenter_bulk_mute]
def bulk_mute_findings(parent_path: str, mute_rule: str) -> None:
    """
      Kicks off an LRO (Long-Running-Operation) to bulk mute findings for a parent based on a filter.
      The parent can be either an organization, folder or project. The findings
      matched by the filter will be muted after the LRO is done.
    Args:
        parent_path: use any one of the following three options
            organizations/{organization} or
            folders/{folder} or
            projects/{project}
        mute_rule: Expression that identifies findings that should be updated.
    """
    from google.cloud import securitycenter

    client = securitycenter.SecurityCenterClient()

    request = securitycenter.BulkMuteFindingsRequest()
    request.parent = parent_path
    # To create mute rules, see:
    # https://cloud.google.com/security-command-center/docs/how-to-mute-findings#create_mute_rules
    request.filter = mute_rule

    response = client.bulk_mute_findings(request)
    print(f"Bulk mute findings completed successfully ! : {response}")


# [END securitycenter_bulk_mute]
