# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from azure.cli.testsdk import ResourceGroupPreparer, JMESPathCheck
from azure.cli.testsdk import ScenarioTest, record_only
from .afdx_scenario_mixin import CdnAfdScenarioMixin

class CdnAfdSecretScenarioTest(CdnAfdScenarioMixin, ScenarioTest):
    @ResourceGroupPreparer()
    def test_afd_secret_crud(self, resource_group):
        profile_name = 'profilesecrettest'
        self.afd_secret_list_cmd(resource_group, profile_name, expect_failure=True)

        # Create a standard Azure frontdoor profile
        self.afd_profile_create_cmd(resource_group, profile_name)
        list_checks = [JMESPathCheck('length(@)', 0)]
        self.afd_secret_list_cmd(resource_group, profile_name, checks=list_checks)

        # Create a secret
        secret_name = self.create_random_name(prefix='secret', length=24)
        secret_source = "/subscriptions/d7cfdb98-c118-458d-8bdf-246be66b1f5e/resourceGroups/cdn-powershell-test/providers/Microsoft.KeyVault/vaults/cdn-powershell-test-kv/certificates/cdn-powershell-test-cer2"
        use_latest_version = True
        secret_version = None

        checks = [JMESPathCheck('provisioningState', 'Succeeded')]
        self.afd_secret_create_cmd(resource_group,
                                 profile_name,
                                 secret_name,
                                 secret_source,
                                 use_latest_version,
                                 secret_version,
                                 checks=checks)

        list_checks = [JMESPathCheck('length(@)', 1),
                       JMESPathCheck('@[0].name', secret_name),
                       JMESPathCheck('@[0].provisioningState', 'Succeeded')]
        self.afd_secret_list_cmd(resource_group, profile_name, checks=list_checks)

        # Delete the secret
        self.afd_secret_delete_cmd(resource_group, profile_name, secret_name)
        list_checks = [JMESPathCheck('length(@)', 0)]
        self.afd_secret_list_cmd(resource_group, profile_name, checks=list_checks)