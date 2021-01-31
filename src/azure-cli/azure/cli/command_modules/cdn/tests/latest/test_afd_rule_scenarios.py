# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from azure.cli.testsdk import ResourceGroupPreparer, JMESPathCheck
from azure.cli.testsdk import ScenarioTest, record_only
from .afdx_scenario_mixin import CdnAfdScenarioMixin

from azure.mgmt.cdn.models import SkuName


class CdnAfdRuleScenarioTest(CdnAfdScenarioMixin, ScenarioTest):
    @ResourceGroupPreparer()
    def test_rule_engine_crud(self, resource_group):
        profile_name = 'profile123'
        self.afd_endpoint_list_cmd(resource_group, profile_name, expect_failure=True)

        self.afd_profile_create_cmd(resource_group, profile_name, options='--sku Standard_Microsoft')
        list_checks = [JMESPathCheck('length(@)', 0)]
        self.afd_endpoint_list_cmd(resource_group, profile_name, checks=list_checks)

        endpoint_name = self.create_random_name(prefix='endpoint', length=24)
        origin = 'www.example.com'
        checks = [JMESPathCheck('name', endpoint_name),
                  JMESPathCheck('origins[0].hostName', origin),
                  JMESPathCheck('isHttpAllowed', True),
                  JMESPathCheck('isHttpsAllowed', True),
                  JMESPathCheck('isCompressionEnabled', False),
                  JMESPathCheck('queryStringCachingBehavior', 'IgnoreQueryString')]
        self.afd_endpoint_create_cmd(resource_group, endpoint_name, profile_name, origin, checks=checks)

        list_checks = [JMESPathCheck('length(@)', 1)]
        self.afd_endpoint_list_cmd(resource_group, profile_name, checks=list_checks)

        rulename = 'r1'
        update_checks = [JMESPathCheck('name', endpoint_name),
                         JMESPathCheck('origins[0].hostName', origin),
                         JMESPathCheck('isHttpAllowed', True),
                         JMESPathCheck('isHttpsAllowed', True),
                         JMESPathCheck('isCompressionEnabled', False),
                         JMESPathCheck('queryStringCachingBehavior', 'IgnoreQueryString'),
                         JMESPathCheck('length(deliveryPolicy.rules)', 1),
                         JMESPathCheck('deliveryPolicy.rules[0].name', rulename)]
        self.afd_endpoint_add_rule_cmd(resource_group,
                                   endpoint_name,
                                   profile_name,
                                   checks=update_checks)

        update_checks = [JMESPathCheck('name', endpoint_name),
                         JMESPathCheck('origins[0].hostName', origin),
                         JMESPathCheck('isHttpAllowed', True),
                         JMESPathCheck('isHttpsAllowed', True),
                         JMESPathCheck('isCompressionEnabled', False),
                         JMESPathCheck('queryStringCachingBehavior', 'IgnoreQueryString'),
                         JMESPathCheck('length(deliveryPolicy.rules[0].conditions)', 2)]
        self.afd_rule_add_condition_cmd(resource_group,
                                        endpoint_name,
                                        profile_name,
                                        checks=update_checks,
                                        options='--rule-name r1 --match-variable RemoteAddress\
                                                 --operator GeoMatch --match-values "TH" "US"')

        update_checks = [JMESPathCheck('name', endpoint_name),
                         JMESPathCheck('length(deliveryPolicy.rules[0].actions)', 2)]
        self.afd_rule_add_action_cmd(resource_group,
                                     endpoint_name,
                                     profile_name,
                                     checks=update_checks,
                                     options='--rule-name r1 --action-name "UrlRewrite"\
                                              --source-pattern "/abc" --destination "/def"')

        update_checks = [JMESPathCheck('name', endpoint_name),
                         JMESPathCheck('length(deliveryPolicy.rules[0].conditions)', 1)]
        self.afd_rule_remove_condition_cmd(resource_group,
                                           endpoint_name,
                                           profile_name,
                                           checks=update_checks,
                                           options='--rule-name r1 --index 0')

        update_checks = [JMESPathCheck('name', endpoint_name),
                         JMESPathCheck('length(deliveryPolicy.rules[0].actions)', 1)]
        self.afd_rule_remove_action_cmd(resource_group,
                                        endpoint_name,
                                        profile_name,
                                        checks=update_checks,
                                        options='--rule-name r1 --index 0')

        update_checks = [JMESPathCheck('name', endpoint_name),
                         JMESPathCheck('length(deliveryPolicy.rules)', 0)]
        self.afd_rule_delete_rule_cmd(resource_group,
                                      endpoint_name,
                                      profile_name,
                                      checks=update_checks,
                                      options='--rule-name r1')

        self.afd_endpoint_delete_cmd(resource_group, endpoint_name, profile_name)
