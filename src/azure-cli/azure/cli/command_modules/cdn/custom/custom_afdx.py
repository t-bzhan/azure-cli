# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from typing import (Optional, List)


from azure.mgmt.cdn.models import (AFDEndpoint, HealthProbeRequestType, EnabledState, Route, LinkToDefaultDomain,
                                   AFDEndpointProtocols, HttpsRedirect, ForwardingProtocol, QueryStringCachingBehavior,)

from azure.mgmt.cdn.operations import (OriginsOperations, AFDOriginGroupsOperations, AFDOriginsOperations,
                                       RoutesOperations, RuleSetsOperations, RulesOperations)

from azure.cli.core.util import (sdk_no_wait)
from knack.util import CLIError
from knack.log import get_logger

logger = get_logger(__name__)

def _update_mapper(existing, new, keys):
    for key in keys:
        existing_value = getattr(existing, key)
        new_value = getattr(new, key)
        setattr(new, key, new_value if new_value is not None else existing_value)

def create_afd_endpoint(client, resource_group_name, profile_name, name, origin_response_timeout_seconds, enabled_state,
                    location=None, tags=None, no_wait=None):

    endpoint = AFDEndpoint(location=location,
                        origin_response_timeout_seconds = origin_response_timeout_seconds,
                        enabled_state = enabled_state,
                        tags=tags)

    return sdk_no_wait(no_wait, client.afd_endpoints.create, resource_group_name, profile_name, name, endpoint)


def create_afd_origin_group(client: AFDOriginGroupsOperations,
                        resource_group_name: str,
                        profile_name: str,
                        name: str,
                        load_balancing_sample_size: int,
                        load_balancing_successful_samples_required: int,
                        load_balancing_additional_latency_in_milliseconds: int,
                        probe_request_type: HealthProbeRequestType,
                        probe_protocol: str,
                        probe_path: str,
                        probe_interval_in_seconds: int = 240):

    # Move these to the parameters list once support is added in RP:
    response_error_detection_error_types: Optional[str] = None
    response_error_detection_failover_threshold: Optional[int] = None
    response_error_detection_status_code_ranges: Optional[str] = None

    from azure.mgmt.cdn.models import (AFDOriginGroup,
                                       LoadBalancingSettingsParameters,
                                       HealthProbeParameters)

    health_probe_parameters = HealthProbeParameters(probe_path=probe_path,
                                                  probe_request_type=probe_request_type,
                                                  probe_protocol=probe_protocol,
                                                  probe_interval_in_seconds=probe_interval_in_seconds)

    load_balancing_settings_parameters = LoadBalancingSettingsParameters(sample_size=load_balancing_sample_size,
                                                  successful_samples_required=load_balancing_successful_samples_required,
                                                  additional_latency_in_milliseconds=load_balancing_additional_latency_in_milliseconds)

    afd_origin_group = AFDOriginGroup(load_balancing_settings=load_balancing_settings_parameters,
                               health_probe_settings=health_probe_parameters)

    return client.create(resource_group_name,
                         profile_name,
                         name,
                         afd_origin_group).result()


def create_afd_origin(client: AFDOriginsOperations,
                  resource_group_name: str,
                  profile_name: str,
                  origin_group_name: str,
                  origin_name: str,
                  host_name: str,
                  enabled_state: EnabledState,
                  http_port: int = 80,
                  https_port: int = 443,
                  origin_host_header: Optional[str] = None,
                  priority: int = 1,
                  weight: int = 1000):
    from azure.mgmt.cdn.models import AFDOrigin

    # TO-DO: Add support for private link if RP support it.
    # TO-DO: Add enabled_state if RP fix the swagger mismatch issue.
    return client.create(resource_group_name,
                         profile_name,
                         origin_group_name,
                         origin_name,
                         AFDOrigin(
                             host_name=host_name,
                             http_port=http_port,
                             https_port=https_port,
                             origin_host_header=origin_host_header,
                             priority=priority,
                             weight=weight))


def create_afd_route(client: RoutesOperations,
                  resource_group_name: str,
                  profile_name: str,
                  endpoint_name: str,
                  route_name: str,
                  https_redirect: HttpsRedirect,
                  supported_protocols: List[AFDEndpointProtocols],
                  origin_group: str,
                  forwarding_protocol: ForwardingProtocol,                  
                  link_to_default_domain: LinkToDefaultDomain,
                  is_compression_enabled: bool=False,
                  content_types_to_compress: List[str] = None,
                  query_string_caching_behavior: QueryStringCachingBehavior = None,
                  custom_domains: List[str] = None,
                  origin_path: Optional[str] = None,
                  patterns_to_match: List[str] = ['/*'],
                  rule_sets: List[str] = None):

    from azure.mgmt.cdn.models import ResourceReference

    # TO-DO: Add support for private link if RP support it.
    # TO-DO: Add enabled_state if RP fix the swagger mismatch issue.
    
    formatted_custom_domains = []
    if custom_domains is not None:
        for custom_domain in custom_domains:
            if '/' not in custom_domain:
                    custom_domain = f'/subscriptions/{client.config.subscription_id}/resourceGroups/{resource_group_name}' \
                            f'/providers/Microsoft.Cdn/profiles/{profile_name}/customDomains/{custom_domain}'
            
            # If the origin is not an ID, assume it's a name and format it as an ID.
            formatted_custom_domains.append(ResourceReference(id=custom_domain))
    
    if '/' not in origin_group:
            origin_group = f'/subscriptions/{client.config.subscription_id}/resourceGroups/{resource_group_name}' \
                            f'/providers/Microsoft.Cdn/profiles/{profile_name}/originGroups/{origin_group}'

    from azure.mgmt.cdn.models import CompressionSettings
    compression_settings = CompressionSettings(
        content_types_to_compress=content_types_to_compress,
        is_compression_enabled=is_compression_enabled
    )

    return client.create(resource_group_name,
                         profile_name,
                         endpoint_name,
                         route_name,
                         Route(
                             custom_domains=formatted_custom_domains,
                             origin_path = origin_path,
                             patterns_to_match=patterns_to_match,
                             supported_protocols=supported_protocols,
                             https_redirect=https_redirect,
                             origin_group=ResourceReference(id=origin_group),
                             forwarding_protocol=forwarding_protocol,
                             rule_sets=rule_sets,
                             query_string_caching_behavior=query_string_caching_behavior,
                             compression_settings=compression_settings,
                             link_to_default_domain=link_to_default_domain))


def create_afd_rule_set(client: RuleSetsOperations,
                  resource_group_name: str,
                  profile_name: str,
                  rule_set_name: str):

    from azure.mgmt.cdn.models import RuleSet
    return client.create(resource_group_name,
                         profile_name,
                         rule_set_name,
                         rule_set=RuleSet())

def create_afd_rule(client: RulesOperations,
                  resource_group_name: str,
                  profile_name: str,
                  rule_set_name: str,
                  rule_name: str,
                  order: int):

    from azure.mgmt.cdn.models import Rule
    rule = Rule()
    return client.create(resource_group_name,
                         profile_name,
                         rule_set_name,
                         rule_name,
                         rule=rule)

# endregion
