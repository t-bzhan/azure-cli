# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from typing import (Optional, List)


from azure.mgmt.cdn.models import (AFDEndpoint, HealthProbeRequestType, EnabledState, Route, LinkToDefaultDomain,
                                   AFDEndpointProtocols, HttpsRedirect, ForwardingProtocol, QueryStringCachingBehavior, RouteUpdateParameters,
                                   AFDOriginUpdateParameters, AFDOriginGroupUpdateParameters, SharedPrivateLinkResourceProperties)

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
                        origin_group_name: str,
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
                         origin_group_name,
                         afd_origin_group).result()

def update_afd_origin_group(client: AFDOriginGroupsOperations,
                        resource_group_name: str,
                        profile_name: str,
                        origin_group_name: str,
                        load_balancing_sample_size: int = None,
                        load_balancing_successful_samples_required: int = None,
                        load_balancing_additional_latency_in_milliseconds: int = None,
                        probe_request_type: HealthProbeRequestType = None,
                        probe_protocol: str = None,
                        probe_path: str = None,
                        probe_interval_in_seconds: int = 240):

    # Move these to the parameters list once support is added in RP:
    response_error_detection_error_types: Optional[str] = None
    response_error_detection_failover_threshold: Optional[int] = None
    response_error_detection_status_code_ranges: Optional[str] = None

    existing = client.get(resource_group_name, profile_name, origin_group_name)

    afd_origin_group_update_parameters = AFDOriginGroupUpdateParameters(load_balancing_settings=existing.load_balancing_settings,
                                                                        health_probe_settings=existing.health_probe_settings)

    if load_balancing_sample_size is not None:
        afd_origin_group_update_parameters.load_balancing_settings.sample_size = load_balancing_sample_size

    if load_balancing_sample_size is not None:
        afd_origin_group_update_parameters.load_balancing_settings.successful_samples_required = load_balancing_successful_samples_required

    if load_balancing_sample_size is not None:
        afd_origin_group_update_parameters.load_balancing_settings.additional_latency_in_milliseconds = load_balancing_additional_latency_in_milliseconds

    if probe_request_type is not None:
        afd_origin_group_update_parameters.health_probe_settings.probe_request_type = probe_request_type

    if probe_protocol is not None:
        afd_origin_group_update_parameters.health_probe_settings.probe_protocol = probe_protocol

    if probe_path is not None:
        afd_origin_group_update_parameters.health_probe_settings.probe_path = probe_path

    if probe_interval_in_seconds is not None:
        afd_origin_group_update_parameters.health_probe_settings.probe_interval_in_seconds = probe_interval_in_seconds

    return client.update(resource_group_name,
                         profile_name,
                         origin_group_name,
                         afd_origin_group_update_parameters).result()


def create_afd_origin(client: AFDOriginsOperations,
                  resource_group_name: str,
                  profile_name: str,
                  origin_group_name: str,
                  origin_name: str,
                  host_name: str,
                  enabled_state: EnabledState,
                  private_link: str,
                  private_link_location: str,
                  group_id: str,
                  request_message: str,
                  http_port: int = 80,
                  https_port: int = 443,
                  origin_host_header: Optional[str] = None,
                  priority: int = 1,
                  weight: int = 1000):

    from azure.mgmt.cdn.models import AFDOrigin
    from azure.mgmt.cdn.models import SharedPrivateLinkResourceProperties
    from azure.mgmt.cdn.models import ResourceReference

    # TO-DO: Add support for private link if RP support it.
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
                             weight=weight,
                             shared_private_link_resource=SharedPrivateLinkResourceProperties(
                                 private_link=ResourceReference(id=private_link),
                                 private_link_location=private_link_location,
                                 group_id=group_id,
                                 request_message=request_message
                             )))

def update_afd_origin(client: AFDOriginsOperations,
                  resource_group_name: str,
                  profile_name: str,
                  origin_group_name: str,
                  origin_name: str,
                  host_name: str = None,
                  enabled_state: EnabledState = None,
                  http_port: int = None,
                  https_port: int = None,
                  origin_host_header: Optional[str] = None,
                  priority: int = None,
                  weight: int = None,
                  private_link: str = None,
                  private_link_location: str = None,
                  group_id: str = None,
                  request_message: str = None):
    from azure.mgmt.cdn.models import SharedPrivateLinkResourceProperties
    from azure.mgmt.cdn.models import ResourceReference

    existing = client.get(resource_group_name, profile_name, origin_group_name, origin_name)
    shared_private_link_resource = existing.shared_private_link_resource
    if any(p is not None for p in [private_link, private_link_location, group_id, request_message]):
        shared_private_link_resource =  SharedPrivateLinkResourceProperties(
                                            private_link=ResourceReference(id=private_link),
                                            private_link_location=private_link_location,
                                            group_id=group_id,
                                            request_message=request_message
                                        )

    # TO-DO: Add enabled_state if RP fix the swagger mismatch issue.
    return client.update(resource_group_name,
                         profile_name,
                         origin_group_name,
                         origin_name,
                         AFDOriginUpdateParameters(
                             host_name=host_name,
                             http_port=http_port,
                             https_port=https_port,
                             origin_host_header=origin_host_header,
                             priority=priority,
                             weight=weight,
                             shared_private_link_resource=shared_private_link_resource))


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

    formatted_rule_sets = []
    if rule_sets is not None:        
        for rule_set in rule_sets:
            if '/' not in rule_set:
                    rule_set = f'/subscriptions/{client.config.subscription_id}/resourceGroups/{resource_group_name}' \
                            f'/providers/Microsoft.Cdn/profiles/{profile_name}/ruleSets/{rule_set}'
            
            formatted_rule_sets.append(ResourceReference(id=rule_set))

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
                             rule_sets=formatted_rule_sets,
                             query_string_caching_behavior=query_string_caching_behavior,
                             compression_settings=compression_settings,
                             link_to_default_domain=link_to_default_domain))

def update_afd_route(client: RoutesOperations,
                  resource_group_name: str,
                  profile_name: str,
                  endpoint_name: str,
                  route_name: str,
                  https_redirect: HttpsRedirect = None,
                  supported_protocols: List[AFDEndpointProtocols] = None,
                  origin_group: str = None,
                  forwarding_protocol: ForwardingProtocol = None,                  
                  link_to_default_domain: LinkToDefaultDomain = None,
                  is_compression_enabled: bool=False,
                  content_types_to_compress: List[str] = None,
                  query_string_caching_behavior: QueryStringCachingBehavior = None,
                  custom_domains: List[str] = None,
                  origin_path: Optional[str] = None,
                  patterns_to_match: List[str] = None,
                  rule_sets: List[str] = None):

    from azure.mgmt.cdn.models import ResourceReference

    # TO-DO: Add support for private link if RP support it.
    # TO-DO: Add enabled_state if RP fix the swagger mismatch issue.

    existing = client.get(resource_group_name,
                      profile_name,
                      endpoint_name,
                      route_name)

    routeUpdateParameters = RouteUpdateParameters(
                             custom_domains=existing.custom_domains,
                             origin_path = existing.origin_path if origin_path is None else origin_path,
                             patterns_to_match=existing.patterns_to_match if patterns_to_match is None else patterns_to_match,
                             supported_protocols=existing.supported_protocols if supported_protocols is None else supported_protocols,
                             https_redirect=existing.https_redirect if https_redirect is None else https_redirect,
                             origin_group=existing.origin_group,
                             forwarding_protocol=existing.forwarding_protocol if forwarding_protocol is None else forwarding_protocol,
                             rule_sets=existing.rule_sets,
                             query_string_caching_behavior=query_string_caching_behavior if query_string_caching_behavior else query_string_caching_behavior,
                             compression_settings=existing.compression_settings,
                             link_to_default_domain=link_to_default_domain if link_to_default_domain is None else link_to_default_domain)    
    
    if custom_domains is not None:
        formatted_custom_domains = []
        for custom_domain in custom_domains:
            if '/' not in custom_domain:
                    custom_domain = f'/subscriptions/{client.config.subscription_id}/resourceGroups/{resource_group_name}' \
                            f'/providers/Microsoft.Cdn/profiles/{profile_name}/customDomains/{custom_domain}'
            
            # If the origin is not an ID, assume it's a name and format it as an ID.
            formatted_custom_domains.append(ResourceReference(id=custom_domain))

        routeUpdateParameters.custom_domains = formatted_custom_domains
    
    if origin_group is not None:
        if '/' not in origin_group:
                origin_group = f'/subscriptions/{client.config.subscription_id}/resourceGroups/{resource_group_name}' \
                                f'/providers/Microsoft.Cdn/profiles/{profile_name}/originGroups/{origin_group}'

        routeUpdateParameters.origin_group = origin_group

    if rule_sets is not None:
        formatted_rule_sets = []
        for rule_set in rule_sets:
            if '/' not in rule_set:
                    rule_set = f'/subscriptions/{client.config.subscription_id}/resourceGroups/{resource_group_name}' \
                            f'/providers/Microsoft.Cdn/profiles/{profile_name}/ruleSets/{rule_set}'
            
            # If the origin is not an ID, assume it's a name and format it as an ID.
            formatted_rule_sets.append(ResourceReference(id=rule_set))

        routeUpdateParameters.rule_sets = formatted_rule_sets

    if is_compression_enabled is not None:
        from azure.mgmt.cdn.models import CompressionSettings
        compression_settings = CompressionSettings(
            content_types_to_compress=content_types_to_compress,
            is_compression_enabled=is_compression_enabled
        )
        routeUpdateParameters.compression_settings = compression_settings

    return client.update(resource_group_name,
                         profile_name,
                         endpoint_name,
                         route_name,
                         routeUpdateParameters)

def create_afd_rule_set(client: RuleSetsOperations,
                  resource_group_name: str,
                  profile_name: str,
                  rule_set_name: str):

    from azure.mgmt.cdn.models import RuleSet
    return client.create(resource_group_name,
                         profile_name,
                         rule_set_name,
                         rule_set=RuleSet())

# pylint: disable=too-many-locals
def create_afd_rule(client: RulesOperations, resource_group_name, profile_name, rule_set_name,
             order, rule_name, action_name, match_variable=None, operator=None,
             match_values=None, selector=None, negate_condition=None, transform=None,
             cache_behavior=None, cache_duration=None, header_action=None,
             header_name=None, header_value=None, query_string_behavior=None, query_parameters=None,
             redirect_type=None, redirect_protocol=None, custom_hostname=None, custom_path=None,
             custom_querystring=None, custom_fragment=None, source_pattern=None,
             destination=None, preserve_unmatched_path=None):
    from azure.mgmt.cdn.models import Rule
    from .custom import create_condition
    from .custom import create_action

    conditions = []
    condition = create_condition(match_variable, operator, match_values, selector, negate_condition, transform)
    if condition is not None:
        conditions.append(condition)
    
    actions = []
    action = create_action(action_name, cache_behavior, cache_duration, header_action, header_name,
                           header_value, query_string_behavior, query_parameters, redirect_type,
                           redirect_protocol, custom_hostname, custom_path, custom_querystring,
                           custom_fragment, source_pattern, destination, preserve_unmatched_path)
    if action is not None:
        actions.append(action)

    rule = Rule(
        name=rule_name,
        order=order,
        conditions=conditions,
        actions=actions
    )

    return client.create(resource_group_name,
                         profile_name,
                         rule_set_name,
                         rule_name,
                         rule=rule)

# endregion
