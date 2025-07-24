#!/usr/bin/env python3

import argparse
import os
import sys
import json
import requests
import time
import traceback

# Valid triage statuses
VALID_STATUSES = {
    'NOT_AFFECTED',
    'FALSE_POSITIVE',
    'IN_TRIAGE',
    'RESOLVED_WITH_PEDIGREE',
    'RESOLVED',
    'EXPLOITABLE'
}

# API Base URL - will be constructed from domain
def get_api_base_url():
    """
    Get the API base URL from the domain environment variable.
    """
    domain = os.getenv('FINITE_STATE_DOMAIN')
    if not domain:
        raise ValueError("FINITE_STATE_DOMAIN environment variable is required")
    return f"https://{domain}/api/public/v0"

def load_environment():
    """
    Load environment variables.
    Returns a tuple of (auth_token, domain)
    """
    # Get required environment variables
    auth_token = os.getenv('FINITE_STATE_AUTH_TOKEN')
    domain = os.getenv('FINITE_STATE_DOMAIN')
    
    # Check if all required variables are present
    missing_vars = []
    if not auth_token:
        missing_vars.append('FINITE_STATE_AUTH_TOKEN')
    if not domain:
        missing_vars.append('FINITE_STATE_DOMAIN')
    
    if missing_vars:
        print("Error: Missing required environment variables:", file=sys.stderr)
        for var in missing_vars:
            print(f"  - {var}", file=sys.stderr)
        print("\nPlease set these environment variables:", file=sys.stderr)
        print("  FINITE_STATE_AUTH_TOKEN: Your authentication token from the Finite State app")
        print("  FINITE_STATE_DOMAIN: Your organization's domain (e.g., 'your-org.finitestate.io')")
        sys.exit(1)
    
    return auth_token, domain

def get_findings(token, domain, artifact_id, component_name=None, component_version=None, debug=False):
    """
    Get findings for an artifact using the REST API.
    """
    url = f"{get_api_base_url()}/findings"
    headers = {
        "X-Authorization": token,
        "Accept": "application/json"
    }
    
    # Build filter expression using RSQL syntax
    filter_parts = [f"projectVersion=={artifact_id}"]
    if component_name:
        filter_parts.append(f"component=={component_name}")
    if component_version:
        filter_parts.append(f"version=={component_version}")
    
    params = {
        "filter": " and ".join(filter_parts),
        "sort": "detected:desc",  # Sort by detection date, newest first
        "limit": 10000  # Set a large limit to get all findings
    }
    
    if debug:
        print(f"\nDEBUG: Making API request to {url}")
        print(f"DEBUG: Headers: {json.dumps(headers, indent=2)}")
        print(f"DEBUG: Params: {json.dumps(params, indent=2)}")
    
    try:
        response = requests.get(url, headers=headers, params=params)
        if debug:
            print(f"DEBUG: Response status code: {response.status_code}")
            print(f"DEBUG: Response headers: {json.dumps(dict(response.headers), indent=2)}")
        
        if response.status_code != 200:
            if debug:
                print(f"DEBUG: Response body: {response.text}")
            raise Exception(f"Failed to get findings: Status {response.status_code} - {response.text}")
        
        findings = response.json()
        if debug:
            print(f"DEBUG: Found {len(findings)} findings")
        return findings
        
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"DEBUG: Request failed: {str(e)}")
        raise Exception(f"Failed to get findings: {str(e)}")
    except json.JSONDecodeError as e:
        if debug:
            print(f"DEBUG: Failed to parse response as JSON: {str(e)}")
            print(f"DEBUG: Response content: {response.text}")
        raise Exception(f"Failed to parse findings response: {str(e)}")
    except Exception as e:
        if debug:
            print(f"DEBUG: Unexpected error: {str(e)}")
        raise

def update_finding_status(token, domain, project_version_id, finding_id, status, justification=None, response=None, reason=None, debug=False):
    """
    Update a finding's status using the Swagger API.
    """
    # Set defaults if missing
    if not justification:
        print(f"[WARN] No justification provided for finding {finding_id}, using default: CODE_NOT_PRESENT")
        justification = "CODE_NOT_PRESENT"
    if not response:
        print(f"[WARN] No response provided for finding {finding_id}, using default: WILL_NOT_FIX")
        response = "WILL_NOT_FIX"
    data = {
        "status": status,
        "justification": justification,
        "response": response
    }
    if reason:
        data["reason"] = reason
    url = f"{get_api_base_url()}/findings/{project_version_id}/{finding_id}/status"
    headers = {
        "X-Authorization": token,
        "Content-Type": "application/json"
    }
    if debug:
        print(f"\nDEBUG: Making API request to {url}")
        print(f"DEBUG: Headers: {json.dumps(headers, indent=2)}")
        print(f"DEBUG: Data: {json.dumps(data, indent=2)}")
    print(f"Updating finding at URL: {url}")
    try:
        response_obj = requests.put(url, headers=headers, json=data)
        if debug:
            print(f"DEBUG: Response status code: {response_obj.status_code}")
            print(f"DEBUG: Response headers: {json.dumps(dict(response_obj.headers), indent=2)}")
        if response_obj.status_code not in (200, 204):
            if debug:
                print(f"DEBUG: Response body: {response_obj.text}")
            raise Exception(f"Failed to update finding status: Status {response_obj.status_code} - {response_obj.text}")
        return response_obj.json()
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"DEBUG: Request failed: {str(e)}")
        raise Exception(f"Failed to update finding status: {str(e)}")
    except json.JSONDecodeError as e:
        if debug:
            print(f"DEBUG: Failed to parse response as JSON: {str(e)}")
            print(f"DEBUG: Response content: {response_obj.text}")
        raise Exception(f"Failed to parse update response: {str(e)}")
    except Exception as e:
        if debug:
            print(f"DEBUG: Unexpected error: {str(e)}")
        raise

def get_status_value(status):
    """
    Extract the status value from a status object, which might be a string or a dictionary.
    Returns the status as a string, or 'UNTRIAGED' if no valid status is found.
    """
    print(f"\nDEBUG: get_status_value input: {status}")
    print(f"DEBUG: get_status_value input type: {type(status)}")
    
    if isinstance(status, dict):
        result = status.get('status', 'UNTRIAGED')
        print(f"DEBUG: Extracted status from dict: {result}")
        return result
    result = str(status) if status else 'UNTRIAGED'
    print(f"DEBUG: Converted status to string: {result}")
    return result

def get_component_key(component):
    """
    Extract component name and version from a component object, which might be a string or a dictionary.
    Returns a tuple of (name, version).
    """
    if isinstance(component, dict):
        name = component.get('name', 'Unknown')
        version = component.get('version', 'Unknown')
        return name, version
    return str(component), 'Unknown'

def view_findings(token, domain, artifact_id, component_name=None, component_version=None, debug=False):
    """
    View all findings and their triage status for a given artifact.
    Optionally filter by component name and version.
    """
    # Get all findings for the artifact
    findings = get_findings(token, domain, artifact_id, component_name, component_version, debug)
    
    if not findings:
        print("No findings found for the artifact")
        return
        
    if debug:
        print("\nDEBUG: Raw findings data:")
        print(json.dumps(findings, indent=2))
        print(f"\nTotal findings received: {len(findings)}")
    
    # Group findings by component
    component_findings = {}
    for finding in findings:
        if not finding or not isinstance(finding, dict):
            if debug:
                print(f"\nSkipping invalid finding: {finding}")
            continue
            
        component = finding.get('component')
        name, version = get_component_key(component)
        key = f"{name}:{version}"
        
        if key not in component_findings:
            component_findings[key] = []
        component_findings[key].append(finding)
    
    # Print findings grouped by component
    print(f"\nFindings for artifact {artifact_id}:")
    print("=" * 80)
    
    # Track status counts
    status_counts = {status: 0 for status in VALID_STATUSES}
    status_counts['UNTRIAGED'] = 0
    
    print("\nDEBUG: Valid statuses:", VALID_STATUSES)
    
    for component_key, component_findings_list in component_findings.items():
        # Split the key safely
        parts = component_key.split(':', 1)
        component_name = parts[0]
        component_version = parts[1] if len(parts) > 1 else 'Unknown'
        
        print(f"\nComponent: {component_name} (v{component_version})")
        print("-" * 80)
        
        for finding in component_findings_list:
            if not finding or not isinstance(finding, dict):
                continue
                
            finding_id = finding.get('findingId', 'Unknown')
            raw_status = finding.get('status')
            print(f"\nDEBUG: Processing finding {finding_id}")
            print(f"DEBUG: Raw status: {raw_status}")
            print(f"DEBUG: Raw status type: {type(raw_status)}")
            
            status = get_status_value(raw_status)
            print(f"DEBUG: Processed status: {status}")
            print(f"DEBUG: Processed status type: {type(status)}")
            print(f"DEBUG: VALID_STATUSES: {VALID_STATUSES} (type: {type(VALID_STATUSES)})")
            print(f"DEBUG: Is status in VALID_STATUSES? {status in VALID_STATUSES}")
            
            # Count statuses
            if status and status != 'UNTRIAGED' and status in VALID_STATUSES:
                print(f"DEBUG: Incrementing count for status: {status}")
                status_counts[status] += 1
            else:
                print(f"DEBUG: Incrementing UNTRIAGED count")
                status_counts['UNTRIAGED'] += 1
            
            print(f"Finding ID: {finding_id}")
            print(f"Status: {status}")
            if debug:
                print("Raw finding data:")
                print(json.dumps(finding, indent=2))
            print("-" * 40)
    
    # Print status summary
    print("\nStatus Summary:")
    print("-" * 40)
    for status, count in status_counts.items():
        if count > 0:
            print(f"{status}: {count}")

def get_component_triage_rules(token, domain, artifact_id, component_name=None, component_version=None, debug=False):
    """
    Get triage rules for specific components or all components from a source artifact.
    Returns a dictionary mapping component names and versions to their triage statuses and comments.
    """
    # Get all findings for the source artifact
    findings = get_findings(token, domain, artifact_id, component_name, component_version, debug)
    
    if not findings:
        print("No findings found for the artifact")
        return {}
        
    if debug:
        print("\nDEBUG: Processing findings for triage rules:")
        print(f"Total findings received: {len(findings)}")
    
    # Create a dictionary to store triage rules
    triage_rules = {}
    
    # Process each finding
    for finding in findings:
        if not finding or not isinstance(finding, dict):
            if debug:
                print(f"\nSkipping invalid finding: {finding}")
            continue
            
        status = get_status_value(finding.get('status'))
        component = finding.get('component')
        name, version = get_component_key(component)
        comment = finding.get('comment') if finding.get('comment') else None
        justification = finding.get('justification') if finding.get('justification') else None
        response = finding.get('response') if finding.get('response') else None
        # Create rule with string status
        rule = {
            'status': status,
            'finding_id': finding.get('findingId'),
            'vulnerability': finding.get('vulnerabilityId') or finding.get('findingId'),
            'title': finding.get('title', 'Unknown'),
            'description': finding.get('description', ''),
            'comment': comment
        }
        if justification:
            rule['justification'] = justification
        if response:
            rule['response'] = response
                
        if debug:
            print(f"\nProcessing finding:")
            print(f"ID: {finding.get('findingId', 'Unknown')}")
            print(f"Status: {status}")
            print(f"Component: {name} v{version}")
            print(f"Vulnerability: {finding.get('vulnerabilityId', 'Unknown')}")
            print(f"Comment: {comment}")
        
        # Only process findings that have been triaged with valid status
        if debug:
            print(f"DEBUG: VALID_STATUSES: {VALID_STATUSES} (type: {type(VALID_STATUSES)})")
        if status and status != 'UNTRIAGED' and status in VALID_STATUSES:
            if name:
                # Use component name as key if no version specified
                key = f"{name}:{version}" if version else name
                if key not in triage_rules:
                    triage_rules[key] = []
                
                # Get vulnerability ID from the finding
                vulnerability_id = finding.get('vulnerabilityId') or finding.get('findingId')
                
                # Create rule with string status
                rule = {
                    'status': status,
                    'finding_id': finding.get('findingId'),
                    'vulnerability': vulnerability_id,
                    'title': finding.get('title', 'Unknown'),
                    'description': finding.get('description', ''),
                    'comment': comment
                }
                
                triage_rules[key].append(rule)
                if debug:
                    print(f"Added to triage rules for {key}")
                    print(f"Status: {status}")
                    print(f"Vulnerability: {vulnerability_id}")
        elif debug:
            print("Skipping - no valid status")
    
    if debug:
        print("\nDEBUG: Final triage rules:")
        print(json.dumps(triage_rules, indent=2))
        print("\nComponent matching summary:")
        for key, rules in triage_rules.items():
            print(f"\n{key}:")
            for rule in rules:
                print(f"  - {rule['vulnerability']}: {rule['status']} (comment: {rule['comment']})")
    
    return triage_rules

def apply_triage_rules(token, domain, target_artifact_id, triage_rules, source_artifact_id, dry_run=False, debug=False):
    """
    Apply triage rules to findings in the target artifact.
    If dry_run is True, only print what would be changed without making changes.
    """
    # Get all findings for the target artifact
    target_findings = get_findings(token, domain, target_artifact_id, debug=debug)
    
    if not target_findings:
        print("No findings found for the target artifact")
        return
        
    if debug:
        print("\nDEBUG: Processing target findings:")
        print(f"Total target findings: {len(target_findings)}")
    
    # Track which findings we've updated
    updated_findings = []
    unmatched_findings = []
    
    # Process each finding in the target artifact
    for finding in target_findings:
        if not finding or not isinstance(finding, dict):
            if debug:
                print(f"\nSkipping invalid finding: {finding}")
            continue
            
        component = finding.get('component')
        name, version = get_component_key(component)
        vulnerability_id = finding.get('vulnerabilityId') or finding.get('findingId')
        finding_id = finding.get('id')  # Use the actual finding ID
        
        if debug:
            print(f"\nProcessing target finding:")
            print(f"Finding ID: {finding_id}")
            print(f"Vulnerability ID: {vulnerability_id}")
            print(f"Component: {name} v{version}")
            print(f"Raw finding data: {json.dumps(finding, indent=2)}")
        
        if name:
            # Use component name as key if no version specified
            key = f"{name}:{version}" if version else name
            
            # If we have a matching rule, apply it
            if key in triage_rules:
                if debug:
                    print(f"Found matching component: {key}")
                    print("Available rules:")
                    for rule in triage_rules[key]:
                        print(f"  - {rule['vulnerability']}: {rule['status']} (comment: {rule['comment']})")
                
                # Find the matching vulnerability in the rules
                matching_rule = None
                for rule in triage_rules[key]:
                    if rule['vulnerability'] == vulnerability_id:
                        matching_rule = rule
                        if debug:
                            print(f"Found matching vulnerability: {vulnerability_id}")
                        break
                
                if not matching_rule and debug:
                    print(f"No matching vulnerability found for {vulnerability_id}")
                    unmatched_findings.append({
                        'component': name,
                        'version': version,
                        'vulnerability': vulnerability_id
                    })
                
                # Get current status, handling dictionary case
                current_status = get_status_value(finding.get('status'))
                current_comment = finding.get('comment') if finding.get('comment') else None
                source_comment = matching_rule['comment'] if matching_rule else None
                
                status_changed = matching_rule and current_status != matching_rule['status']
                comment_changed = matching_rule and current_comment != source_comment
                
                should_update = False
                # When building update_payload, add justification, response, and reason fields if present
                update_payload = {
                    'id': finding_id,
                    'status': matching_rule['status'] if matching_rule else None,
                    'component': name,
                    'version': version,
                    'vulnerability': vulnerability_id
                }
                if matching_rule:
                    if 'justification' in matching_rule and matching_rule['justification']:
                        update_payload['justification'] = matching_rule['justification']
                    if 'response' in matching_rule and matching_rule['response']:
                        update_payload['response'] = matching_rule['response']
                # Place comment in reason
                if source_comment is not None:
                    update_payload['reason'] = source_comment
                
                if status_changed:
                    should_update = True
                    # If source has a comment, use it. If not, and audit is set, and both source and target have no comment, add traceability comment
                    if source_comment is not None:
                        update_payload['comment'] = source_comment
                
                if should_update:
                    updated_findings.append(update_payload)
                    if debug or dry_run:
                        print(f"\nWould update finding:")
                        print(f"Finding ID: {finding_id}")
                        print(f"Vulnerability ID: {vulnerability_id}")
                        print(f"Component: {name} v{version}")
                        print(f"Current status: {current_status}")
                        print(f"Current comment: {current_comment}")
                        print(f"New status: {update_payload.get('status')}")
                        print(f"New comment: {update_payload.get('comment')}")
                        if not update_payload.get('comment') and not current_comment:
                            print("(Traceability comment will be added)")
                        print("---")
            elif debug:
                print(f"No matching component found for {key}")
                unmatched_findings.append({
                    'component': name,
                    'version': version,
                    'vulnerability': vulnerability_id
                })
    
    # Print what would be changed
    if updated_findings:
        print("\nThe following changes would be made:")
        for update in updated_findings:
            print(f"Finding ID: {update['id']}")
            print(f"Vulnerability ID: {update['vulnerability']}")
            print(f"Component: {update['component']} (v{update['version']})")
            print(f"Status: {update.get('status')}")
            # Show old and new justification, response, and reason (comment) for dry run
            old_justification = None
            old_response = None
            old_reason = None
            for finding in target_findings:
                if finding.get('id') == update['id']:
                    old_justification = finding.get('justification')
                    old_response = finding.get('response')
                    old_reason = finding.get('reason') if finding.get('reason') else finding.get('comment')
                    break
            new_justification = update.get('justification') or "CODE_NOT_PRESENT"
            new_response = update.get('response') or "WILL_NOT_FIX"
            new_reason = update.get('reason')
            if new_reason is None and source_comment is not None:
                new_reason = source_comment
            print(f"Old justification: {old_justification}")
            print(f"New justification: {new_justification}")
            print(f"Old response: {old_response}")
            print(f"New response: {new_response}")
            print(f"Old reason: {old_reason}")
            print(f"New reason: {new_reason}")
            print("---")
        
        if not dry_run:
            if debug:
                print(f"\nDEBUG: Using source artifact ID: {source_artifact_id}")
            
            # Process updates in batches
            failed_updates = []
            for update in updated_findings:
                if update['id'] and update['status']:
                    if debug:
                        print(f"\nDEBUG: Updating finding {update['id']}:")
                        print(f"Vulnerability ID: {update['vulnerability']}")
                        print(f"Status: {update['status']}")
                        print(f"Source artifact ID: {source_artifact_id}")
                    
                    # Try to apply the update with retries
                    max_retries = 3
                    retry_delay = 2  # seconds
                    success = False
                    
                    for attempt in range(max_retries):
                        try:
                            # Apply the update
                            update_finding_status(
                                token=token,
                                domain=domain,
                                project_version_id=target_artifact_id,
                                finding_id=update['id'],
                                status=update['status'],
                                justification=update.get('justification'),
                                response=update.get('response'),
                                reason=update.get('reason'),
                                debug=debug
                            )
                            success = True
                            break
                        except Exception as e:
                            if attempt < max_retries - 1:
                                if debug:
                                    print(f"Attempt {attempt + 1} failed: {str(e)}")
                                    print(f"Retrying in {retry_delay} seconds...")
                                time.sleep(retry_delay)
                                retry_delay *= 2  # Exponential backoff
                            else:
                                print(f"Failed to update finding {update['id']} after {max_retries} attempts: {str(e)}", file=sys.stderr)
                                failed_updates.append(update)
                    
                    if success and debug:
                        print(f"Successfully updated finding {update['id']}")
            
            # Print summary
            successful_updates = len(updated_findings) - len(failed_updates)
            print(f"\nUpdated {successful_updates} findings in target artifact")
            
            if failed_updates:
                print("\nFailed to update the following findings:")
                for update in failed_updates:
                    print(f"Finding ID: {update['id']}")
                    print(f"Vulnerability ID: {update['vulnerability']}")
                    print(f"Component: {update['component']} (v{update['version']})")
                    print(f"Status: {update.get('status')}")
                    print(f"New comment: {update.get('comment')}")
                    print("---")
        else:
            print(f"\nDry run: Would update {len(updated_findings)} findings in target artifact")
    else:
        print("No findings needed to be updated")
    
    # Print summary of unmatched findings
    if unmatched_findings and debug:
        print("\nUnmatched findings:")
        print("=" * 80)
        for finding in unmatched_findings:
            print(f"Component: {finding['component']} (v{finding['version']})")
            print(f"Vulnerability: {finding['vulnerability']}")
            print("---")

def main():
    parser = argparse.ArgumentParser(description='Replicate triage decisions from one artifact to another')
    parser.add_argument('source_artifact', nargs='?', help='ID of the source artifact')
    parser.add_argument('target_artifact', nargs='?', help='ID of the target artifact')
    parser.add_argument('--view', action='store_true', help='View findings for an artifact instead of replicating triage')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be changed without making changes')
    parser.add_argument('--component', help='Specific component name to replicate triage for')
    parser.add_argument('--version', help='Specific component version to replicate triage for')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    try:
        # Load environment variables
        auth_token, domain = load_environment()
        
        # Always enable debug output for now to help diagnose issues
        # args.debug = True
        
        if args.view:
            if not args.source_artifact:
                print("Error: Artifact ID is required when using --view", file=sys.stderr)
                sys.exit(1)
            view_findings(auth_token, domain, args.source_artifact, args.component, args.version, args.debug)
        else:
            if not args.source_artifact or not args.target_artifact:
                print("Error: Both source and target artifact IDs are required for triage replication", file=sys.stderr)
                sys.exit(1)
                
            # Get triage rules from source artifact
            print(f"Getting triage rules from source artifact {args.source_artifact}...")
            triage_rules = get_component_triage_rules(
                auth_token, 
                domain, 
                args.source_artifact,
                args.component,
                args.version,
                args.debug
            )
            
            if not triage_rules:
                print("No triage rules found matching the specified criteria")
                sys.exit(0)
                
            # Apply triage rules to target artifact
            print(f"Applying triage rules to target artifact {args.target_artifact}...")
            apply_triage_rules(auth_token, domain, args.target_artifact, triage_rules, args.source_artifact, args.dry_run, args.debug)
        
    except TypeError as e:
        print(f"TypeError: {e}")
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main() 