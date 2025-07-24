#!/usr/bin/env python3

import argparse
import os
import sys
import json
import requests
import time

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

def get_findings(token, domain, artifact_id, component_name=None, component_version=None):
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
    
    print(f"\nDEBUG: Making API request to {url}")
    print(f"DEBUG: Headers: {json.dumps(headers, indent=2)}")
    print(f"DEBUG: Params: {json.dumps(params, indent=2)}")
    
    try:
        response = requests.get(url, headers=headers, params=params)
        print(f"DEBUG: Response status code: {response.status_code}")
        print(f"DEBUG: Response headers: {json.dumps(dict(response.headers), indent=2)}")
        
        if response.status_code != 200:
            print(f"DEBUG: Response body: {response.text}")
            raise Exception(f"Failed to get findings: Status {response.status_code} - {response.text}")
        
        findings = response.json()
        print(f"DEBUG: Found {len(findings)} findings")
        return findings
        
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: Request failed: {str(e)}")
        raise Exception(f"Failed to get findings: {str(e)}")
    except json.JSONDecodeError as e:
        print(f"DEBUG: Failed to parse response as JSON: {str(e)}")
        print(f"DEBUG: Response content: {response.text}")
        raise Exception(f"Failed to parse findings response: {str(e)}")
    except Exception as e:
        print(f"DEBUG: Unexpected error: {str(e)}")
        raise

def update_finding_status(token, domain, finding_id, status, justification=None, comment=None):
    """
    Update a finding's status using the Swagger API.
    """
    url = f"{get_api_base_url()}/findings/{finding_id}/status"
    headers = {
        "X-Authorization": token,
        "Content-Type": "application/json"
    }
    
    # Handle status that might be a dictionary
    if isinstance(status, dict):
        status = status.get('status')
    
    # Prepare the request body according to the Swagger API spec
    data = {
        "status": status,
        "comment": comment or "",
        "justification": justification or ""
    }
    
    print(f"\nDEBUG: Making API request to {url}")
    print(f"DEBUG: Headers: {json.dumps(headers, indent=2)}")
    print(f"DEBUG: Data: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.put(url, headers=headers, json=data)
        print(f"DEBUG: Response status code: {response.status_code}")
        print(f"DEBUG: Response headers: {json.dumps(dict(response.headers), indent=2)}")
        
        if response.status_code != 200:
            print(f"DEBUG: Response body: {response.text}")
            raise Exception(f"Failed to update finding status: Status {response.status_code} - {response.text}")
        
        return response.json()
        
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: Request failed: {str(e)}")
        raise Exception(f"Failed to update finding status: {str(e)}")
    except json.JSONDecodeError as e:
        print(f"DEBUG: Failed to parse response as JSON: {str(e)}")
        print(f"DEBUG: Response content: {response.text}")
        raise Exception(f"Failed to parse update response: {str(e)}")
    except Exception as e:
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
    findings = get_findings(token, domain, artifact_id, component_name, component_version)
    
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
            print(f"DEBUG: Is status in VALID_STATUSES? {status in VALID_STATUSES}")
            
            # Count statuses
            if status in VALID_STATUSES:
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
    Returns a dictionary mapping component names and versions to their triage statuses.
    """
    # Get all findings for the source artifact
    findings = get_findings(token, domain, artifact_id, component_name, component_version)
    
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
        
        if debug:
            print(f"\nProcessing finding:")
            print(f"ID: {finding.get('findingId', 'Unknown')}")
            print(f"Status: {status}")
            print(f"Component: {name} v{version}")
            print(f"Raw finding data: {json.dumps(finding, indent=2)}")
        
        # Only process findings that have been triaged with valid status
        if status in VALID_STATUSES:
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
                    'description': finding.get('description', '')
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
                print(f"  - {rule['vulnerability']}: {rule['status']}")
    
    return triage_rules

def apply_triage_rules(token, domain, target_artifact_id, triage_rules, source_artifact_id, dry_run=False, debug=False):
    """
    Apply triage rules to findings in the target artifact.
    If dry_run is True, only print what would be changed without making changes.
    """
    # Get all findings for the target artifact
    target_findings = get_findings(token, domain, target_artifact_id)
    
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
                        print(f"  - {rule['vulnerability']}: {rule['status']}")
                
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
                
                if matching_rule and current_status != matching_rule['status']:
                    if not finding_id:
                        if debug:
                            print(f"\nSkipping finding - no valid ID")
                        continue
                        
                    update = {
                        'id': finding_id,
                        'status': matching_rule['status'],
                        'component': name,
                        'version': version,
                        'vulnerability': vulnerability_id
                    }
                    updated_findings.append(update)
                    if debug:
                        print(f"\nWould update finding:")
                        print(f"Finding ID: {finding_id}")
                        print(f"Vulnerability ID: {vulnerability_id}")
                        print(f"Component: {name} v{version}")
                        print(f"Current status: {current_status}")
                        print(f"New status: {matching_rule['status']}")
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
            print(f"Status: {update['status']}")
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
                                finding_id=update['id'],
                                status=update['status'],
                                justification='COMPONENT_NOT_PRESENT' if update['status'] == 'NOT_AFFECTED' else None,
                                comment=f'Replicated from source artifact {source_artifact_id}'
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
                    print(f"Status: {update['status']}")
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
        args.debug = True
        
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
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main() 