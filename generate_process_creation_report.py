#!/usr/bin/env python3
"""
Script to generate a comprehensive report about data in
linux_data/sigma/events/linux/process_creation
"""

import os
import json
import yaml
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime


def load_properties(properties_file):
    """Load properties.yml file"""
    try:
        with open(properties_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load {properties_file}: {e}")
        return None


def analyze_directory(base_dir):
    """Analyze all subdirectories and their data"""
    results = []
    
    base_path = Path(base_dir)
    
    # Iterate through each subdirectory (detection rule)
    for rule_dir in sorted(base_path.iterdir()):
        if not rule_dir.is_dir():
            continue
            
        rule_name = rule_dir.name
        properties_file = rule_dir / "properties.yml"
        
        # Load properties
        properties = load_properties(properties_file)
        
        # Count JSON files
        json_files = list(rule_dir.glob("*.json"))
        total_events = len(json_files)
        
        # Categorize events
        match_events = len([f for f in json_files if "_Match_" in f.name])
        evasion_events = len([f for f in json_files if "_Evasion_" in f.name])
        other_events = total_events - match_events - evasion_events
        
        # Analyze event types from file names
        event_types = set()
        for json_file in json_files:
            # Extract event type from filename (e.g., Microsoft-Windows-Sysmon_1)
            parts = json_file.name.split('_')
            if len(parts) >= 2:
                event_types.add('_'.join(parts[:2]))
        
        # Analyze a sample JSON file for more details
        sigma_rule_title = None
        sigma_rule_id = None
        attack_ids = set()
        log_files = set()
        edited_fields = []
        
        if json_files:
            try:
                with open(json_files[0], 'r') as f:
                    sample_event = json.load(f)
                    labels = sample_event.get('labels', {})
                    sigma_rule_title = labels.get('sigma_rule_title')
                    sigma_rule_id = labels.get('sigma_rule_id')
                
                # Collect all attack IDs and log files
                for json_file in json_files:
                    try:
                        with open(json_file, 'r') as f:
                            event = json.load(f)
                            labels = event.get('labels', {})
                            if 'attack_id' in labels:
                                attack_ids.add(labels['attack_id'])
                            if 'log_file' in labels:
                                log_files.add(labels['log_file'])
                    except:
                        pass
                        
            except Exception as e:
                print(f"Warning: Could not analyze JSON files in {rule_dir}: {e}")
        
        # Get edited fields from properties
        if properties and 'edited_fields' in properties:
            edited_fields = properties['edited_fields']
        
        results.append({
            'rule_name': rule_name,
            'sigma_rule_title': sigma_rule_title or rule_name.replace('_', ' ').title(),
            'sigma_rule_id': sigma_rule_id,
            'total_events': total_events,
            'match_events': match_events,
            'evasion_events': evasion_events,
            'other_events': other_events,
            'event_types': sorted(event_types),
            'attack_ids': sorted(attack_ids, key=lambda x: int(x) if x.isdigit() else 0),
            'log_files': sorted(log_files),
            'properties': properties,
            'edited_fields': edited_fields
        })
    
    return results


def generate_markdown_report(results, output_file):
    """Generate a markdown report"""
    
    with open(output_file, 'w') as f:
        # Header
        f.write("# Linux Process Creation Data Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Total Detection Rules:** {len(results)}\n\n")
        
        # Summary Statistics
        f.write("## Summary Statistics\n\n")
        
        total_events = sum(r['total_events'] for r in results)
        total_match = sum(r['match_events'] for r in results)
        total_evasion = sum(r['evasion_events'] for r in results)
        
        f.write(f"- **Total Events:** {total_events:,}\n")
        f.write(f"- **Match Events:** {total_match:,}\n")
        f.write(f"- **Evasion Events:** {total_evasion:,}\n")
        f.write(f"- **Detection Rules with Events:** {len([r for r in results if r['total_events'] > 0])}\n")
        f.write(f"- **Detection Rules without Events:** {len([r for r in results if r['total_events'] == 0])}\n\n")
        
        # Event type distribution
        f.write("## Event Type Distribution\n\n")
        event_type_counter = Counter()
        for result in results:
            for event_type in result['event_types']:
                event_type_counter[event_type] += result['total_events']
        
        for event_type, count in event_type_counter.most_common():
            f.write(f"- **{event_type}:** {count:,} events\n")
        f.write("\n")
        
        # Detection rules with most events
        f.write("## Top 20 Detection Rules by Event Count\n\n")
        f.write("| Rank | Rule Name | Sigma Rule Title | Total | Match | Evasion |\n")
        f.write("|------|-----------|------------------|-------|-------|----------|\n")
        
        sorted_by_events = sorted(results, key=lambda x: x['total_events'], reverse=True)
        for i, result in enumerate(sorted_by_events[:20], 1):
            f.write(f"| {i} | `{result['rule_name']}` | {result['sigma_rule_title']} | "
                   f"{result['total_events']} | {result['match_events']} | {result['evasion_events']} |\n")
        f.write("\n")
        
        # Rules with evasion possible
        f.write("## Detection Rules with Evasion Analysis\n\n")
        evasion_possible = [r for r in results if r['properties'] and 
                           r['properties'].get('evasion_possible') == 'yes']
        f.write(f"**Rules with evasion_possible=yes:** {len(evasion_possible)}\n\n")
        
        if evasion_possible:
            f.write("| Rule Name | Total Events | Match | Evasion | Broken Rule |\n")
            f.write("|-----------|--------------|-------|---------|-------------|\n")
            for result in sorted(evasion_possible, key=lambda x: x['total_events'], reverse=True)[:20]:
                broken_rule = result['properties'].get('broken_rule', 'unknown')
                f.write(f"| `{result['rule_name']}` | {result['total_events']} | "
                       f"{result['match_events']} | {result['evasion_events']} | {broken_rule} |\n")
            f.write("\n")
        
        # Rules with no events
        f.write("## Detection Rules with No Events\n\n")
        no_events = [r for r in results if r['total_events'] == 0]
        f.write(f"**Total:** {len(no_events)} rules\n\n")
        
        if no_events:
            f.write("<details>\n<summary>Click to expand list</summary>\n\n")
            for result in sorted(no_events, key=lambda x: x['rule_name']):
                f.write(f"- `{result['rule_name']}`\n")
            f.write("\n</details>\n\n")
        
        # Edited fields analysis
        f.write("## Edited Fields Analysis\n\n")
        field_counter = Counter()
        for result in results:
            if result['edited_fields']:
                for field in result['edited_fields']:
                    field_counter[field] += 1
        
        if field_counter:
            f.write("| Field | Rules Count |\n")
            f.write("|-------|-------------|\n")
            for field, count in field_counter.most_common():
                f.write(f"| `{field}` | {count} |\n")
            f.write("\n")
        
        # Detailed breakdown by detection rule
        f.write("## Detailed Breakdown by Detection Rule\n\n")
        
        for result in sorted(results, key=lambda x: x['total_events'], reverse=True):
            f.write(f"### {result['sigma_rule_title']}\n\n")
            f.write(f"**Directory:** `{result['rule_name']}`\n\n")
            
            if result['sigma_rule_id']:
                f.write(f"**Sigma Rule ID:** `{result['sigma_rule_id']}`\n\n")
            
            # Event counts
            f.write("**Event Counts:**\n")
            f.write(f"- Total: {result['total_events']}\n")
            f.write(f"- Match Events: {result['match_events']}\n")
            f.write(f"- Evasion Events: {result['evasion_events']}\n")
            if result['other_events'] > 0:
                f.write(f"- Other Events: {result['other_events']}\n")
            f.write("\n")
            
            # Properties
            if result['properties']:
                f.write("**Properties:**\n")
                f.write(f"- Evasion Possible: {result['properties'].get('evasion_possible', 'N/A')}\n")
                f.write(f"- Broken Rule: {result['properties'].get('broken_rule', 'N/A')}\n")
                if result['edited_fields']:
                    f.write(f"- Edited Fields: {', '.join([f'`{field}`' for field in result['edited_fields']])}\n")
                if 'queried_event_types' in result['properties']:
                    f.write(f"- Queried Event Types: {', '.join(result['properties']['queried_event_types'])}\n")
                f.write("\n")
            
            # Attack IDs and log files
            if result['attack_ids']:
                f.write(f"**Attack IDs:** {', '.join(result['attack_ids'])}\n\n")
            
            if result['log_files']:
                f.write("**Log Files:**\n")
                for log_file in result['log_files']:
                    f.write(f"- `{log_file}`\n")
                f.write("\n")
            
            f.write("---\n\n")


def generate_json_summary(results, output_file):
    """Generate a JSON summary"""
    summary = {
        'generated_at': datetime.now().isoformat(),
        'total_rules': len(results),
        'total_events': sum(r['total_events'] for r in results),
        'total_match_events': sum(r['match_events'] for r in results),
        'total_evasion_events': sum(r['evasion_events'] for r in results),
        'rules': results
    }
    
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2)


def main():
    base_dir = "linux_data/sigma/events/linux/process_creation"
    
    print(f"Analyzing directory: {base_dir}")
    print("This may take a few moments...\n")
    
    # Check if directory exists
    if not os.path.exists(base_dir):
        print(f"ERROR: Directory not found: {base_dir}")
        return
    
    # Analyze the directory
    results = analyze_directory(base_dir)
    
    print(f"Found {len(results)} detection rules")
    print(f"Total events: {sum(r['total_events'] for r in results):,}\n")
    
    # Generate reports
    markdown_report = "process_creation_report.md"
    json_summary = "process_creation_summary.json"
    
    print(f"Generating markdown report: {markdown_report}")
    generate_markdown_report(results, markdown_report)
    
    print(f"Generating JSON summary: {json_summary}")
    generate_json_summary(results, json_summary)
    
    print("\n✓ Report generation complete!")
    print(f"  - Markdown report: {markdown_report}")
    print(f"  - JSON summary: {json_summary}")


if __name__ == "__main__":
    main()
