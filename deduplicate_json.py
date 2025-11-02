#!/usr/bin/env python3
"""
Deduplicate JSON objects based on Image name, Resource name, and CVE name.

This script removes duplicate entries from a JSON array where duplicates are
identified by having the same combination of:
- Image name
- Resource name
- CVE name
"""

import json
import sys
from typing import List, Dict, Any


def deduplicate_json(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicates from a list of JSON objects based on Image name,
    Resource name, and CVE name.
    
    Args:
        data: List of JSON objects/dictionaries
        
    Returns:
        List of deduplicated JSON objects (first occurrence is kept)
    """
    seen = set()
    deduplicated = []
    
    for item in data:
        # Extract the three key fields
        image_name = item.get("Image name", "")
        resource_name = item.get("Resource name", "")
        cve_name = item.get("CVE name", "")
        
        # Create a unique key from the three fields
        key = (image_name, resource_name, cve_name)
        
        # Only add if we haven't seen this combination before
        if key not in seen:
            seen.add(key)
            deduplicated.append(item)
    
    return deduplicated


def main():
    """Main function to handle command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Deduplicate JSON objects by Image name, Resource name, and CVE name"
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        type=str,
        help="Input JSON file (default: read from stdin)",
        default=None
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output JSON file (default: write to stdout)",
        default=None
    )
    parser.add_argument(
        "--indent",
        type=int,
        help="JSON indentation level (default: 2)",
        default=2
    )
    
    args = parser.parse_args()
    
    # Read input
    if args.input_file:
        try:
            with open(args.input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"Error: File '{args.input_file}' not found.", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in file '{args.input_file}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Ensure data is a list
    if not isinstance(data, list):
        print("Error: Input must be a JSON array.", file=sys.stderr)
        sys.exit(1)
    
    # Deduplicate
    original_count = len(data)
    deduplicated = deduplicate_json(data)
    new_count = len(deduplicated)
    
    # Write output
    output_json = json.dumps(deduplicated, indent=args.indent, ensure_ascii=False)
    
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output_json)
            print(f"Deduplicated {original_count} items to {new_count} items. "
                  f"Removed {original_count - new_count} duplicates.", file=sys.stderr)
        except IOError as e:
            print(f"Error writing to file '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_json)
        print(f"\n# Deduplicated {original_count} items to {new_count} items. "
              f"Removed {original_count - new_count} duplicates.", file=sys.stderr)


if __name__ == "__main__":
    main()
