#!/usr/bin/env python3
"""
Download rebuilt binaries from GitHub Actions and update demo/out submodule.

This script downloads binary artifacts from the "Verify Binaries" workflows
and places them in the correct locations in demo/out/{compiler}/.

Usage:
    # Download from latest successful workflow run
    python scripts/download_binaries_from_ci.py

    # Download from specific run ID
    python scripts/download_binaries_from_ci.py --run-id 12345678

    # Download specific compiler only
    python scripts/download_binaries_from_ci.py --compiler clang-19

    # List available runs without downloading
    python scripts/download_binaries_from_ci.py --list
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run_gh_command(args, check=True):
    """Run gh CLI command and return output."""
    try:
        result = subprocess.run(
            ['gh'] + args,
            capture_output=True,
            text=True,
            check=check
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running gh command: {e.stderr}", file=sys.stderr)
        if check:
            raise
        return None


def list_workflow_runs(workflow_name_pattern, limit=10):
    """List recent workflow runs matching pattern."""
    output = run_gh_command([
        'run', 'list',
        '--json', 'databaseId,name,conclusion,headBranch,createdAt',
        '--limit', str(limit)
    ])
    
    if not output:
        return []
    
    runs = json.loads(output)
    
    # Filter by workflow name pattern
    filtered = [
        r for r in runs 
        if workflow_name_pattern.lower() in r['name'].lower()
    ]
    
    return filtered


def get_run_artifacts(run_id):
    """Get artifacts for a specific run."""
    output = run_gh_command([
        'run', 'view', str(run_id),
        '--json', 'artifacts'
    ])
    
    if not output:
        return []
    
    data = json.loads(output)
    return data.get('artifacts', [])


def download_artifact(run_id, artifact_name, dest_dir):
    """Download artifact from a run to destination directory."""
    print(f"  Downloading artifact: {artifact_name}")
    
    result = run_gh_command([
        'run', 'download', str(run_id),
        '-n', artifact_name,
        '-D', str(dest_dir)
    ], check=False)
    
    return result is not None


def extract_compiler_from_artifact(artifact_name):
    """Extract compiler name from artifact name.
    
    Examples:
        rebuilt-binaries-clang-19 -> clang-19
        rebuilt-binaries-clang-20 -> clang-20
        rebuilt-binaries-msvc-14.44 -> msvc-14.44
    """
    if artifact_name.startswith('rebuilt-binaries-'):
        return artifact_name.replace('rebuilt-binaries-', '')
    return None


def update_binaries(compiler, temp_dir, out_dir):
    """Copy downloaded binaries to demo/out/{compiler}/ directory."""
    src_dir = Path(temp_dir)
    dest_dir = Path(out_dir) / compiler
    
    if not src_dir.exists():
        print(f"  ✗ Source directory not found: {src_dir}", file=sys.stderr)
        return False
    
    # Ensure destination exists
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy all .exe and .pdb files
    files_copied = 0
    for pattern in ['*.exe', '*.pdb']:
        for src_file in src_dir.glob(pattern):
            dest_file = dest_dir / src_file.name
            print(f"  Copying: {src_file.name} -> {dest_file.relative_to(out_dir.parent)}")
            shutil.copy2(src_file, dest_file)
            files_copied += 1
    
    if files_copied == 0:
        print(f"  ⚠ Warning: No .exe or .pdb files found in {src_dir}", file=sys.stderr)
        return False
    
    print(f"  ✓ Copied {files_copied} files to {dest_dir.relative_to(out_dir.parent)}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Download rebuilt binaries from GitHub Actions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--run-id',
        type=int,
        help='Specific workflow run ID to download from'
    )
    parser.add_argument(
        '--compiler',
        choices=['clang-19', 'clang-20', 'msvc-14.44'],
        help='Download binaries for specific compiler only'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List available workflow runs without downloading'
    )
    parser.add_argument(
        '--branch',
        default='feature/compiler-matrix-submodule',
        help='Branch to download from (default: feature/compiler-matrix-submodule)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=20,
        help='Number of recent runs to check (default: 20)'
    )
    
    args = parser.parse_args()
    
    # Verify we're in the right directory
    script_dir = Path(__file__).parent
    demo_dir = script_dir.parent
    out_dir = demo_dir / 'out'
    
    if not demo_dir.exists() or demo_dir.name != 'demo':
        print("Error: This script must be run from demo/scripts/", file=sys.stderr)
        return 1
    
    print("=" * 80)
    print("GitHub Actions Binary Downloader")
    print("=" * 80)
    print()
    
    # List workflow runs
    print(f"Searching for 'Verify Binaries' workflow runs on branch: {args.branch}")
    runs = list_workflow_runs('Verify Binaries', limit=args.limit)
    
    if not runs:
        print("No workflow runs found", file=sys.stderr)
        return 1
    
    # Filter by branch if specified
    branch_runs = [r for r in runs if r.get('headBranch') == args.branch]
    
    if not branch_runs:
        print(f"No runs found for branch: {args.branch}", file=sys.stderr)
        print(f"\nAvailable branches in recent runs:")
        branches = set(r.get('headBranch', 'unknown') for r in runs)
        for branch in sorted(branches):
            print(f"  - {branch}")
        return 1
    
    print(f"Found {len(branch_runs)} workflow runs")
    print()
    
    # If --list, just show the runs
    if args.list:
        print("Recent workflow runs:")
        print("-" * 80)
        for run in branch_runs[:10]:
            status = run.get('conclusion', 'unknown').upper()
            run_id = run['databaseId']
            name = run['name']
            print(f"  [{status:8}] Run {run_id}: {name}")
        print()
        print("Use --run-id <id> to download from a specific run")
        return 0
    
    # Determine which run to use
    if args.run_id:
        # Use specified run
        run_id = args.run_id
        print(f"Using specified run ID: {run_id}")
    else:
        # Find latest successful run
        successful_runs = [r for r in branch_runs if r.get('conclusion') == 'success']
        
        if not successful_runs:
            print("No successful runs found. Recent runs:", file=sys.stderr)
            for run in branch_runs[:5]:
                status = run.get('conclusion', 'unknown')
                run_id = run['databaseId']
                name = run['name']
                print(f"  [{status}] Run {run_id}: {name}", file=sys.stderr)
            return 1
        
        # Use most recent successful run
        run_id = successful_runs[0]['databaseId']
        print(f"Using latest successful run: {run_id}")
    
    print()
    
    # Get artifacts for the run
    print(f"Fetching artifacts for run {run_id}...")
    
    # We need to find all "Verify Binaries" runs with this approximate time
    # because each compiler has its own workflow run
    all_runs = list_workflow_runs('Verify Binaries', limit=50)
    
    # Group by approximate time (within 1 minute of each other)
    target_run = next((r for r in all_runs if r['databaseId'] == run_id), None)
    if not target_run:
        print(f"Error: Run {run_id} not found", file=sys.stderr)
        return 1
    
    from datetime import datetime, timedelta
    target_time = datetime.fromisoformat(target_run['createdAt'].replace('Z', '+00:00'))
    
    # Find all runs within 2 minutes
    related_runs = [
        r for r in all_runs
        if 'Verify Binaries' in r['name']
        and abs((datetime.fromisoformat(r['createdAt'].replace('Z', '+00:00')) - target_time).total_seconds()) < 120
        and r.get('headBranch') == args.branch
    ]
    
    print(f"Found {len(related_runs)} related workflow runs from same trigger")
    print()
    
    # Download artifacts from all related runs
    downloaded_compilers = []
    
    with tempfile.TemporaryDirectory() as temp_base:
        for run in related_runs:
            run_id_current = run['databaseId']
            run_name = run['name']
            
            # Extract compiler from run name
            # "Verify Binaries (clang-19)" -> clang-19
            if '(' in run_name and ')' in run_name:
                compiler_name = run_name.split('(')[1].split(')')[0]
            else:
                continue
            
            # Skip if user specified a different compiler
            if args.compiler and compiler_name != args.compiler:
                continue
            
            print(f"Processing: {run_name} (Run {run_id_current})")
            
            # Look for rebuilt-binaries artifact
            artifact_name = f"rebuilt-binaries-{compiler_name}"
            
            temp_dir = Path(temp_base) / compiler_name
            temp_dir.mkdir(exist_ok=True)
            
            if download_artifact(run_id_current, artifact_name, temp_dir):
                if update_binaries(compiler_name, temp_dir, out_dir):
                    downloaded_compilers.append(compiler_name)
                print()
            else:
                print(f"  ⚠ Warning: Could not download artifact for {compiler_name}")
                print()
    
    # Summary
    print("=" * 80)
    print("Download Summary")
    print("=" * 80)
    print()
    
    if downloaded_compilers:
        print(f"✓ Successfully downloaded binaries for {len(downloaded_compilers)} compiler(s):")
        for compiler in sorted(downloaded_compilers):
            print(f"  - {compiler}")
        print()
        print("Next steps:")
        print("  1. Verify binaries:")
        print(f"     ls -lh demo/out/{{{'|'.join(downloaded_compilers)}}}/")
        print()
        print("  2. Commit to submodule:")
        print("     cd demo/out")
        print("     git status")
        print(f"     git add {' '.join(downloaded_compilers)}/*.exe {' '.join(downloaded_compilers)}/*.pdb")
        print("     git commit -m 'build: Update binaries from CI'")
        print("     git push")
        print()
        print("  3. Update main repo:")
        print("     cd ../..")
        print("     git add demo/out")
        print("     git commit -m 'chore: Update demo binaries submodule'")
        print("     git push")
        print()
        return 0
    else:
        print("✗ No binaries were downloaded", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
