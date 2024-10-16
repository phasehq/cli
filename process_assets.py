import os
import argparse
import hashlib
import zipfile
from pathlib import Path

def sha256sum(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            h.update(block)
    return h.hexdigest()

def process_artifacts(input_dir, output_dir, version):
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Define expected files and their source locations here
    assets = [
        ('phase_cli_linux_amd64_{version}.apk', 'phase-apk'),
        ('phase_cli_linux_amd64_{version}.deb', 'phase-deb'),
        ('phase_cli_linux_amd64_{version}.rpm', 'phase-rpm'),
        ('phase_cli_linux_amd64_{version}.zip', 'Linux-binary'),
        ('phase_cli_linux_arm64_{version}.zip', 'Linux-binary-arm64'),
        ('phase_cli_macos_amd64_{version}.zip', 'macOS-amd64-binary'),
        ('phase_cli_macos_arm64_{version}.zip', 'macOS-arm64-binary'),
        ('phase_cli_windows_amd64_{version}.zip', 'Windows-binary'),
    ]

    for output_file, source_dir in assets:
        output_file = output_file.format(version=version)
        source_path = input_dir / source_dir
        output_path = output_dir / output_file

        if source_path.is_dir():
            # If it's a directory, zip it
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file in source_path.rglob('*'):
                    if file.is_file():
                        zipf.write(file, file.relative_to(source_path))
        elif source_path.is_file():
            # If it's a file, just copy it
            source_path.rename(output_path)
        else:
            print(f"Warning: Source not found for {output_file}")
            continue

        # Generate SHA256 hash
        hash_file = output_path.with_name(f"{output_path.name}.sha256")
        hash_value = sha256sum(output_path)
        hash_file.write_text(f'{hash_value} {output_file}\n')

def main():
    parser = argparse.ArgumentParser(description='Process Phase CLI artifacts')
    parser.add_argument('input_dir', help='Input directory containing artifacts')
    parser.add_argument('output_dir', help='Output directory for processed artifacts')
    parser.add_argument('--version', required=True, help='Version number for file names')
    
    args = parser.parse_args()
    
    process_artifacts(args.input_dir, args.output_dir, args.version)
    print(f"Artifacts processed and saved to {args.output_dir}")

if __name__ == "__main__":
    main()