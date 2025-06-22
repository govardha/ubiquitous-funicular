import os
import subprocess
import argparse
import shlex # Used for safely quoting command-line arguments when printing

def run_filebot_on_mkvs(input_directory, prefix, dry_run):
    """
    Recursively finds .mkv files within the input_directory and runs the
    specified FileBot command on each.

    Args:
        input_directory (str): The root directory to search for .mkv files.
                               Paths starting with '~' will be expanded to the
                               user's home directory.
        prefix (str): The name of the subdirectory under '$HOME/files/' where
                      FileBot will move the processed files (e.g., 'Movies', 'TVShows').
        dry_run (bool): If True, the script will only print the FileBot commands
                        without executing them. If False, the commands will be executed.
    """
    # 1. Standardize and expand paths
    # os.path.expanduser handles '~' to the user's home directory.
    # os.path.abspath converts relative paths to absolute paths.
    input_directory = os.path.abspath(os.path.expanduser(input_directory))

    # Construct the base output directory for FileBot: $HOME/files/<prefix>
    home_dir = os.path.expanduser('~')
    output_base_dir = os.path.join(home_dir, 'files')
    output_dir = os.path.join(output_base_dir, prefix)

    # Define the path for FileBot's log file: $HOME/tmp/amc.log
    log_file_path = os.path.join(home_dir, 'tmp', 'amc.log')

    # 2. Ensure necessary directories exist
    # Create the output directory and the directory for the log file if they don't exist.
    # exist_ok=True prevents an error if the directory already exists.
    try:
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    except OSError as e:
        print(f"Error creating directories: {e}")
        print("Please check your permissions or path validity and try again.")
        return # Exit if directories cannot be created

    print(f"--- FileBot Automation Script ---")
    print(f"Input Directory:  {input_directory}")
    print(f"Output Directory: {output_dir}")
    print(f"Log File:         {log_file_path}")
    print(f"Dry Run Mode:     {'ENABLED' if dry_run else 'DISABLED (Commands will execute)'}")
    print("-" * 30)

    found_files_count = 0
    # 3. Traverse the input directory to find .mkv files
    # os.walk generates the file names in a directory tree by walking the tree
    # top-down or bottom-up.
    for root, _, files in os.walk(input_directory):
        for file in files:
            # Check if the file has a .mkv extension (case-insensitive)
            if file.lower().endswith('.mkv'):
                found_files_count += 1
                mkv_file_path = os.path.join(root, file) # Full path to the current .mkv file

                # 4. Construct the FileBot command as a list of arguments
                # This is crucial for subprocess.run(shell=False) which is safer.
                # Each item in the list is treated as a distinct argument.
                # subprocess.run handles spaces in paths when passed this way.
                filebot_command_args = [
                    'filebot',
                    '-script', 'fn:amc',
                    '-non-strict',
                    '--def', 'ut_kind=multi',
                    '--log', 'all',
                    '--log-file', log_file_path,
                    # The 'ut_dir' definition: FileBot expects 'ut_dir=VALUE',
                    # where VALUE is the full path to the .mkv file.
                    '--def', f'ut_dir={mkv_file_path}',
                    '--output', output_dir, # This is the target base directory for FileBot
                    '--conflict', 'override',
                    '--def', 'artwork=y',
                    '--def', 'subtitles=eng',
                    '--def', 'minFileSize=0',
                    '--action', 'move' # Tells FileBot to move the files after processing
                ]

                # For displaying the command clearly in the console (especially in dry-run mode),
                # use shlex.join to re-quote arguments as they would appear in a shell.
                command_to_print = shlex.join(filebot_command_args)

                print(f"\nProcessing File: {mkv_file_path}")
                print(f"Proposed Command: {command_to_print}")

                # 5. Execute the command or simulate execution based on dry_run flag
                if not dry_run:
                    try:
                        # subprocess.run executes the command.
                        # check=True: Raises CalledProcessError if the command returns a non-zero exit code.
                        # text=True: Decodes stdout and stderr as text.
                        # capture_output=True: Captures stdout and stderr for printing.
                        result = subprocess.run(
                            filebot_command_args,
                            check=True,
                            text=True,
                            capture_output=True
                        )
                        print("--- FileBot STDOUT ---")
                        print(result.stdout.strip())
                        print("--- FileBot STDERR ---")
                        print(result.stderr.strip())
                        if result.returncode == 0:
                            print("FileBot command executed successfully.")
                        else:
                            print(f"FileBot command finished with exit code {result.returncode}.")
                    except subprocess.CalledProcessError as e:
                        print(f"ERROR: FileBot command failed for '{mkv_file_path}'!")
                        print(f"Exit Code: {e.returncode}")
                        print("STDOUT:\n", e.stdout.strip())
                        print("STDERR:\n", e.stderr.strip())
                    except FileNotFoundError:
                        print("ERROR: 'filebot' command not found in your system's PATH.")
                        print("Please ensure FileBot is installed and accessible from your command line.")
                        print("Exiting script as FileBot cannot be run.")
                        return # Stop processing if filebot itself isn't found
                else:
                    print("Dry run: Command not executed.")
                print("-" * 30)

    # 6. Final summary
    if found_files_count == 0:
        print(f"\nNo .mkv files found in '{input_directory}' or its subdirectories.")
    else:
        print(f"\nFinished processing. Found and {'simulated' if dry_run else 'attempted to process'} "
              f"{found_files_count} .mkv files.")
    print("--- Script Complete ---")

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Automate FileBot processing for all .mkv files in a given directory."
    )
    parser.add_argument(
        "-i", "--input_dir", # Added short argument -i and changed long argument name
        type=str,
        help="The root directory where the script will start searching for .mkv files "
             "(e.g., '/Users/youruser/Downloads' or '~/Videos')."
    )
    parser.add_argument(
        "-p", "--prefix", # Added short argument -p
        type=str,
        help="A prefix used to create the output directory under $HOME/files/. "
             "For example, if you provide 'Movies', files will be moved to $HOME/files/Movies/."
    )
    parser.add_argument(
        "-d", "--dry-run", # Added short argument -d
        action="store_true", # This flag will be True if --dry-run is present, False otherwise.
        help="If specified, the script will only print the FileBot commands that WOULD be run, "
             "without actually executing them. This is useful for testing."
    )

    # Parse the arguments provided by the user
    args = parser.parse_args()

    # Pass the parsed arguments to the main function, ensuring variable names match the function signature
    run_filebot_on_mkvs(args.input_dir, args.prefix, args.dry_run)
