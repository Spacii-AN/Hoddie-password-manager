#!/usr/bin/env python3
"""
Hoodie Password Generator

A simple yet powerful password generator that allows users to create secure passwords
with customizable length and character sets.

Features:
- Generate passwords between 6 and 24 characters in length
- Include or exclude uppercase letters, lowercase letters, numbers, and special characters
- Cross-platform compatibility (Windows, macOS, Linux)
- Command-line interface for easy use
- Multithreaded processing for faster generation of multiple passwords
- Generate all possible passwords and save to a text file (use with caution!)

Usage:
    python hoodie_generator.py

    or make it executable (Linux/macOS) with:
    chmod +x hoodie_generator.py
    ./hoodie_generator.py
"""

import random
import string
import argparse
import sys
import os
import concurrent.futures
import multiprocessing
import itertools
import time


def generate_password(length=12, min_length=None, max_length=None, use_uppercase=True, use_lowercase=True,
                     use_numbers=True, use_special=True):
    """
    Generate a random password with the specified characteristics.

    Args:
        length (int): Length of the password (between 6-24)
        min_length (int, optional): Minimum length if generating variable length passwords
        max_length (int, optional): Maximum length if generating variable length passwords
        use_uppercase (bool): Include uppercase letters
        use_lowercase (bool): Include lowercase letters
        use_numbers (bool): Include numbers
        use_special (bool): Include special characters

    Returns:
        str: Generated password
    """
    # If min and max length are provided, override the fixed length
    if min_length is not None and max_length is not None:
        # Generate a random length between min and max (inclusive)
        length = random.randint(int(min_length), int(max_length))
    
    # Validate length and ensure it's an integer
    length = int(length)
    if not (6 <= length <= 24):
        raise ValueError("Password length must be between 6 and 24 characters")

    # Ensure at least one character type is selected
    if not (use_uppercase or use_lowercase or use_numbers or use_special):
        raise ValueError("At least one character type must be selected")

    # Define character sets based on user preferences
    chars = ""
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_numbers:
        chars += string.digits
    if use_special:
        chars += string.punctuation

    # Generate password
    password = ''.join(random.choice(chars) for _ in range(length))

    # Ensure password includes at least one character from each selected character set
    while True:
        has_uppercase = any(c in string.ascii_uppercase for c in password) if use_uppercase else True
        has_lowercase = any(c in string.ascii_lowercase for c in password) if use_lowercase else True
        has_number = any(c in string.digits for c in password) if use_numbers else True
        has_special = any(c in string.punctuation for c in password) if use_special else True

        if has_uppercase and has_lowercase and has_number and has_special:
            break

        # If a required character type is missing, regenerate password
        password = ''.join(random.choice(chars) for _ in range(length))

    return password


def generate_passwords_in_parallel(count, length=None, min_length=None, max_length=None, 
                                  use_uppercase=True, use_lowercase=True, use_numbers=True, 
                                  use_special=True, max_workers=None):
    """
    Generate multiple passwords in parallel using thread pool.

    Args:
        count (int): Number of passwords to generate
        length (int, optional): Fixed length of each password
        min_length (int, optional): Minimum length if generating variable length passwords
        max_length (int, optional): Maximum length if generating variable length passwords
        use_uppercase (bool): Include uppercase letters
        use_lowercase (bool): Include lowercase letters
        use_numbers (bool): Include numbers
        use_special (bool): Include special characters
        max_workers (int, optional): Maximum number of worker threads

    Returns:
        list: List of generated passwords
    """
    # If no max_workers is specified, use the number of CPU cores
    if max_workers is None:
        max_workers = multiprocessing.cpu_count()

    # Create password generation tasks
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create a list of futures (tasks)
        futures = [
            executor.submit(
                generate_password,
                length=length,
                min_length=min_length,
                max_length=max_length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_numbers=use_numbers,
                use_special=use_special
            ) for _ in range(count)
        ]

        # Get results as they complete
        results = []
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return results

def estimate_password_count(length, char_count):
    """
    Estimate the number of possible passwords with given length and character set.

    Args:
        length (int): Length of each password
        char_count (int): Number of characters in the character set

    Returns:
        int: Estimated number of possible passwords
    """
    # Ensure inputs are integers
    length = int(length)
    char_count = int(char_count)
    return char_count ** length

def generate_all_passwords(length, use_uppercase, use_lowercase, use_numbers, use_special, output_file, batch_size=10000):
    """
    Generate all possible passwords with the given parameters and save to a file.

    Args:
        length (int): Length of each password
        use_uppercase (bool): Include uppercase letters
        use_lowercase (bool): Include lowercase letters
        use_numbers (bool): Include numbers
        use_special (bool): Include special characters
        output_file (str): Path to the output file
        batch_size (int): Number of passwords to write at once

    Returns:
        int: Number of passwords generated
    """
    # Define character set
    chars = ""
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_numbers:
        chars += string.digits
    if use_special:
        chars += string.punctuation

    # Estimate total number of passwords
    total_passwords = estimate_password_count(length, len(chars))

    print(f"Generating all possible passwords with length {length} using {len(chars)} characters")
    print(f"Total possible combinations: {total_passwords:,}")
    print(f"Writing to: {output_file}")

    # Progress tracking variables
    start_time = time.time()
    last_update_time = start_time
    passwords_written = 0
    update_interval = 5  # seconds

    with open(output_file, 'w') as f:
        password_batch = []

        try:
            # Generate all possible combinations
            for combo in itertools.product(chars, repeat=length):
                password = ''.join(combo)
                password_batch.append(password)

                # Write in batches for efficiency and memory management
                if len(password_batch) >= batch_size:
                    f.write('\n'.join(password_batch) + '\n')
                    passwords_written += len(password_batch)
                    password_batch.clear()  # Clear batch to free memory

                    # Update progress periodically
                    current_time = time.time()
                    if current_time - last_update_time > update_interval:
                        elapsed = current_time - start_time
                        percent_done = (passwords_written / total_passwords) * 100
                        passwords_per_sec = passwords_written / elapsed if elapsed > 0 else 0

                        print(f"Progress: {passwords_written:,}/{total_passwords:,} ({percent_done:.2f}%) "
                              f"- {passwords_per_sec:.2f} passwords/sec", end='\r')

                        last_update_time = current_time
                        
                        # Force garbage collection to prevent memory buildup
                        import gc
                        gc.collect()

            # Write any remaining passwords
            if password_batch:
                f.write('\n'.join(password_batch) + '\n')
                passwords_written += len(password_batch)
                password_batch.clear()  # Clear batch to free memory
        except MemoryError:
            # Handle out of memory situation
            if password_batch:
                f.write('\n'.join(password_batch) + '\n')
                passwords_written += len(password_batch)
                password_batch.clear()
            print("\nMemory limit reached. Partial generation complete.")

    # Final statistics
    total_time = time.time() - start_time
    print(f"\nGeneration complete. {passwords_written:,} passwords written in {total_time:.2f} seconds.")
    print(f"Average speed: {passwords_written / total_time:.2f} passwords/sec")
    
    # Final garbage collection
    import gc
    gc.collect()

    return passwords_written, total_time

def main():
    """Main function to handle command-line arguments and generate passwords."""
    parser = argparse.ArgumentParser(description="Hoodie - Generate a secure random password")

    # Password length options
    length_group = parser.add_mutually_exclusive_group()
    length_group.add_argument("-l", "--length", type=int, default=12,
                        help="Length of the password (6-24 characters)")
    length_group.add_argument("-r", "--range", type=str, metavar="MIN-MAX",
                        help="Generate passwords with random length in range (e.g., 8-16)")
    
    parser.add_argument("--no-uppercase", action="store_false", dest="uppercase",
                        help="Exclude uppercase letters")
    parser.add_argument("--no-lowercase", action="store_false", dest="lowercase",
                        help="Exclude lowercase letters")
    parser.add_argument("--no-numbers", action="store_false", dest="numbers",
                        help="Exclude numbers")
    parser.add_argument("--no-special", action="store_false", dest="special",
                        help="Exclude special characters")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Number of passwords to generate")
    parser.add_argument("-t", "--threads", type=int, default=None,
                        help="Number of threads to use (default: number of CPU cores)")
    parser.add_argument("--all", action="store_true",
                        help="Generate all possible passwords (warning: can be extremely large)")
    parser.add_argument("-o", "--output", type=str,
                        help="Output file for all passwords (required with --all)")
    parser.add_argument("--force", action="store_true",
                        help="Force generation even for very large password sets")

    args = parser.parse_args()

    try:
        # Parse min-max range if provided
        min_length = None
        max_length = None
        if args.range:
            try:
                range_parts = args.range.split('-')
                if len(range_parts) == 2:
                    min_length = int(range_parts[0])
                    max_length = int(range_parts[1])
                    # Verify min is less than or equal to max
                    if min_length > max_length:
                        print("Error: Minimum length must be less than or equal to maximum length", file=sys.stderr)
                        sys.exit(1)
                    # Verify range is within allowed limits
                    if not (6 <= min_length <= 24) or not (6 <= max_length <= 24):
                        print("Error: Password length must be between 6 and 24 characters", file=sys.stderr)
                        sys.exit(1)
                else:
                    print("Error: Range format should be MIN-MAX (e.g., 8-16)", file=sys.stderr)
                    sys.exit(1)
            except ValueError:
                print("Error: Range values must be integers (e.g., 8-16)", file=sys.stderr)
                sys.exit(1)
        
        # Generate all possible passwords
        if args.all:
            if not args.output:
                print("Error: --output is required when using --all", file=sys.stderr)
                sys.exit(1)
                
            # Can't use range with --all
            if min_length is not None:
                print("Error: Cannot use --range with --all", file=sys.stderr)
                sys.exit(1)

            # Build character set to estimate size
            chars = ""
            if args.uppercase:
                chars += string.ascii_uppercase
            if args.lowercase:
                chars += string.ascii_lowercase
            if args.numbers:
                chars += string.digits
            if args.special:
                chars += string.punctuation

            # Check if empty character set
            if not chars:
                print("Error: At least one character type must be selected", file=sys.stderr)
                sys.exit(1)

            # Calculate estimated file size
            # Ensure length is an integer
            length = int(args.length)
            total_passwords = estimate_password_count(length, len(chars))
            # Assume average 8 bytes per password (length + newline)
            estimated_size_bytes = total_passwords * (length + 1)
            estimated_size_gb = estimated_size_bytes / (1024**3)

            # Warn if file will be very large
            if estimated_size_gb > 1 and not args.force:
                print(f"Warning: This will generate approximately {total_passwords:,} passwords", file=sys.stderr)
                print(f"The output file could be around {estimated_size_gb:.2f} GB", file=sys.stderr)
                print("This could take a very long time and use a lot of disk space.", file=sys.stderr)
                print("Use --force to override this warning.", file=sys.stderr)
                sys.exit(1)

            # Generate all passwords
            # time is already imported at the top of the file
            result = generate_all_passwords(
                length=int(args.length),
                use_uppercase=args.uppercase,
                use_lowercase=args.lowercase,
                use_numbers=args.numbers,
                use_special=args.special,
                output_file=args.output
            )
            
            # Handle either single value or tuple return
            if isinstance(result, tuple) and len(result) == 2:
                passwords_written, _ = result
            else:
                passwords_written = result
                
            print(f"Total passwords written: {passwords_written:,}")
        # For a single password, don't bother with threading
        elif args.count == 1:
            password = generate_password(
                length=int(args.length) if args.length else None,
                min_length=min_length,
                max_length=max_length,
                use_uppercase=args.uppercase,
                use_lowercase=args.lowercase,
                use_numbers=args.numbers,
                use_special=args.special
            )
            if min_length is not None:
                print(f"Hoodie Password [{len(password)} chars]: {password}")
            else:
                print(f"Hoodie Password: {password}")
        else:
            # Generate multiple passwords in parallel
            passwords = generate_passwords_in_parallel(
                count=int(args.count),
                length=int(args.length) if args.length else None,
                min_length=min_length,
                max_length=max_length,
                use_uppercase=args.uppercase,
                use_lowercase=args.lowercase,
                use_numbers=args.numbers,
                use_special=args.special,
                max_workers=args.threads
            )

            # Print results
            for i, password in enumerate(passwords):
                if min_length is not None:
                    print(f"Hoodie Password {i+1} [{len(password)} chars]: {password}")
                else:
                    print(f"Hoodie Password {i+1}: {password}")

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Seed the random number generator
    # In Python 3.9+, this is done automatically, but we do it explicitly for backwards compatibility
    random.seed(os.urandom(16))

    try:
        main()
    except KeyboardInterrupt:
        print("\nHoodie password generation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
