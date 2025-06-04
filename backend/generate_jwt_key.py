import secrets
import re
from pathlib import Path

def generate_secure_key(length=64):
    """Generate a secure random key using secrets module."""
    return secrets.token_hex(length)

def update_env_file(env_path, new_key):
    """Update the JWT_SECRET_KEY in .env file."""
    # Convert env_path to string for regex operations
    env_path_str = str(env_path)
    
    # Read the current .env file
    with open(env_path, 'r') as f:
        content = f.read()
    
    # Check if JWT_SECRET_KEY already exists
    if 'JWT_SECRET_KEY=' in content:
        # Replace existing key
        new_content = re.sub(
            r'JWT_SECRET_KEY=.*',
            f'JWT_SECRET_KEY={new_key}',
            content
        )
    else:
        # Add new key
        new_content = content.rstrip() + f'\nJWT_SECRET_KEY={new_key}\n'
    
    # Create backup of current .env using Path for proper path handling
    backup_path = env_path.with_suffix('.env.backup')
    if env_path.exists():
        env_path.rename(backup_path)
        print(f"Created backup at: {backup_path}")
    
    # Write new content
    with open(env_path, 'w') as f:
        f.write(new_content)
    
    print(f"Updated JWT_SECRET_KEY in {env_path}")
    print(f"New key: {new_key}")

def main():
    # Get the directory of this script
    script_dir = Path(__file__).parent
    env_path = script_dir / '.env'
    
    if not env_path.exists():
        print(f"Error: .env file not found at {env_path}")
        return
    
    # Generate new key
    new_key = generate_secure_key()
    
    # Update .env file
    update_env_file(env_path, new_key)
    
    print("\nImportant: After updating the JWT key:")
    print("1. All existing sessions will be invalidated")
    print("2. Users will need to log in again")
    print("3. Restart your backend server")
    print("\nTo restart the backend:")
    print("1. Stop the current server")
    print("2. Start it again with: python server.py")

if __name__ == "__main__":
    main() 