import subprocess
import os

def check_sql_injection(url):
    try:
        # Path to the sqlmap.py file
        sqlmap_path = "sqlmap.py"
        
        # Check if sqlmap.py exists
        if not os.path.isfile(sqlmap_path):
            raise FileNotFoundError(f"sqlmap.py not found at {sqlmap_path}")
        
        # Construct the command to run sqlmap.py
        command = ["python3", sqlmap_path, "-u", url, "--batch", "--level=1", "--risk=1", "--dbs"]
        
        # Run the command
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
        
        # Print the standard output and error for debugging
        print("Standard Output:")
        print(result.stdout)
        print("Standard Error:")
        print(result.stderr)
        
        # Check if the output contains the phrase indicating a DBMS was detected
        if "the back-end DBMS is" in result.stdout:
            return True
        return False
    except FileNotFoundError as e:
        print(e)
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python sqlmap_check.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    is_vulnerable = check_sql_injection(url)
    print(f"SQL Injection vulnerability: {'Detected' if is_vulnerable else 'Not detected'}")
