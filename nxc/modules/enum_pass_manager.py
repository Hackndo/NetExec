import pathlib
import fnmatch
import os

class NXCModule:
    """
    Detects installed password managers by checking specific file paths
    and active processes.
    """

    # Metadata
    name = "enum_pass_manager"
    description = "Detects installed password managers via file paths and processes"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        Define additional options for the module if needed.
        """
        pass

    def on_login(self, context, connection):
        """
        Entry point after logging into the target.
        """
        target = self._get_target(connection)
        context.log.info(f"Analyzing target: {target}")

        password_managers = {
            "LastPass": {
                "paths": [r"C:\\Program Files (x86)\\LastPass",
                          r"C:\\ProgramData\\LastPass"],
                "pipes": [r"LASTPASS_"]
            },
            "Dashlane": {
                "paths": [r"C:\\Program Files (x86)\\Dashlane",
                          r"C:\\ProgramData\\Dashlane"],
                "pipes": []
            },
            "1Password": {
                "paths": [r"C:\\Users\\*\\AppData\\*\\1Password",
                          r"C:\\Program Files\\1Password",
                          r"C:\\Program Files (x86)\\1Password"],
                "pipes": []
            },
            "Bitwarden": {
                "paths": [r"C:\\Program Files\\Bitwarden",
                          r"C:\\Users\\*\\AppData\\Local\\Bitwarden"],
                "pipes": []
            },
            "KeePass": {
                "paths": [r"C:\\Program Files\\KeePass*",
                          r"C:\\Program Files (x86)\\KeePass*"],
                "pipes": []
            },
            "EnPass": {
                "paths": [r"C:\\Program Files\\Enpass",
                          r"C:\\Program Files (x86)\\Enpass"],
                "pipes": [r"-enpass-", ]
            }
        }

        self._detect_running_processes(context, connection, password_managers)
        self._detect_password_managers(context, connection, password_managers)

    def _get_target(self, connection):
        """
        Retrieve the target information.
        """
        return connection.host if not connection.kerberos else f"{connection.hostname}.{connection.domain}"



    def _detect_password_managers(self, context, connection, password_managers):
        """
        Detect installed password managers by checking for specific file paths.
        Supports wildcard (*) in any segment of the path.
        """
        context.log.info(f"Checking for known password manager file paths on {connection.host}...")

        for name, product in password_managers.items():
            for path in product['paths']:
                try:
                    # Split the path into segments for processing
                    path_segments = path.split(r"\\")
                    base_path = path_segments[0]  # Root path, e.g., "C:"
                    remaining_paths = path_segments[1:]  # Remaining segments with wildcards
                    # Start exploring paths recursively
                    if self._recursive_match(connection, base_path, remaining_paths):
                        context.log.highlight(f"Password manager installed: {name}")
                        break
                except Exception as e:
                    context.log.debug(f"Failed to check path {path}: {str(e)}")

    def _recursive_match(self, connection, current_path, remaining_paths):
        """
        Recursively match wildcard segments in a path.
        """
        if not remaining_paths:
            # If no more segments, return the final resolved path
            return [current_path]

        next_path = remaining_paths[0]

        # List the contents of the current directory
        try:
            contents = connection.conn.listPath("C$", current_path.replace("C:", "") + "/*")
        except:
            return False

        # Filter the directory contents to match the current segment
        matched_dirs = [
            os.path.join(current_path, item.get_shortname())
            for item in contents
            if fnmatch.fnmatch(item.get_shortname(), next_path)
        ]

        # Recurse into each matched directory
        matched_paths = []
        for matched_dir in matched_dirs:
            if not self._recursive_match(connection, matched_dir, remaining_paths[1:]):
                continue
            return True

        return False

    def _detect_running_processes(self, context, connection, password_managers):
        context.log.info(f"Detecting running processes on {connection.host} by enumerating pipes...")
        try:
            for f in connection.conn.listPath("IPC$", "\\*"):
                fl = f.get_longname()
                for name, product in password_managers.items():
                    for pipe in product['pipes']:
                        if pipe.lower() in fl.lower():
                            context.log.highlight(f"Password manager RUNNING: {name}")
                            break
        except Exception as e:
                context.log.fail(str(e))

    def dump_results(self, results, context):
        """
        Display results in a structured manner.
        """
        if not results:
            context.log.highlight("No password managers detected.")
            return

        for manager, data in results.items():
            message = f"Password manager detected: {manager}"
            if "paths" in data and len(data["paths"]) > 0:
                message += " (Paths detected)"
            if "pipes" in data and len(data["pipes"]) > 0:
                message += " - RUNNING!"
            context.log.highlight(message)
