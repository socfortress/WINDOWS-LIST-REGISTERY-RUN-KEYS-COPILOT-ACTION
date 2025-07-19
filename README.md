# PowerShell List Registry Run Keys Template

This repository serves as a template for creating PowerShell-based active response scripts for security automation and incident response. The template provides a standardized structure and common functions to ensure consistent logging, error handling, and execution flow across all active response scripts.

## Overview

The `List-RegistryRunKeys.ps1` file is the foundation for PowerShell active response scripts that enumerate Windows registry "Run" keys, including signature and trust information for associated executables. It provides a robust framework with built-in logging, error handling, and standardized output formatting suitable for integration with security orchestration platforms, SIEM systems, and incident response workflows.

## Template Structure

### Core Components

The template includes the following essential components:

1. **Parameter Definitions** - Configurable script parameters
2. **Logging Framework** - Comprehensive logging with rotation
3. **Error Handling** - Structured exception management
4. **JSON Output** - Standardized response format
5. **Execution Timing** - Performance monitoring

## How Scripts Are Invoked

### Command Line Execution
```powershell
.\List-RegistryRunKeys.ps1 [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter     | Type   | Default Value                                                    | Description                                  |
|---------------|--------|------------------------------------------------------------------|----------------------------------------------|
| `LogPath`     | string | `$env:TEMP\ListRegistryRunKeys-script.log`                       | Path for execution logs                      |
| `ARLog`       | string | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

### Example Invocations

```powershell
# Basic execution with default parameters
.\List-RegistryRunKeys.ps1

# Custom log path
.\List-RegistryRunKeys.ps1 -LogPath "C:\Logs\ListRegistryRunKeys.log"

# Integration with OSSEC/Wazuh active response
.\List-RegistryRunKeys.ps1 -ARLog "C:\ossec\active-responses.log"
```

## Template Functions

### `Write-Log`
**Purpose**: Provides standardized logging with multiple severity levels and console output.

**Parameters**:
- `Message` (string): The log message to write
- `Level` (ValidateSet): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'

**Features**:
- Timestamp formatting with milliseconds
- Color-coded console output based on severity
- File logging with structured format
- Verbose debugging support

**Usage**:
```powershell
Write-Log "Registry Run keys JSON appended to C:\ossec\active-responses.log" 'INFO'
Write-Log "Failed to read HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run: ..." 'WARN'
Write-Log "Critical error occurred" 'ERROR'
Write-Log "Debug information" 'DEBUG'
```

### `Rotate-Log`
**Purpose**: Manages log file size and implements automatic log rotation to prevent disk space issues.

**Features**:
- Monitors log file size (default: 100KB threshold)
- Maintains configurable number of historical log files (default: 5)
- Automatic rotation when size limit exceeded
- Preserves log history for forensic analysis

**Configuration Variables**:
- `$LogMaxKB`: Maximum log file size in KB before rotation
- `$LogKeep`: Number of rotated log files to retain

## Script Execution Flow

### 1. Initialization Phase
- Parameter validation and default assignment
- Error action preference configuration
- Environment variable collection
- Log rotation check and execution

### 2. Execution Phase
- Script start logging with timestamp
- Main action logic execution (enumerate registry Run keys, extract executable, check signature/trust)
- Real-time logging of operations

### 3. Completion Phase
- JSON result formatting and output
- Active response log appending
- Execution duration calculation
- Cleanup and resource disposal

### 4. Error Handling
- Structured exception catching
- Error message logging
- JSON error response formatting
- Graceful failure handling

## JSON Output Format

All scripts output standardized JSON responses to the active response log:

### Success Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "list_registry_run_keys",
  "run_key_entries": [
    {
      "registry_key": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "value_name": "MyApp",
      "command": "\"C:\\Program Files\\MyApp\\myapp.exe\" /start",
      "executable": "C:\\Program Files\\MyApp\\myapp.exe",
      "signed": true,
      "trusted_microsoft": false
    }
  ]
}
```

### Error Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "list_registry_run_keys",
  "status": "error",
  "error": "Failed to read HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run: Access is denied"
}
```

## Implementation Guidelines

### 1. Customizing the Template
1. Copy `List-RegistryRunKeys.ps1` to your new script name
2. Replace the action logic section between the comment markers
3. Update the action name in the JSON output
4. Add any additional parameters as needed
5. Implement your specific functionality

### 2. Best Practices
- Always use the provided logging functions
- Implement proper error handling for all operations
- Include meaningful progress messages
- Validate all input parameters
- Document any additional functions or parameters

### 3. Integration Considerations
- Ensure proper file permissions for log paths and registry access
- Test script execution in target environments
- Validate JSON output format compatibility

## Security Considerations

- Scripts should run with minimal required privileges
- Validate all input parameters to prevent injection attacks
- Implement proper access controls for log files
- Use secure communication channels when applicable
- Log all security-relevant actions and decisions

## Troubleshooting

### Common Issues
1. **Permission Errors**: Ensure script has write access to log paths and registry keys, and is run as Administrator for registry enumeration
2. **Log Rotation**: Check disk space and file permissions for log directory
3. **JSON Format**: Validate output against expected schema

### Debug Mode
Enable verbose logging by running with `-Verbose` parameter:
```powershell
.\List-RegistryRunKeys.ps1 -Verbose
```

## Contributing

When creating new active response scripts based on this template:
1. Maintain the core logging and error handling structure
2. Follow PowerShell best practices and coding standards
3. Document any additional functions or parameters
4. Test thoroughly in isolated environments
5. Include usage examples and expected outputs

## Automated Releases

This repository includes automated release functionality via GitHub Actions that creates production-ready PowerShell scripts for distribution.

### Release Features

- **Automated Script Packaging**: Adds metadata headers with version, build date, and repository information
- **Multiple Distribution Formats**: Creates both versioned and generic script names
- **Integrity Verification**: Generates SHA256 checksums for all release files
- **Automated Installer**: Provides a PowerShell installer script for easy deployment
- **Production Documentation**: Includes comprehensive usage and security documentation

### Creating Releases

#### Method 1: Git Tags (Recommended)
```bash
# Create and push a version tag
git tag v1.0.0
git push origin v1.0.0
```

#### Method 2: Manual Workflow Trigger
1. Go to the **Actions** tab in GitHub
2. Select **"Create PowerShell Script Release"**
3. Click **"Run workflow"**
4. Enter the version (e.g., `v1.0.0`) and script name
5. Click **"Run workflow"**

### Release Artifacts

Each release contains:
- `{script-name}.ps1` - Production script with metadata
- `{script-name}-{version}.ps1` - Versioned production script
- `install.ps1` - Automated installation script
- `checksums.txt` - SHA256 file integrity checksums
- `README.md` - Release-specific documentation

### Distribution Methods

#### Option 1: Automated Installation
```powershell
# Download and run the installer
Invoke-WebRequest -Uri "https://github.com/{owner}/{repo}/releases/download/v1.0.0/install.ps1" -OutFile "install.ps1"
.\install.ps1
```

#### Option 2: Direct Download
```powershell
# Download script directly
Invoke-WebRequest -Uri "https://github.com/{owner}/{repo}/releases/download/v1.0.0/List-RegistryRunKeys.ps1" -OutFile "List-RegistryRunKeys.ps1"
```

#### Option 3: One-liner Execution
```powershell
# Execute directly from URL (use with caution)
Invoke-WebRequest -Uri "https://github.com/{owner}/{repo}/releases/download/v1.0.0/List-RegistryRunKeys.ps1" | Invoke-Expression
```

### Production Deployment

For production environments, the recommended approach is:

1. **Use the automated installer** for validated deployments
2. **Verify checksums** to ensure script integrity
3. **Test in isolated environments** before production deployment
4. **Use proper execution policies** and security controls
5. **Monitor script execution** through the built-in logging framework

### Why Not Compiled Scripts?

For PowerShell active response scripts, raw `.ps1` files with metadata headers provide the best balance of:

- **Transparency**: Source code is visible and auditable
- **Flexibility**: Easy to modify for specific environments
- **Compatibility**: Works across different PowerShell versions and platforms
- **Security**: Can be signed and verified without complex packaging
- **Debugging**: Easier to troubleshoot and customize when needed

However, for environments requiring additional security or deployment simplification, consider:
- **Code signing** with digital certificates
- **Module packaging** for reusable components
- **PowerShell galleries** for internal distribution
- **Group Policy deployment** for enterprise environments

## License

This template is provided as-is for security automation and incident
