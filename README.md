# AWS Role Access Analyzer

This tool analyzes IAM role access patterns across multiple AWS accounts. It checks when and which AWS services were last accessed by a specific IAM role within the last 365 days.

## Features

- Analyze IAM role access patterns across multiple AWS accounts
- Parallel processing of accounts for faster execution
- Detailed CSV reports with service access history
- Easy-to-use command line interface
- Support for role assumption across accounts

## Prerequisites

- Python 3.6+
- AWS credentials configured with appropriate permissions
- The IAM role you want to analyze must exist in all target accounts
- Your AWS credentials must have permission to assume the target role in all accounts

## Installation

### From Source

1. Clone this repository:
```bash
git clone https://github.com/yourusername/aws-role-access-analyzer.git
cd aws-role-access-analyzer
```

2. Create and activate a virtual environment (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the package in development mode:
```bash
pip install -e .
```

### Using pip

```bash
pip install aws-role-access-analyzer
```

## Usage

After installation, you can use the tool in two ways:

### Command Line Interface

```bash
aws-role-analyzer --accounts "111111111111,222222222222" --role-name "RoleNameToAnalyze"
```

### Python API

```python
from aws_role_analyzer.analyzer import RoleAccessAnalyzer

# Initialize the analyzer
analyzer = RoleAccessAnalyzer(role_name="YourRoleName")

# Analyze a single account
result = analyzer.get_role_last_accessed("111111111111")

# Process multiple accounts
from concurrent.futures import ThreadPoolExecutor
account_ids = ["111111111111", "222222222222"]
with ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(analyzer.get_role_last_accessed, account_ids))
```

### Arguments

- `--accounts`: Comma-separated list of AWS account IDs to analyze
- `--role-name`: Name of the IAM role to analyze (must exist in all specified accounts)

### Output

The script will:
1. Query each account in parallel
2. Display a summary of the role's service access
3. Save a detailed report to a CSV file

### Required AWS Permissions

Your AWS credentials need the following permissions:
- `sts:AssumeRole` on the target role in each account
- The target role needs:
  - `iam:GetRole`
  - `iam:GenerateServiceLastAccessedDetails`
  - `iam:GetServiceLastAccessedDetails`

## Example Output

```
Analyzing role 'MyRole' across 2 accounts...

Role Access Summary:
AccountId    RoleId    ServiceName    LastAccessed                DaysSinceAccess
111111111111 AROA1... s3             2023-12-01T10:30:00+00:00  30
111111111111 AROA1... ec2            2023-11-15T14:20:00+00:00  45
222222222222 AROA2... lambda         2023-12-15T09:45:00+00:00  15

Detailed report saved to: role_access_report_20231230_123456.csv 
```

## Development

To set up the development environment:

1. Clone the repository
2. Create a virtual environment
3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 