#!/bin/bash

# Define the list of AI queries
declare -a queries=(
  "Find exposed AI/ML model files (.pkl, .h5, .pt) that may leak proprietary algorithms or sensitive training data"
  "Find exposed automation scripts (.sh, .ps1, .bat) revealing internal tooling or credentials"
  "Identify misconfigured CSP headers allowing 'unsafe-inline' or wildcard sources"
  "Detect pages leaking JWT tokens in URLs or cookies"
  "Identify overly verbose error messages revealing framework or library details"
  "Find application endpoints with verbose stack traces or source code exposure"
  "Find sensitive information in HTML comments (debug notes, API keys, credentials)"
  "Find exposed .env files leaking credentials, API keys, and database passwords"
  "Find exposed configuration files such as config.json, config.yaml, config.php, application.properties containing API keys and database credentials."
  "Find exposed configuration files containing sensitive information such as credentials, API keys, database passwords, and cloud service secrets."
  "Find database configuration files such as database.yml, db_config.php, .pgpass, .my.cnf leaking credentials."
  "Find exposed Docker and Kubernetes configuration files such as docker-compose.yml, kubeconfig, .dockercfg, .docker/config.json containing cloud credentials and secrets."
  "Find exposed SSH keys and configuration files such as id_rsa, authorized_keys, and ssh_config."
  "Find exposed WordPress configuration files (wp-config.php) containing database credentials and authentication secrets."
  "Identify exposed .npmrc and .yarnrc files leaking NPM authentication tokens"
  "Identify open directory listings exposing sensitive files"
  "Find exposed .git directories allowing full repo download"
  "Find exposed .svn and .hg repositories leaking source code"
  "Identify open FTP servers allowing anonymous access"
  "Find GraphQL endpoints with introspection enabled"
  "Identify exposed .well-known directories revealing sensitive data"
  "Find publicly accessible phpinfo() pages leaking environment details"
  "Find exposed Swagger, Redocly, GraphiQL, and API Blueprint documentation"
  "Identify exposed .vscode and .idea directories leaking developer configs"
  "Detect internal IP addresses (10.x.x.x, 192.168.x.x, etc.) in HTTP responses"
  "Find exposed WordPress debug.log files leaking credentials and error messages"
  "Detect misconfigured CORS allowing wildcard origins ('*')"
  "Find publicly accessible backup and log files (.log, .bak, .sql, .zip, .dump)"
  "Find exposed admin panels with default credentials"
  "Identify commonly used API endpoints that expose sensitive user data, returning HTTP status 200 OK."
  "Detect web applications running in debug mode, potentially exposing sensitive system information."
)

# Ensure targets.txt exists
if [ ! -f targets.txt ]; then
  echo "Error: targets.txt not found. Please create the file with your target URLs."
  exit 1
fi

# Run nuclei for each query
for query in "${queries[@]}"; do
  echo "Running nuclei with query: $query"
  nuclei -list targets.txt -ai "$query"
  echo "Completed query: $query"
  echo "----------------------------------------"
done

echo "All scans completed."