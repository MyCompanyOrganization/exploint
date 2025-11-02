# Exploint

> What is the point of that exploit?!

Exploint is a Go CLI tool that automates vulnerability exploitability analysis with AI-powered enrichment. It analyzes Go codebases and container images to determine if vulnerabilities are exploitable in the specific context, with LLM integration for latest CVE information and interactive Q&A capabilities.

## Features

- 🔍 **Vulnerability Scanning**: Optional Trivy integration for scanning filesystems and container images
- 📦 **Manual CVE Input**: Support for JSON/YAML/CSV input or command-line CVE lists
- 🤖 **AI-Powered Analysis**: LLM integration for CVE enrichment and context-aware exploitability assessment
- 🔬 **Code Analysis**: Go AST parsing to identify component usage and execution paths
- 🐳 **Container Analysis**: Dockerfile parsing and image inspection
- 💬 **Interactive Q&A**: Chat interface for querying analysis results
- 📊 **Rich Reports**: Markdown reports with VEX (CycloneDX) generation

## Installation

### From Source

```bash
git clone https://github.com/matanlivne/exploint.git
cd exploint
go build -o exploint cmd/exploint/main.go
```

### Docker

```bash
# Build the image
docker build -t exploint:latest -f docker/Dockerfile .

# Run analysis
docker run --rm \
  -v $(pwd):/workspace \
  -e EXPLOINT_LLM_API_KEY=$OPENAI_API_KEY \
  exploint:latest analyze \
  --repo /workspace \
  --scan \
  --output /workspace/report.md

# Interactive chat
docker run -it --rm \
  -v $(pwd):/workspace \
  -e EXPLOINT_LLM_API_KEY=$OPENAI_API_KEY \
  exploint:latest chat \
  --results /workspace/results.json \
  --interactive
```

## Configuration

### Environment Variables

Create a `.env` file or set environment variables:

```bash
export EXPLOINT_LLM_API_KEY=your-api-key-here
export EXPLOINT_LLM_PROVIDER=openai
```

### Config File

Create `~/.exploint/config.yaml`:

```yaml
llm:
  provider: openai
  api_key: your-api-key-here
  enabled: true
```

## Usage

### Analyze a Repository

```bash
exploint analyze \
  --repo /path/to/go/project \
  --scan \
  --output report.md \
  --format md
```

### Analyze a Container Image

```bash
exploint analyze \
  --image myapp:latest \
  --scan \
  --output report.md
```

### Manual CVE Analysis

```bash
exploint analyze \
  --repo /path/to/go/project \
  --cves CVE-2025-47273,CVE-2025-0913 \
  --output report.md
```

### Interactive Chat

```bash
exploint chat \
  --results report.json \
  --interactive
```

## Development

### Project Structure

```
exploint/
├── cmd/
│   └── exploint/          # Main CLI entry point
├── pkg/
│   ├── analyzer/           # Code and image analysis
│   ├── assessor/           # Exploitability assessment
│   ├── scanner/            # Trivy and manual CVE input
│   ├── llm/                # LLM integration
│   ├── chat/               # Interactive Q&A
│   ├── reporter/           # Report generation
│   ├── models/             # Data models
│   └── config/             # Configuration management
└── docker/
    └── Dockerfile
```

## License

[License TBD]

