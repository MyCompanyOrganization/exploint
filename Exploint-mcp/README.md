# Exploint MCP Server

MCP (Model Context Protocol) server for Exploint that enables vulnerability exploitability analysis from Cursor IDE using Cursor's built-in LLM capabilities.

## Overview

Exploint MCP Server exposes Exploint's vulnerability analysis tools to Cursor IDE. When using Cursor's LLM integration, the server generates structured prompts that Cursor's LLM can process, eliminating the need for separate API keys.

## Features

- **Repository Analysis**: Analyze Go repositories for vulnerability exploitability
- **Image Analysis**: Analyze Docker images for vulnerabilities
- **CVE Analysis**: Analyze specific CVEs manually
- **Cursor LLM Integration**: Uses Cursor's LLM for enrichment without requiring API keys

## Installation

### Build from Source

```bash
# Build the MCP server binary
cd cmd/exploint-mcp
go build -o exploint-mcp main.go
```

Or use the pre-built binary in this directory.

## Configuration in Cursor IDE

Add the following to your Cursor MCP configuration file (typically `~/.cursor/mcp.json` or Cursor settings):

```json
{
  "mcpServers": {
    "exploint": {
      "command": "/path/to/exploint-mcp",
      "args": []
    }
  }
}
```

### Using Absolute Path

```json
{
  "mcpServers": {
    "exploint": {
      "command": "/Users/your-username/path/to/exploint-mcp/exploint-mcp"
    }
  }
}
```

## Available Tools

### analyze_repository

Analyze a Go repository for vulnerability exploitability.

**Parameters:**
- `path` (string, required): Path to the Go repository
- `scan` (boolean, optional): Run Trivy scan (default: true)
- `use_cursor_llm` (boolean, optional): Use Cursor's LLM for enrichment (default: true)

**Example:**
```json
{
  "name": "analyze_repository",
  "arguments": {
    "path": "/path/to/repo",
    "scan": true,
    "use_cursor_llm": true
  }
}
```

### analyze_image

Analyze a Docker image for vulnerability exploitability.

**Parameters:**
- `image` (string, required): Docker image name/tag
- `scan` (boolean, optional): Run Trivy scan (default: true)
- `use_cursor_llm` (boolean, optional): Use Cursor's LLM for enrichment (default: true)

**Example:**
```json
{
  "name": "analyze_image",
  "arguments": {
    "image": "nginx:latest",
    "scan": true,
    "use_cursor_llm": true
  }
}
```

### analyze_cves

Analyze specific CVEs for a repository or image.

**Parameters:**
- `cves` (string, required): Comma-separated list of CVE IDs
- `path` (string, optional): Path to repository (if analyzing repo)
- `image` (string, optional): Docker image name (if analyzing image)
- `use_cursor_llm` (boolean, optional): Use Cursor's LLM for enrichment (default: true)

**Example:**
```json
{
  "name": "analyze_cves",
  "arguments": {
    "cves": "CVE-2025-58187,CVE-2025-0913",
    "path": "/path/to/repo",
    "use_cursor_llm": true
  }
}
```

## How Cursor LLM Integration Works

When `use_cursor_llm` is enabled, Exploint:

1. Performs vulnerability scanning and analysis using Trivy and code analysis
2. Generates structured prompts for CVE enrichment and context analysis
3. Returns results with `llm_prompts` field containing:
   - `enrichment_prompts`: Prompts for Cursor's LLM to enrich CVE information
   - `analysis_prompts`: Prompts for Cursor's LLM to analyze exploitability in context

4. Cursor's LLM automatically processes these prompts when it receives the tool results
5. You can ask questions about the analysis, and Cursor's LLM will use the provided context

## Response Format

The MCP server returns results in the following format:

```json
{
  "success": true,
  "report": {
    "generated_at": "2025-11-02T...",
    "target": "/path/to/repo",
    "target_type": "repository",
    "findings": [...],
    "components": [...],
    "summary": {...}
  },
  "llm_prompts": {
    "enrichment_prompts": [
      {
        "cve": "CVE-2025-XXXX",
        "prompt": "[CURSOR_LLM_PROMPT:ENRICH_CVE]..."
      }
    ],
    "analysis_prompts": [
      {
        "finding_id": "CVE-2025-XXXX",
        "component": "package-name",
        "prompt": "[CURSOR_LLM_PROMPT:ANALYZE_CONTEXT]..."
      }
    ]
  },
  "message": "Analyzed X vulnerabilities in repository"
}
```

## Usage in Cursor

Once configured, you can use Exploint tools directly in Cursor:

```
@exploint analyze_repository path=/path/to/my/repo
```

Cursor will:
1. Call the MCP tool
2. Receive the analysis results and LLM prompts
3. Use its LLM to process the prompts and enrich the analysis
4. Provide you with insights and answer questions

## Requirements

- Trivy must be installed and available in PATH (for scanning)
- Go 1.25+ (if building from source)
- Cursor IDE with MCP support

## Troubleshooting

- **Server not starting**: Check that the binary has execute permissions
- **Tools not appearing**: Verify the MCP configuration path is correct
- **Scan failures**: Ensure Trivy is installed and accessible
- **LLM prompts not processed**: Check that `use_cursor_llm` is set to `true`

## License

Same as Exploint project.

