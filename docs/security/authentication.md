# Authentication Architecture

Authentication is owned solely by the Python Control Plane (`control-plane/src/intriqo/auth`).

## Mechanisms
- **JWT / Bearer Tokens**: Stateless session authentication for human operators and UI clients.
- **Mutual TLS (mTLS) / API Keys**: Authenticated communication channels for internal engine-to-control plane adapters.
- **No Direct C++ Authentication**: The detection engine does not handle user sessions or credentials.
