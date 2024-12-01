# Mumble WebUI

A minimal, suckless-inspired WebUI for Mumble that allows users to connect to Mumble servers directly from their web browsers.

## Features

- Pure WebRTC audio streaming
- Minimal dependencies
- Simple and maintainable codebase
- Direct Mumble protocol integration
- Clean and functional UI

## Requirements

- C compiler (gcc/clang)
- OpenSSL
- libwebsockets
- jansson
- Make

## Installation

1. Clone the repository:

```bash
git clone https://github.com/F1PWE/webui-mumble.git
cd webui-mumble
```

2. Run the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

This will install dependencies and build the server.

## Usage

1. Start your Mumble server

2. Start the WebUI server:

```bash
./mumble-webui-server
```

3. Open `src/client/index.html` in your web browser

4. Enter your username and connect

## Building from Source

```bash
make clean
make
```

## License

This project follows the suckless philosophy. Use it as you see fit.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request 