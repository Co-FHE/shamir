#!/bin/bash

# Default name
DEFAULT_NAME="coordinator"

# Get the name from the first argument, default to DEFAULT_NAME
NAME="${1:-$DEFAULT_NAME}"

# Define the directory and socket path
SOCKET_DIR=".ipc_socket"
SOCKET_PATH="${SOCKET_DIR}/${NAME}.sock"

# Check if socat is installed
if ! command -v socat &> /dev/null
then
    echo "socat is not installed. Please install socat first."
    exit 1
fi

# Ensure the socket directory exists
if [ ! -d "$SOCKET_DIR" ]; then
    mkdir -p "$SOCKET_DIR"
    if [ $? -ne 0 ]; then
        echo "Failed to create directory: $SOCKET_DIR"
        exit 1
    fi
fi

# Function: Send a message and receive a response
send_message() {
    local message="$1"
    echo "$message" | socat - UNIX-CONNECT:"$SOCKET_PATH"
}

# Check if the socket file exists and is a socket
if [ ! -S "$SOCKET_PATH" ]; then
    echo "Socket file does not exist or is not a socket: $SOCKET_PATH"
    echo "Please ensure the IPC server is running and the socket path is correct."
    exit 1
fi

# Function: Display help on startup
display_startup_help() {
    local help_response
    help_response=$(send_message "help")
    if [ $? -ne 0 ]; then
        echo "Failed to retrieve help message. Please check the socket connection."
    else
        echo "$help_response"
    fi
}

# Display help message upon startup
display_startup_help

# Main loop
while true; do
    # Use '>' as the prompt
    read -p ">" msg
    if [ "$msg" = "exit" ]; then
        echo "Exiting IPC client."
        break
    fi
    response=$(send_message "$msg")
    if [ $? -ne 0 ]; then
        echo "Failed to send message. Please check the socket connection."
    else
        # Display only the response without any prefix
        echo "$response"
    fi
done
