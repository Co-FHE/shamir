#!/bin/bash

# Infinite loop until user manually stops
while true; do
    # Prompt user for input with > as prompt
    read -p "> " user_command

    # Exit loop if user enters 'exit'
    if [[ "$user_command" == "exit" ]]; then
        echo "Exiting program."
        break
    fi

    # Construct command
    final_command="cargo run --release -p tss -- $user_command"

    # Print and execute final command
    echo "Executing command: $final_command"
    $final_command
done