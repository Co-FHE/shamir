#!/bin/bash

# 死循环，直到用户手动停止
while true; do
    # 提示用户输入指令，显示 > 作为提示符
    read -p "> " user_command

    # 如果用户输入 'exit'，则退出循环
    if [[ "$user_command" == "exit" ]]; then
        echo "退出程序。"
        break
    fi

    # 拼接指令
    final_command="cargo run --release -p veritss -- $user_command"

    # 打印并执行最终命令
    echo "执行命令：$final_command"
    $final_command
done