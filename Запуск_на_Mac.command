#!/bin/bash
# Локальный запуск без установки пакетов и сетевых запросов.
cd -- "$(dirname -- "$0")" || exit 1
task_python=""
for candidate in /usr/local/bin/python3 /opt/homebrew/bin/python3 "$(command -v python3)" "$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"; do
    if [ -x "$candidate" ] && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
        task_python="$candidate"
        break
    fi
done
if [ -z "$task_python" ]; then
    echo 'Нужен Python 3.10 или новее. На этом компьютере подходящий Python не найден.'
    echo 'Инструкция находится в README.md. Дополнительные библиотеки не требуются.'
    read -r -p 'Нажмите Enter, чтобы закрыть окно.'
    exit 1
fi
if [ "${1:-}" = '--check' ]; then
    exec "$task_python" hash_study.py check
fi
"$task_python" mac_menu.py "$@"
task_exit=$?
if [ "$task_exit" -ne 0 ]; then
    echo 'Возникла ошибка. Текст выше поможет выяснить причину.'
    read -r -p 'Нажмите Enter, чтобы закрыть окно.'
fi
exit "$task_exit"
