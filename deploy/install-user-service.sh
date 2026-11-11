#!/usr/bin/env bash
set -euo pipefail

project_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
library_directory="$HOME/.local/lib/vulntrack-delivery"
unit_directory="$HOME/.config/systemd/user"

install -d -m 700 "$library_directory" "$unit_directory" "$HOME/.local/state/vulntrack-delivery"
install -m 600 "$project_directory/scripts/deploy_verified.py" "$project_directory/scripts/delivery_common.py" "$library_directory/"
install -m 600 "$project_directory/deploy/vulntrack-delivery.service" "$project_directory/deploy/vulntrack-delivery.timer" "$unit_directory/"
systemctl --user daemon-reload
printf '%s\n' 'Служба установлена. Таймер ещё не включён.'
printf '%s\n' 'Проверка: /usr/bin/python3 ~/.local/lib/vulntrack-delivery/deploy_verified.py --check-only'
printf '%s\n' 'Включение: systemctl --user enable --now vulntrack-delivery.timer'
