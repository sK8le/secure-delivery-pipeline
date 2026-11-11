# Secure Delivery Pipeline

![DevSecOps](https://github.com/sK8le/secure-delivery-pipeline/actions/workflows/security.yml/badge.svg)

Проект защищённого конвейера для веб-приложения: проверки кода и зависимостей, сборка контейнера, испытания в Kubernetes и мониторинг попыток подбора пароля. Для постоянного стенда предусмотрена локальная служба доставки: GitHub публикует проверенный образ, а ВМ применяет его по digest и подтверждает готовность. Настройка службы и первого пакета описана в [инструкции](docs/deployment.md).

Приложение - **VulnTrack**, трекер уязвимостей на FastAPI + PostgreSQL: аналитик импортирует отчёты сканеров и работает со списком уязвимостей своей команды.

**Стек:** Python 3.11 · FastAPI · SQLAlchemy · PostgreSQL 16 · Docker · Kubernetes (minikube, kind) · GitHub Actions · Gitleaks · Bandit · Semgrep · pip-audit · Trivy · OWASP ZAP · Prometheus · Grafana · Alertmanager

## Конвейер

![Граф заданий конвейера](docs/pipeline.png)

Первые четыре проверки идут параллельно. Сборка начинается, только если все они прошли. Образ собирается **один раз**, сканирование образа и DAST используют этот же артефакт. Задание «Все ворота пройдены» объединяет их результаты для защиты ветки.

Для `main` включено [правило защиты](https://github.com/sK8le/secure-delivery-pipeline/rules/26979774): изменения через PR, актуальная ветка, успешный итоговый статус от GitHub Actions, разрешённые обсуждения, запрет удаления и force push. Список обхода пуст.

| № | Этап | Инструменты | Что блокирует поставку |
|---|---|---|---|
| 1 | Поиск секретов | Gitleaks + собственное правило | Секрет в коммитах PR / push |
| 2 | SAST | Bandit, Semgrep (+ своё правило) | Находка Bandit ≥ MEDIUM, любое срабатывание Semgrep |
| 3 | SCA | pip-audit, Trivy fs, SBOM (CycloneDX) | Известная уязвимость в зависимостях (HIGH/CRITICAL с исправлением) |
| 4 | Тесты | pytest | Падение теста, в том числе регрессионные тесты мер защиты |
| 5 | Сборка | Docker (`docker save` → артефакт) | Ошибка сборки |
| 6 | Скан образа | Trivy image | HIGH/CRITICAL в итоговом образе |
| 7 | DAST | kind + OWASP ZAP, контроль отчёта | Любой High, правило FAIL, HTTP 5xx, потеря авторизации, неполный или недостоверный скан |
| 8 | Публикация | GHCR + release-манифест | Только push в main после всех ворот; проверяется тот же архив и анонимное скачивание |
| 9 | Выкладка на ВМ | Локальная служба + Kubernetes | Успешная текущая main, верный digest, готовность реплик и healthz; при отказе — откат |

Детали, которые стоит посмотреть в [`security.yml`](.github/workflows/security.yml):
- `permissions: contents: read` на весь workflow, расширение прав только точечно;
- `trivy-action` закреплён по SHA: в марте 2026 его теги были перезаписаны вредоносным кодом (CVE-2026-33634);
- DAST разворачивает те же манифесты, что и прод, в одноразовом кластере kind с одноразовыми секретами;
- ZAP сканирует под залогиненным пользователем, а решения по правилам задокументированы в [`.zap/rules.tsv`](.zap/rules.tsv);
- **закрытые ворота:** отдельно проверяются авторизация, доступ к контрольной записи, история запросов самого ZAP и завершение скана. Ошибка сканера блокирует поставку, даже если отчёт не содержит находок. Подробности: [политика DAST](docs/dast-gate.md).

Рядом лежит [`baseline.yml`](.github/workflows/baseline.yml): тот же проект без проверок безопасности (тесты → сборка → деплой). Он нужен для сравнения времени и результатов.

## Среда выполнения

**Образ** ([`Dockerfile`](Dockerfile)):
- многоэтапная сборка на `python:3.11-slim`;
- пользователь с UID 10001;
- из итогового образа удалены `pip`, `setuptools` и `wheel`;
- gunicorn + uvicorn workers, HEALTHCHECK.

Размер образа: **1,81 ГБ → 264 МБ** по сравнению с наивным `FROM python:3.11` + `COPY . .`.

**Kubernetes** ([`k8s/`](k8s/)):
- securityContext приложения уровня `restricted`: `runAsNonRoot`, `readOnlyRootFilesystem`, `drop: [ALL]`, seccomp `RuntimeDefault`, без токена сервисной учётки;
- Pod Security Admission: `enforce: baseline`, `warn/audit: restricted`;
- NetworkPolicy: всё входящее запрещено по умолчанию, к БД ходит только приложение, к метрикам — только из пространства имён monitoring;
- RBAC: учётка только на чтение;
- явно настроенные liveness/readiness-пробы и лимиты ресурсов;
- секреты в манифестах отсутствуют и создаются в кластере.

## Мониторинг атак

![Путь оповещения](docs/alerting.png)

Приложение экспортирует счётчик попыток входа. Правило Prometheus срабатывает, когда скорость неудачных входов превышает 0,1/с в течение минуты, и Alertmanager шлёт оповещение в Telegram. На тестовом стенде подбор пароля обнаруживался за **2 мин 21 с**. Неудачные входы дополнительно пишутся в журнал приложения (пользователь, IP).

## Что нашлось на практике

- **Ложный PASS в DAST.** `kubectl port-forward` рвался под нагрузкой активного скана, атакующие запросы не доходили, и XSS «не находилась». Решение: NodePort плюс проверка, что стенд жив после скана.
- **Уязвимости, которых нет в `requirements.txt`.** Скан образа нашёл CVE-2026-23949 и CVE-2026-24049 во встроенных зависимостях `setuptools` базового образа. Анализ зависимостей их не видел, а конвейер без проверок спокойно пропустил бы такой образ.
- **Подбор пароля как DoS.** bcrypt на каждую попытку, низкий лимит CPU и пробы по умолчанию (1 с) давали каскад перезапусков подов. Ни одни ворота конвейера этого не ловят, поймал только мониторинг.

## Быстрый старт

Локально через Docker Compose:

```bash
cp .env.example .env        # заполнить POSTGRES_PASSWORD и VULNTRACK_SECRET_KEY
docker compose up --build   # http://127.0.0.1:8000
```

В minikube (сетевые политики требуют CNI с их поддержкой):

```bash
minikube start --cni=calico
docker build -t vulntrack:local .
minikube image load vulntrack:local
kubectl apply -f k8s/00-namespace.yaml
# создать секреты — команды в комментарии k8s/01-config.yaml
kubectl apply -f k8s/01-config.yaml -f k8s/02-postgres.yaml -f k8s/03-web.yaml -f k8s/04-networkpolicy.yaml -f k8s/06-rbac.yaml
```

Тесты:

```bash
pip install -r requirements.txt -r requirements-dev.txt
VULNTRACK_SECRET_KEY=$(openssl rand -hex 32) pytest -q
```

Тесты создают собственный случайный ключ; секрет репозитория им не нужен. Временный стенд DAST получает отдельные случайные секреты приложения и PostgreSQL.

После регистрации пользователь ожидает назначения команды администратором. Через Docker Compose:

```bash
docker compose exec web python -m app.manage assign-team --username alice --team blue
```

В Kubernetes:

```bash
kubectl -n vulntrack exec deployment/vulntrack-web -- python -m app.manage assign-team --username alice --team blue
```

Доступны только записи назначенной команды. Подмена поля `team` при регистрации или импорте не меняет права. См. [модель доступа и проверку](docs/team-access.md).

## Известные ограничения

- Нет CSRF-токенов в формах. Частично смягчает `SameSite=Lax`, правило ZAP 10202 стоит как WARN.
- Нет ограничения частоты попыток входа (rate limiting), поэтому атака на `/login` грузит CPU.
- Назначение команд выполняется операторской командой; отдельного административного веб-интерфейса нет. Ранее созданные учётные записи нужно проверить перед обновлением.
- Исходящий трафик подов не ограничен.
- Секреты хранятся в объектах Secret; для прода — Vault или Sealed Secrets.
- `pip-audit` и `semgrep` в `requirements-dev.txt` не закреплены по версиям.
- Остальные GitHub Actions подключены по тегам, по SHA закреплён только Trivy.
- Локальную службу доставки и публичность пакета GHCR необходимо настроить по [инструкции](docs/deployment.md). Публикация в GitHub и готовность приложения на ВМ подтверждаются разными отчётами.

