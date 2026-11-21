# Риск вызовов агента — IAM 604

Учебный ML-проект Даниила Бурдыгина для ML System Design, ИТМО, осень 2026.
Модель оценивает риск следующего вызова инструмента ИИ-агентом с учётом задачи,
ресурса и предыдущих действий. Оценка помогает отправлять опасные вызовы на
подтверждение. Проверка прав и ограничение возможностей выполняются отдельно.

## Задача и границы

Внутри разрешённого доступа агент может выбрать неверный объект или сочетать
чтение чувствительных данных с внешней отправкой. Одинаковые права ещё не
означают одинаковый риск для текущего поручения. Сравниваем правила,
логистическую регрессию и модель на табличных признаках по полноте обнаружения
опасных действий при ограниченном числе ложных тревог.

Связь с [проектом Enterprise IAM 604](https://talenttrack.aitalenthub.ru/projects/604) —
исследование дополнительного сигнала риска на шлюзе инструментов. Автор участвует
в проекте; распределение в команде, интерфейс интеграции и использование темы ещё
требуют согласования с руководителем. Дизайн не объявляет эту ML-часть требованием
команды проекта 604.

**Состояние ДЗ2:** собраны пилотный синтетический набор v0 (1 500 семейств сценариев,
17 453 вызова) и таблицы из открытых трасс AgentDojo, проведён EDA, в дизайне заполнен
раздел «Этапы решения задачи». Модели ещё не обучались. Основной источник данных —
собственная синтетика; AgentDojo служит внешней проверкой.

## Документы

- [Дизайн системы](docs/ml_system_design_doc.md): цели, требования, scope,
  предпосылки, ML-задача, схемы baseline/MVP, данные и план проверки.
- [Отчёт EDA](reports/eda.md): состав, качество и выводы по обоим наборам.
- [Источники](docs/sources.md): условия ДЗ1 и ДЗ2, занятия курса и основания решений.

## Локальная работа

Нужны Git, Node.js 22 или новее, npm, Python 3.11 или новее и `uv`.
Python-пакет `agent-risk` содержит словарь стенда (`catalog`), скрытое состояние
(`world`), признаки шлюза (`gateway`), эталон последствий (`oracle`), правила B0/B1/B1+
(`rules`), генератор синтетики (`synthetic`) и извлечение трасс AgentDojo (`agentdojo`).
Модели появятся в следующей итерации.

```bash
npm ci
uv sync --locked --python 3.11
uv tool install pre-commit==4.7.0
pre-commit install
pre-commit run --all-files
```

`uv sync` устанавливает пакет из `src/` и инструменты разработки в `.venv/`.
`uv.lock` фиксирует зависимости Python. Установленный бинарь `pre-commit`
должен быть доступен через `PATH`.

```bash
npm run format        # форматирование Markdown, YAML и JSON
npm run format:check  # проверка форматирования
npm run lint         # структура Markdown
uv run --frozen ruff check src tests
uv run --frozen ruff format --check src tests
uv run --frozen mypy
uv run --frozen pytest
```

Ruff проверяет и форматирует Python; mypy проверяет `src/` и `tests/` в строгом
режиме. Для автоформатирования Python: `uv run --frozen ruff format src tests`.
Pre-commit запускает Ruff и mypy, проверяет YAML/JSON/TOML, окончания строк,
конфликтные маркеры и крупные файлы. GitHub Actions запускает эти проверки
и отдельный job с pytest на Python 3.11 и 3.12.
Тесты проверяют метки эталона на контрастных примерах дизайна, скрытие сведений
при неполном контексте, детерминированность генератора, разбор трасс и правила.
Зелёные проверки не измеряют качество ML.

## Данные и EDA

```bash
uv run --frozen python -m agent_risk generate --out data/synthetic/v0
uv sync --locked --group eda
uv run --frozen --group eda jupyter nbconvert --to notebook --execute --inplace \
  notebooks/01_eda_synthetic.ipynb notebooks/02_eda_agentdojo.ipynb
```

Генерация детерминирована: те же seed и версия дают те же байты, хеши лежат
в `data/synthetic/v0/manifest.json`. Таблицы AgentDojo строятся из трасс репозитория
[AgentDojo](https://github.com/ethz-spylab/agentdojo) на коммите `089ed46` (лицензия MIT,
текст — `data/external/agentdojo/LICENSE-agentdojo.txt`):

```bash
git clone --filter=blob:none --no-checkout https://github.com/ethz-spylab/agentdojo .cache/agentdojo
git -C .cache/agentdojo sparse-checkout set runs/gpt-4o-2024-05-13 \
  runs/claude-3-5-sonnet-20241022 runs/meta-llama_Llama-3.3-70B-Instruct
git -C .cache/agentdojo checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
uv run --frozen python -m agent_risk agentdojo --runs .cache/agentdojo/runs \
  --out data/external/agentdojo --commit 089ed468cf3ed0322acc66b0211f26d9d90dbf60
```

Рисунки отчёта ноутбуки сохраняют в `reports/figures/`.

## Порядок сдачи

Работа по [ДЗ1](https://gist.github.com/pacifikus/47424379293e0874859354ecd130ba13)
находится в ветке `hw_1`, по [ДЗ2](https://gist.github.com/pacifikus/bada0e4b597852e4bb50512daf451929) —
в ветке `hw_2`, которая продолжает `hw_1`. PR объединяются в `main` после ревью ментора
и двух студентов курса.
