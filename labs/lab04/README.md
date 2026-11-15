# Лабораторна робота № 4

**Тема:** інтеграція із зовнішніми Web API та автоматизоване тестування
Python-коду.  
**Варіант:** 8 — зміна меж впливу (`scope`).

## Правило варіанта

Запис позначається для ручного огляду (`review`), якщо у **вибраній**
оцінці CVSS v3.1 одночасно:

```text
baseScore >= 9.0  і  cvssData.scope == "CHANGED"
```

`scope = CHANGED` означає, що успішна атака виходить за межі повноважень
уразливого компонента й зачіпає інші компоненти (наприклад, втеча з
пісочниці чи віртуальної машини). Число й ознака беруться з однієї оцінки:
першої з `type = "Primary"`, а якщо такої немає — першої в
`metrics.cvssMetricV31`. Поріг 9.0 — навчальний параметр, а не нова
категорія CVSS.

Номер варіанта береться з `shared/student.py` (`VARIANT_NUMBER = 8`).
Правила всіх 15 варіантів описані в `analysis.VARIANT_RULES`.

## Структура

```text
labs/lab04/
├── __init__.py
├── main.py              # argparse, вибір джерела даних, повідомлення, коди
├── api_client.py        # build_headers() і один GET-запит до NVD
├── analysis.py          # extract_record() і build_report()
├── data/
│   └── nvd_sample.json  # синтетичний запис CVE-2099-10001
├── tests/
│   ├── conftest.py      # заборона мережі та видалення NVD_API_KEY
│   ├── factories.py     # фабрики синтетичних відповідей
│   ├── test_analysis.py # правило, межі порога, стани, помилки даних
│   ├── test_api_client.py # заголовки, параметри запиту, HTTP-помилки
│   └── test_main.py     # CLI, локальний режим, коди завершення
├── README.md
└── REPORT.md            # звіт до здачі
```

## Встановлення

Команди виконуйте з кореня репозиторію в активованому віртуальному
середовищі з Python 3.12 або новішим:

```powershell
python -m pip install -r requirements.txt
```

Нові залежності роботи: `requests==2.34.2`, `pytest==9.1.1`
(`ruff==0.17.0` уже був у файлі).

## Запуск

Локальний режим (без мережі):

```powershell
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Один ручний запит до NVD:

```powershell
python -m labs.lab04.main --cve CVE-2021-44228
```

Ключ API необов'язковий. Якщо він є, задайте його лише у змінній
середовища поточного сеансу (не у файлах проєкту):

```powershell
$env:NVD_API_KEY = "ваш-ключ"      # PowerShell
export NVD_API_KEY="ваш-ключ"      # bash
```

Ключ передається в заголовку `apiKey`, а не в URL. Запит виконується з
`timeout=(3.05, 10)`, без перенаправлень і з перевіркою TLS.

### Аргументи

| Аргумент | Опис |
| --- | --- |
| `--cve` | Обов'язковий. Повний збіг із `CVE-[0-9]{4}-[0-9]{4,}`, регістр важливий |
| `--input` | Необов'язковий шлях до UTF-8 JSON-відповіді NVD; мережа не використовується |

### Коди завершення

| Код | Значення |
| --- | --- |
| 0 | Звіт сформовано (включно з `not_found` та `insufficient_data`) |
| 1 | Помилка отримання, читання чи перевірки даних |
| 2 | Неправильні аргументи або номер варіанта |

У `stdout` друкується лише JSON-звіт; повідомлення про помилки — у
`stderr`, без трасування стека, ключа, заголовків і тіла відповіді.

## Формат звіту

```json
{
  "cve_id": "CVE-2099-10001",
  "variant": 8,
  "description": "Synthetic vulnerability for offline API testing.",
  "vuln_status": "Analyzed",
  "cvss_version": "3.1",
  "score": 9.8,
  "score_source": "nvd@nist.gov",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "rule": {
    "threshold": 9.0,
    "field": "scope",
    "expected": "CHANGED"
  },
  "observed": "UNCHANGED",
  "decision": "other"
}
```

Стани `decision` (у порядку застосування):

| Стан | Умова |
| --- | --- |
| `not_found` | `vulnerabilities` порожній |
| `rejected` | `vulnStatus == "Rejected"` (оцінки не аналізуються) |
| `insufficient_data` | немає статусу, оцінки v3.1 або поля `scope` |
| `review` | `score >= 9.0` і `scope == "CHANGED"` |
| `other` | даних достатньо, але умова не виконується |

`other` та `insufficient_data` не означають, що вразливість безпечна, а
`review` — лише відповідність навчальному правилу.

## Перевірка

```powershell
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Тести не звертаються до мережі: `tests/conftest.py` автоматично прибирає
`requests.sessions.Session.request` і змінну `NVD_API_KEY` перед кожним
тестом. Окремий тест можна перезапустити з ідентифікатором, наприклад:

```powershell
python -m pytest "labs/lab04/tests/test_analysis.py::test_decision_by_score_and_scope[9.0-CHANGED-review]" -v
```
