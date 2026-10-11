"""Точка входу для лабораторної роботи № 2."""

import sys
from pathlib import Path

if __package__:
    from .task2 import main
else:
    # PyCharm може запускати файл напряму, без контексту пакета.
    project_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(project_root))
    from labs.lab02.task2 import main

if __name__ == "__main__":
    raise SystemExit(main())
