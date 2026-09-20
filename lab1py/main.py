from task1 import main as run_task1
from task2 import main as run_task2
from task3 import main as run_task3

def main():
    print("=" * 50)
    print(">>> ЗАПУСК ЗАВДАННЯ 1 <<<")
    print("=" * 50)
    run_task1()

    print("\n" + "=" * 50)
    print(">>> ЗАПУСК ЗАВДАННЯ 2 <<<")
    print("=" * 50)
    run_task2()

    print("\n" + "=" * 50)
    print(">>> ЗАПУСК ЗАВДАННЯ 3 <<<")
    print("=" * 50)
    run_task3()

if __name__ == "__main__":
    main()