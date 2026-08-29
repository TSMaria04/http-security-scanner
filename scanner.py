import requests
from colorama import Fore, Style, init

# Инициализация цветного вывода в консоли
init(autoreset=True)

# Заголовки безопасности для проверки
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Защита от MITM-атак и принудительное использование HTTPS (HSTS).",
        "risk": "Высокий"
    },
    "Content-Security-Policy": {
        "description": "Защита от XSS-атак и межсайтового внедрения скриптов.",
        "risk": "Высокий"
    },
    "X-Frame-Options": {
        "description": "Защита от Clickjacking (запрещает встраивать сайт в iframe).",
        "risk": "Средний"
    },
    "X-Content-Type-Options": {
        "description": "Запрещает браузеру угадывать MIME-тип файла (MIME-sniffing).",
        "risk": "Низкий"
    },
    "Referrer-Policy": {
        "description": "Контролирует передачу конфиденциальных данных в заголовке Referer.",
        "risk": "Низкий"
    },
    "Permissions-Policy": {
        "description": "Ограничивает доступ к функциям браузера (камера, микрофон, геолокация).",
        "risk": "Низкий"
    }
}

def scan_website(url):
    # Добавляем https://, если пользователь ввёл адрес без него
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n{Fore.CYAN}==================================================")
    print(f"{Fore.CYAN}[*] Начинаем сканирование: {url}")
    print(f"{Fore.CYAN}==================================================\n")

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        missing_count = 0
        present_count = 0

        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                print(f"{Fore.GREEN}[+] НАЙДЕН: {header}")
                print(f"    Значение: {headers[header][:60]}...")
                present_count += 1
            else:
                print(f"{Fore.RED}[-] ОТСУТСТВУЕТ: {header}")
                print(f"    Риск: {info['risk']} | {info['description']}")
                missing_count += 1
            print("-" * 50)

        # Итоговая статистика
        print(f"\n{Fore.YELLOW}=== ИТОГИ СКАНИРОВАНИЯ ===")
        print(f"{Fore.GREEN}Найдено защитных заголовков: {present_count}/{len(SECURITY_HEADERS)}")
        print(f"{Fore.RED}Отсутствует заголовков: {missing_count}/{len(SECURITY_HEADERS)}")

        score = (present_count / len(SECURITY_HEADERS)) * 100
        print(f"\nОбщий уровень защищенности: ", end="")
        if score >= 80:
            print(f"{Fore.GREEN}ОТЛИЧНЫЙ ({score:.0f}%)")
        elif score >= 50:
            print(f"{Fore.YELLOW}СРЕДНИЙ ({score:.0f}%)")
        else:
            print(f"{Fore.RED}НИЗКИЙ ({score:.0f}%)")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Ошибка при подключении к {url}: {e}")

if __name__ == "__main__":
    target_url = input("Введите URL сайта для проверки (например, github.com): ").strip()
    if target_url:
        scan_website(target_url)
    else:
        print("URL не был введён.")