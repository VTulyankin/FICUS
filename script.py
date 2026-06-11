import os
import sys
import hashlib
import json
import argparse
import re
import fnmatch
import time


class IntegrityChecker:
    DEFAULT_CONFIG = {
        'database_path': 'hash_database.json',
        'report_path': 'reports/report_%Y-%m-%d_%H-%M-%S.log',
        'schedule': '',
        'default_args': 'scan full',
        'include': [
            '/etc', '/bin', '/sbin', '/home'
        ],
        'exclude': [
            '/tmp', '/proc', '/sys', '/dev', '/run',
            'mask:*.tmp', 'mask:*.cache', 'mask:*.log'
        ],
        'follow_symlinks': False,
        'verbosity': 'verbose',
        'use_colors': True
    }

    COLORS = {
        'info': '\033[94m',
        'warn': '\033[93m',
        'error': '\033[91m',
        'result': '\033[92m',
        'report': '',
        'endc': '\033[0m',
    }

    PREFIXES = {
        'info': '[*]',
        'warn': '[WARN]',
        'error': '[ERROR]',
        'result': '',
        'report': '',
    }

    VERBOSITY_MAP = {
        'verbose': ['info', 'warn', 'error', 'result'],
        'quiet': ['error', 'result'],
        'silent': []
    }

    SCAN_TYPE_HASH = ['h', 'hash', 'hashes']
    SCAN_TYPE_PATHS = ['p', 'path', 'paths']

    def __init__(self):
        self.config = self.DEFAULT_CONFIG.copy()
        self.report_file_handler = None
        self.base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.updated_db_path = None

    def setup_config(self, config_path, use_default=False):
        if use_default:
            self.log("Конфигурационный файл проигнорирован, используется конфигурация по умолчанию", level='info')
            return

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                if not isinstance(file_config, dict):
                    raise ValueError("Конфигурационный файл должен содержать JSON объект (словарь)")
                if 'include' in file_config and not isinstance(file_config['include'], list):
                    raise ValueError("Ключ 'include' должен быть списком")
                if 'exclude' in file_config and not isinstance(file_config['exclude'], list):
                    raise ValueError("Ключ 'exclude' должен быть списком")
                self.config.update(file_config)
            except (json.JSONDecodeError, OSError, ValueError) as e:
                self.log(f"Ошибка чтения конфигурационного файла '{config_path}': {e}",
                         level='error')
                sys.exit(2)
        else:
            try:
                self.save_config(config_path)
                self.log(f"Конфигурационный файл не найден. Создан файл по умолчанию: {config_path}",
                         level='warn')
            except OSError as e:
                self.log(f"Не удалось создать конфигурационный файл '{config_path}': {e}",
                         level='error')

    def log(self, messages, level='info'):
        if isinstance(messages, str):
            messages = [messages]

        prefix = self.PREFIXES.get(level, f"[{level.upper()}]")

        current_verbosity = self.config['verbosity']
        allowed_levels = self.VERBOSITY_MAP.get(current_verbosity, [])
        use_colors = self.config.get('use_colors', True)

        for message in messages:
            if self.report_file_handler:
                uncolored_line = f"{prefix} {message}".strip()
                self.report_file_handler.write(uncolored_line + '\n')
                self.report_file_handler.flush()

            if level not in allowed_levels:
                continue

            if use_colors and sys.stderr.isatty():
                color = self.COLORS.get(level, '')
                endc = self.COLORS['endc']
                formatted_prefix = f"{color}{prefix}{endc} " if prefix else ""
            else:
                formatted_prefix = f"{prefix} " if prefix else ""

            print(f"{formatted_prefix}{message}", file=sys.stderr)

    def setup_report(self, report_arg):
        report_template = self.config.get('report_path')
        if not report_template:
            return

        if report_arg is None:
            final_report_path = time.strftime(report_template)
        else:
            if report_arg.endswith('/') or report_arg.endswith('\\'):
                filename_template = os.path.basename(report_template)
                formatted_filename = time.strftime(filename_template)
                final_report_path = os.path.join(report_arg, formatted_filename)
            else:
                final_report_path = report_arg

        try:
            if not os.path.isabs(final_report_path):
                final_report_path = os.path.join(self.base_dir, final_report_path)
            report_dir = os.path.dirname(final_report_path)
            os.makedirs(report_dir, exist_ok=True)
            self.report_file_handler = open(final_report_path, 'w', encoding='utf-8')
        except (OSError, TypeError) as e:
            self.log(f"Не удалось создать файл отчета: {e}", level='error')
            self.report_file_handler = None

    def report(self, stage, results=None, is_new_db=False):
        if stage == 'start':
            start_time = time.strftime("%Y-%m-%d %H:%M:%S")
            reason = "По расписанию (cron)" if os.environ.get("FICUS_CRON_MARKER") else "Ручной запуск"
            args_str = " ".join(sys.argv)

            header_lines = [
                f"Время запуска: {start_time}",
                f"Причина запуска: {reason}",
                f"Аргументы командной строки: {args_str}",
                "",
                "ЛОГИ ОПЕРАЦИЙ:"
            ]
            self.log(header_lines, level='report')

        elif stage == 'end':
            file_results_header = [
                "",
                "РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:"
            ]
            self.log(file_results_header, level='report')

            results_lines = []
            if is_new_db:
                results_lines.append("Инициализация начальной базы данных завершена.")
            else:
                has_changes = False
                if results:
                    for status, items in results.items():
                        if items:
                            has_changes = True
                            results_lines.append(f"{status.upper()}:")
                            for item in items:
                                results_lines.append(f"  - {item}")

                if not has_changes:
                    results_lines.append("Проверка завершена. Изменений не найдено.")
                else:
                    results_lines.append("Проверка завершена. Обнаружены изменения.")

            self.log(results_lines, level='result')

            config_lines = [
                "",
                "ТЕКУЩАЯ КОНФИГУРАЦИЯ:"
            ]
            try:
                config_str = json.dumps(self.config, indent=4, ensure_ascii=False)
                config_lines.extend(config_str.splitlines())
            except Exception as e:
                config_lines.append(f"Ошибка форматирования конфигурации: {e}")

            self.log(config_lines, level='report')

    def display_progress(self, iteration, total, prefix='', suffix='', length=20):
        if self.config['verbosity'] != 'verbose':
            return

        try:
            terminal_width = os.get_terminal_size().columns
        except OSError:
            terminal_width = 80

        use_colors = self.config.get('use_colors', True) and sys.stdout.isatty()
        color = self.COLORS['info'] if use_colors else ''
        endc = self.COLORS['endc'] if use_colors else ''

        if total > 0:
            percent = "{0:.1f}".format(100 * (iteration / float(total)))
            filled_length = int(length * iteration // total)
            bar_filled = '=' * filled_length
            bar_unfilled = ' ' * (length - filled_length)
            indicator = f"{bar_filled}{bar_unfilled}"
            header = f" {prefix}: {percent}% ({iteration}/{total})"
        else:
            spinner_chars = ['/', '-', '\\', '|']
            indicator = spinner_chars[iteration % len(spinner_chars)]
            header = f" {prefix}:"

        colored_indicator = f"{color}[{indicator}]{endc}"

        uncolored_len = len(f"[{indicator}]") + len(header)
        max_suffix_len = terminal_width - uncolored_len - 2

        if len(suffix) > max_suffix_len > 0:
            suffix = "..." + suffix[-max_suffix_len + 3:]

        output_str = f'\r\033[2K{colored_indicator}{header} {suffix}'

        sys.stdout.write(output_str)
        sys.stdout.flush()

    def clear_progress_line(self):
        if self.config['verbosity'] == 'verbose':
            sys.stdout.write('\r\033[2K')
            sys.stdout.flush()

    def setup_parser(self):
        if len(sys.argv) == 1:
            sys.argv.extend(self.config['default_args'].split())

        parser = argparse.ArgumentParser(description='WIP')

        parser.add_argument('--default-config', action='store_true', help='WIP')

        verbosity_group = parser.add_mutually_exclusive_group()
        verbosity_group.add_argument('-v', '--verbose', action='store_const',
                                     dest='verbosity', const='verbose', help='WIP')
        verbosity_group.add_argument('-q', '--quiet', action='store_const',
                                     dest='verbosity', const='quiet', help='WIP')
        verbosity_group.add_argument('-s', '--silent', action='store_const',
                                     dest='verbosity', const='silent', help='WIP')

        subparsers = parser.add_subparsers(dest='command', required=True,
                                           help='Доступные команды')

        parser_scan = subparsers.add_parser('scan', aliases=['s'], help='WIP')
        scan_choices = self.SCAN_TYPE_HASH + self.SCAN_TYPE_PATHS + ['full']
        parser_scan.add_argument('scan_type', nargs='?', choices=scan_choices,
                                 default='full', help='WIP')
        parser_scan.add_argument('-u', '--update', dest='update', action='store_true', help='WIP')

        subparsers.add_parser('config', help='WIP')
        subparsers.add_parser('install-cron', help='WIP')
        subparsers.add_parser('remove-cron', help='WIP')

        try:
            args, unknown_args = parser.parse_known_args()
            if hasattr(args, 'scan_type'):
                if args.scan_type in self.SCAN_TYPE_PATHS:
                    args.scan_type = 'paths'
                elif args.scan_type in self.SCAN_TYPE_HASH:
                    args.scan_type = 'hashes'
            args.modifiers = unknown_args
            return args
        except SystemExit:
            print("[ERROR] Неверные аргументы командной строки", file=sys.stderr)
            sys.exit(2)

    def compile_rules(self, rules):
        compiled = []
        for rule in rules:
            if not isinstance(rule, str) or not rule:
                continue
            try:
                pattern = rule
                if pattern.startswith('mask:'):
                    pattern = fnmatch.translate(pattern.split('mask:')[1])
                else:
                    pattern = re.escape(pattern)
                    if not rule.startswith('/'):
                        pattern = f".*{pattern}"

                compiled.append(re.compile(f"^{pattern}$"))

            except re.error as e:
                self.log(f"Ошибка компиляции регулярного выражения для правила '{rule}': {e}", level='error')
        return compiled

    def save_config(self, config_path):
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except OSError as e:
            self.log(f"Не удалось сохранить конфигурационный файл '{config_path}': {e}", level='error')
            raise

    def apply_dynamic_config(self, modifiers):
        if not modifiers:
            return

        current_key = None
        list_action = None

        for token in modifiers:
            if token.startswith('--'):
                key = token[2:]
                if key in self.config:
                    current_key = key
                    list_action = None
                    if type(self.config[current_key]) is str:
                        self.config[current_key] = ""
                else:
                    self.log(f"Неизвестный параметр конфигурации: {key}", level='warn')
                    current_key = None
            elif current_key:
                val_type = type(self.config[current_key])
                if val_type is list:
                    if token in ('add', 'remove'):
                        list_action = token
                    elif list_action == 'add':
                        if token not in self.config[current_key]:
                            self.config[current_key].append(token)
                    elif list_action == 'remove':
                        if token in self.config[current_key]:
                            self.config[current_key].remove(token)
                elif val_type is bool:
                    self.config[current_key] = (token.lower() == 'true')
                elif val_type is str:
                    if self.config[current_key]:
                        self.config[current_key] += f" {token}"
                    else:
                        self.config[current_key] = token
                else:
                    try:
                        self.config[current_key] = val_type(token)
                    except ValueError:
                        self.log(f"Неверный тип значения для {current_key}", level='warn')

    def install_cron(self):
        schedule = self.config.get('schedule', '').strip()
        if not schedule:
            self.log("Поле 'schedule' в конфигурации пустое. Нечего устанавливать.", level='error')
            return

        script_path = os.path.abspath(sys.argv[0])
        marker = "FICUS_CRON_MARKER=true"
        cron_command = f"env {marker} flock -n /tmp/ficus.lock {sys.executable} {script_path} {self.config['default_args']}"
        cron_job = f"{schedule} {cron_command}"

        try:
            import subprocess
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""

            lines = [line for line in current_cron.splitlines() if not (marker in line and script_path in line)]
            lines.append(cron_job)

            new_cron = "\n".join(lines) + "\n"
            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(new_cron)

            if process.returncode == 0:
                self.log(f"Задача успешно добавлена в cron:\n  {cron_job}", level='result')
            else:
                self.log("Ошибка при обновлении crontab.", level='error')
        except Exception as e:
            self.log(f"Не удалось установить cron: {e}", level='error')

    def remove_cron(self):
        script_path = os.path.abspath(sys.argv[0])
        marker = "FICUS_CRON_MARKER=true"
        try:
            import subprocess
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode != 0:
                self.log("Crontab пуст или недоступен.", level='info')
                return

            current_cron = result.stdout
            lines = current_cron.splitlines()
            new_lines = [line for line in lines if not (marker in line and script_path in line)]

            if len(lines) == len(new_lines):
                self.log("Задача не найдена в cron.", level='info')
                return

            new_cron = "\n".join(new_lines) + "\n" if new_lines else ""

            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(new_cron)

            if process.returncode == 0:
                self.log("Задача успешно удалена из cron.", level='result')
            else:
                self.log("Ошибка при обновлении crontab.", level='error')
        except Exception as e:
            self.log(f"Не удалось удалить cron: {e}", level='error')

    def scan_paths(self, include_paths, include_rules, exclude_rules):
        visited_inodes = set()
        spinner_count = 0
        follow_symlinks = self.config.get('follow_symlinks', False)

        target_dirs_tuple = tuple(
            os.path.abspath(p) + os.sep if not os.path.abspath(p).endswith(os.sep) else os.path.abspath(p)
            for p in include_paths
        )
        exact_target_dirs = set(os.path.abspath(p) for p in include_paths)

        stack = []
        roots_to_scan = set(include_paths)

        if include_rules:
            roots_to_scan.add('/')

        for path in roots_to_scan:
            if not os.path.exists(path):
                self.log(f"Путь '{path}' не найден (пропуск)", level='warn')
                continue

            if not os.path.isdir(path):
                yield path
                continue

            stack.append(path)

        while stack:
            current_dir = stack.pop()
            spinner_count += 1
            self.display_progress(spinner_count, 0, prefix='Сканирование', suffix=current_dir)

            try:
                stat_info = os.stat(current_dir, follow_symlinks=follow_symlinks)
                inode = (stat_info.st_dev, stat_info.st_ino)
                if inode in visited_inodes:
                    continue
                visited_inodes.add(inode)
            except OSError:
                continue

            try:
                with os.scandir(current_dir) as it:
                    for entry in it:
                        full_path = entry.path

                        if exclude_rules and any(r.match(full_path) for r in exclude_rules):
                            continue

                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            stack.append(full_path)
                        elif entry.is_file(follow_symlinks=follow_symlinks):
                            in_target = full_path in exact_target_dirs or any(
                                full_path.startswith(d) for d in target_dirs_tuple)
                            matches_mask = include_rules and any(r.match(full_path) for r in include_rules)

                            if in_target or matches_mask:
                                yield full_path
            except OSError:
                continue

    def scan_hashes(self, target_files, existing_data):
        current_hashes = {}
        report = {'Изменены': [], 'Ошибки доступа': []}
        total = len(target_files)

        for i, path in enumerate(target_files):
            self.display_progress(i + 1, total, prefix='Получение хэшей', suffix=path)
            hash_value = None
            try:
                with open(path, "rb") as f:
                    file_hash = hashlib.sha256()
                    while chunk := f.read(8192):
                        file_hash.update(chunk)
                    hash_value = file_hash.hexdigest()
            except (OSError, PermissionError) as e:
                self.clear_progress_line()
                self.log(f"Не удалось прочитать файл '{path}': {e}", level='warn')
                report['Ошибки доступа'].append(path)
                hash_value = "ACCESS_DENIED"

            current_hashes[path] = hash_value

            if path in existing_data and existing_data[path] != hash_value:
                report['Изменены'].append(path)

        if total > 0:
            self.clear_progress_line()

        return report, current_hashes

    def setup_database(self, db_path):
        data = {}
        if not os.path.exists(db_path):
            self.log("База данных не найдена. Будет создана начальная база", level='warn')
            return data, True, True

        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            self.log(f"Ошибка чтения базы данных ({e}).", level='error')
            return None, False, False
        return data, True, False

    def update_database(self, db_path, current_data):
        try:
            with open(db_path, 'w', encoding='utf-8') as f:
                json.dump(current_data, f, indent=4, sort_keys=True, ensure_ascii=False)
            self.updated_db_path = db_path
        except OSError as e:
            self.log(f"Ошибка записи в базу данных: {e}", level='error')

    def run(self):
        try:
            args = self.setup_parser()
            config_path = os.path.join(self.base_dir, 'config.json')
            self.setup_config(config_path, args.default_config)

            if args.verbosity is not None:
                self.config['verbosity'] = args.verbosity

            self.apply_dynamic_config(args.modifiers)

            if self.config.get('report_path'):
                self.setup_report(None)

            self.report(stage='start')

            if args.command == 'config':
                if not args.modifiers:
                    import subprocess
                    try:
                        subprocess.run(['nano', config_path])
                    except FileNotFoundError:
                        self.log("Редактор nano не найден в системе", level='error')
                        sys.exit(1)
                else:
                    self.save_config(config_path)
                    keys_modified = [arg[2:] for arg in args.modifiers if arg.startswith('--')]
                    for key in keys_modified:
                        if key in self.config:
                            self.log(f"{key}: {self.config[key]} успешно сохранено в {config_path}", level='result')
                sys.exit(0)

            if args.command == 'install-cron':
                if args.modifiers:
                    self.save_config(config_path)
                self.install_cron()
                sys.exit(0)

            if args.command == 'remove-cron':
                self.remove_cron()
                sys.exit(0)

            if args.command not in ['scan', 's']:
                sys.exit(0)

            db_path = self.config['database_path']
            if not os.path.isabs(db_path):
                args.db = os.path.join(self.base_dir, db_path)
            else:
                args.db = db_path

            start_time = time.time()
            existing_data, success, is_new_db = self.setup_database(args.db)
            if not success:
                sys.exit(2)

            if is_new_db:
                args.update = True

            report_data = {}
            new_db_data = existing_data.copy()

            run_paths = args.scan_type in ('paths', 'full')
            run_hashes = args.scan_type in ('hashes', 'full')

            if run_paths:
                include_rules = self.compile_rules([r for r in self.config['include'] if r.startswith('mask:')])
                exclude_rules = self.compile_rules(self.config['exclude'])
                include_paths = [r for r in self.config['include'] if not r.startswith('mask:')]

                current_files = list(self.scan_paths(include_paths, include_rules, exclude_rules))
                self.clear_progress_line()

                master_set = set(existing_data.keys())
                current_set = set(current_files)

                report_data['Новые'] = sorted(list(current_set - master_set))
                report_data['Удалены'] = sorted(list(master_set - current_set))

                if args.update:
                    for p in report_data.get('Удалены', []):
                        new_db_data.pop(p, None)
                    for p in report_data.get('Новые', []):
                        if p not in new_db_data:
                            new_db_data[p] = ""
            else:
                current_files = list(existing_data.keys())

            if run_hashes:
                files_to_hash = sorted(current_files)
                hash_report, current_hashes = self.scan_hashes(files_to_hash, existing_data)
                report_data.update(hash_report)

                if args.update:
                    new_db_data.update(current_hashes)

            if args.update:
                self.update_database(args.db, new_db_data)

            elapsed_time = time.time() - start_time
            stats_message = f"Статистика: обработано {len(current_files)} файлов за {elapsed_time:.2f} сек"
            self.log(stats_message, level='info')

            self.report(stage='end', results=report_data, is_new_db=is_new_db)

            exit_code = 1 if any(report_data.values()) and not is_new_db else 0
            sys.exit(exit_code)

        except SystemExit as e:
            sys.exit(e.code)
        except Exception as e:
            self.log(f"Непредвиденная ошибка: {e}", level='error')
            import traceback
            self.log(traceback.format_exc(), level='error')
            sys.exit(2)
        finally:
            if hasattr(self, 'updated_db_path') and self.updated_db_path:
                self.log(f"База данных обновлена ({self.updated_db_path})", level='info')
            if self.report_file_handler:
                self.log(f"Файл отчета сохранен ({self.report_file_handler.name}).", level='info')
                self.report_file_handler.close()


if __name__ == "__main__":
    app = IntegrityChecker()
    app.run()
