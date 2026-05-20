import os
import sys
import hashlib
import json
import argparse
import glob
import fnmatch
import time


class IntegrityChecker:
    DEFAULT_CONFIG = {
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
        'endc': '\033[0m',
    }

    PREFIXES = {
        'info': '[*]',
        'warn': '[WARN]',
        'error': '[ERROR]',
        'result': '',
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
        self.IS_ADMIN = os.getuid() == 0 if hasattr(os, 'getuid') else False
        self.skipped_files_count = 0

    def log(self, message, level='info'):
        current_verbosity = self.config['verbosity']
        allowed_levels = self.VERBOSITY_MAP[current_verbosity]
        
        if level not in allowed_levels:
            return

        prefix = self.PREFIXES.get(level, f"[{level.upper()}]")
        use_colors = self.config.get('use_colors', True)

        if use_colors and sys.stderr.isatty():
            color = self.COLORS.get(level, '')
            endc = self.COLORS['endc']
            formatted_prefix = f"{color}{prefix}{endc} " if prefix else ""
        else:
            formatted_prefix = f"{prefix} " if prefix else ""

        print(f"{formatted_prefix}{message}", file=sys.stderr)

    def _display_progress(self, iteration, total, prefix='', suffix='', length=20):
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
            suffix = "..." + suffix[-max_suffix_len+3:]

        output_str = f'\r\033[2K{colored_indicator}{header} {suffix}'
        
        sys.stdout.write(output_str)
        sys.stdout.flush()

    def _clear_progress_line(self):
        if self.config['verbosity'] == 'verbose':
            sys.stdout.write('\r\033[2K')
            sys.stdout.flush()

    def setup(self):
        if not self.IS_ADMIN:
            self.log("Скрипт запущен без прав администратора. Некоторые файлы могут быть недоступны для проверки.", level='warn')

        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

        parser = argparse.ArgumentParser(description='WIP')
        parser.add_argument('action', choices=['scan', 's'],
                            help='WIP')
        parser.add_argument('scan_type', nargs='?', choices=self.SCAN_TYPE_HASH + self.SCAN_TYPE_PATHS + ['full'], default='full',
                            help='WIP')
        parser.add_argument('-u', '--update', dest='update', action='store_true',
                            help='WIP')
        
        parser.add_argument('--config', type=str, default=os.path.join(base_dir, 'config.json'),
                            help='WIP')
        parser.add_argument('--db', type=str, default=os.path.join(base_dir, 'hash_database'),
                            help='WIP')
        parser.add_argument('--ignore-config', action='store_true',
                            help='WIP')
        parser.add_argument('--include', nargs='*',
                            help='WIP')
        parser.add_argument('--exclude', nargs='*',
                            help='WIP')
        parser.add_argument('--follow-symlinks', choices=['true', 'false'],
                            help='WIP')
        
        verbosity_group = parser.add_mutually_exclusive_group()
        verbosity_group.add_argument('-v', '--verbose', action='store_const', dest='verbosity', const='verbose',
                                     help='WIP')
        verbosity_group.add_argument('-q', '--quiet', action='store_const', dest='verbosity', const='quiet',
                                     help='WIP')
        verbosity_group.add_argument('-s', '--silent', action='store_const', dest='verbosity', const='silent',
                                     help='WIP')

        try:
            args = parser.parse_args()
            if args.scan_type in self.SCAN_TYPE_PATHS:
                args.scan_type = 'paths'
            elif args.scan_type in self.SCAN_TYPE_HASH:
                args.scan_type = 'hashes'
        except SystemExit:
            self.log("Неверные аргументы командной строки", level='error')
            sys.exit(2)

        config_file_path = args.config

        if not args.ignore_config:
            if os.path.exists(config_file_path):
                try:
                    with open(config_file_path, 'r', encoding='utf-8') as f:
                        file_config = json.load(f)
                    if not isinstance(file_config, dict):
                        raise ValueError("Конфигурационный файл должен содержать JSON объект (словарь)")
                    
                    if 'include' in file_config and not isinstance(file_config['include'], list):
                         raise ValueError("Ключ 'include' должен быть списком")
                    if 'exclude' in file_config and not isinstance(file_config['exclude'], list):
                         raise ValueError("Ключ 'exclude' должен быть списком")

                    self.config.update(file_config)
                except (json.JSONDecodeError, OSError, ValueError) as e:
                    self.log(f"Ошибка чтения конфигурационного файла '{config_file_path}': {e}", level='error')
                    sys.exit(2)
            else:
                try:
                    with open(config_file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.DEFAULT_CONFIG, f, indent=4, ensure_ascii=False)
                    self.log(f"Конфигурационный файл не найден. Создан файл по умолчанию: {config_file_path}", level='warn')
                except OSError as e:
                    self.log(f"Не удалось создать конфигурационный файл '{config_file_path}': {e}", level='error')
        else:
            self.log("Конфигурационный файл проигнорирован", level='info')

        if args.include is not None: self.config['include'] = args.include
        if args.exclude is not None: self.config['exclude'] = args.exclude
        if args.verbosity is not None: self.config['verbosity'] = args.verbosity
        if args.follow_symlinks is not None: self.config['follow_symlinks'] = (args.follow_symlinks == 'true')

        if not args.db.endswith('.json'):
            args.db = f"{args.db.replace('.db', '')}.json"

        return args

    def _load_database(self, db_path):
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

    def scan_paths(self, existing_data):
        file_set = set()
        mask_prefix = 'mask:'
        
        include_list = self.config.get('include', [])
        exclude_list = self.config.get('exclude', [])
        
        follow_symlinks = bool(self.config.get('follow_symlinks', False))

        include_dirs, include_masks, exclude_exact, exclude_masks = [], [], [], []
        for item in include_list:
            if not isinstance(item, str):
                continue
            if item.startswith(mask_prefix):
                include_masks.append(item[len(mask_prefix):])
            elif item:
                include_dirs.append(item)

        for item in exclude_list:
            if not isinstance(item, str):
                continue
            if item.startswith(mask_prefix):
                exclude_masks.append(item[len(mask_prefix):])
            elif item:
                exclude_exact.append(item)

        def is_excluded(path):
            if any(ex in path for ex in exclude_exact):
                return True
            if any(fnmatch.fnmatch(path, mask) for mask in exclude_masks):
                return True
            return False

        spinner_count = 0
        for mask in include_masks:
            try:
                matched = glob.glob(mask, recursive=True)
                if not matched:
                    self.log(f"По маске '{mask}' ничего не найдено (пропуск)", level='warn')
                for f in matched:
                    spinner_count += 1
                    self._display_progress(spinner_count, 0, prefix='Сканирование', suffix=f)
                    if not is_excluded(f) and os.path.isfile(f) and (follow_symlinks or not os.path.islink(f)):
                        file_set.add(f)
            except Exception as e:
                self.log(f"Ошибка при обработке маски '{mask}': {e}", level='error')

        for root in include_dirs:
            if not isinstance(root, str) or not os.path.exists(root):
                self.log(f"Директория '{root}' не найдена (пропуск)", level='warn')
                continue

            try:
                for base, dirs, files in os.walk(root, followlinks=follow_symlinks):
                    spinner_count += 1
                    self._display_progress(spinner_count, 0, prefix='Сканирование', suffix=base)

                    dirs[:] = [d for d in dirs if not is_excluded(os.path.join(base, d))]
                    for name in files:
                        full_path = os.path.join(base, name)
                        spinner_count += 1
                        self._display_progress(spinner_count, 0, prefix='Сканирование', suffix=full_path)
                        if not is_excluded(full_path) and os.path.isfile(full_path) and (follow_symlinks or not os.path.islink(full_path)):
                            file_set.add(full_path)
            except OSError as e:
                self.log(f"Ошибка при сканировании '{root}': {e}", level='error')

        self._clear_progress_line()
        
        current_files = list(file_set)
        master_set = set(existing_data.keys())
        current_set = set(current_files)
        
        report = {
            'Новые': list(current_set - master_set),
            'Удалены': list(master_set - current_set)
        }
        return report, current_files

    def scan_hashes(self, target_files, existing_data):
        current_hashes = {}
        report = {'Изменены': []}
        total = len(target_files)
        
        for i, path in enumerate(target_files):
            self._display_progress(i + 1, total, prefix='Получение хэшей', suffix=path)
            hash_value = None
            try:
                with open(path, "rb") as f:
                    file_hash = hashlib.sha256()
                    while chunk := f.read(8192):
                        file_hash.update(chunk)
                    hash_value = file_hash.hexdigest()
            except PermissionError as e:
                if not self.IS_ADMIN:
                    self.skipped_files_count += 1
                else:
                    self._clear_progress_line()
                    self.log(f"Не удалось прочитать файл '{path}': {e}", level='error')
                    continue
            except OSError as e:
                self._clear_progress_line()
                self.log(f"Не удалось прочитать файл '{path}': {e}", level='error')
                continue

            current_hashes[path] = hash_value
            if path in existing_data and existing_data[path] != current_hashes[path]:
                report['Изменены'].append(path)
                
        if total > 0:
            self._clear_progress_line()
            
        return report, current_hashes

    def update_database(self, db_path, current_data):
        success = False
        try:
            if not db_path.endswith('.json'):
                db_path = db_path.replace('.db', '') + '.json'
            with open(db_path, 'w', encoding='utf-8') as f:
                json.dump(current_data, f, indent=4, ensure_ascii=False)
            success = True
        except OSError as e:
            self.log(f"Ошибка записи в базу данных: {e}", level='error')

        if success:
            self.log("База данных успешно обновлена.", level='result')
            self.log(f"Файл базы данных: {db_path}", level='result')
            self.log(f"Всего файлов в базе: {len(current_data)}", level='result')
        else:
            self.log("Не удалось обновить базу данных.", level='error')

    def report(self):
        try:
            start_time = time.time()
            params = self.setup()

            existing_data, success, is_new_db = self._load_database(params.db)
            if not success:
                sys.exit(2)
                
            if is_new_db:
                params.update = True
                params.scan_type = 'full'

            report_data = {}
            new_db_data = existing_data.copy()
            files_to_hash = []
            total_checked = 0

            if params.scan_type in ['paths', 'full']:
                paths_report, current_files = self.scan_paths(existing_data)
                
                if is_new_db:
                    paths_report['Новые'] = []
                
                report_data.update(paths_report)
                total_checked = len(current_files)
                files_to_hash = current_files if params.scan_type == 'full' else paths_report.get('Новые', [])
            
            elif params.scan_type == 'hashes':
                files_to_hash = list(existing_data.keys())
                total_checked = len(files_to_hash)

            hash_report, current_hashes = self.scan_hashes(files_to_hash, existing_data)
            
            if is_new_db:
                hash_report['Изменены'] = []
                
            report_data.update(hash_report)

            if params.update:
                if params.scan_type == 'paths':
                    for p in report_data.get('Удалены', []):
                        new_db_data.pop(p, None)
                    new_db_data.update(current_hashes)
                elif params.scan_type == 'hashes':
                    for p in report_data.get('Изменены', []):
                        new_db_data[p] = current_hashes[p]
                elif params.scan_type == 'full':
                    new_db_data = current_hashes
            
            has_changes = False
            
            if not is_new_db:
                for status, items in report_data.items():
                    if items:
                        has_changes = True
                        self.log(f"{status.upper()}:", level='result')
                        for item in items:
                            self.log(f"  - {item}", level='result')
                
                if not has_changes:
                    self.log("Проверка завершена. Изменений не найдено.", level='result')
                    exit_code = 0
                else:
                    self.log("Проверка завершена. Обнаружены изменения.", level='result')
                    exit_code = 1
            else:
                self.log("Инициализация начальной базы данных завершена.", level='result')
                exit_code = 0
            
            if params.update:
                self.update_database(params.db, new_db_data)

            elapsed_time = time.time() - start_time
            stats_message = f"Статистика: проверено {total_checked} файлов за {elapsed_time:.2f} сек"
            if self.skipped_files_count > 0:
                stats_message += f" (пропущено {self.skipped_files_count} файлов из-за отсутствия доступа)"
            self.log(stats_message, level='info')
            
            sys.exit(exit_code)
            
        except SystemExit as e:
            sys.exit(e.code)
        except Exception as e:
            self.log(f"Непредвиденная ошибка: {e}", level='error')
            sys.exit(2)


if __name__ == "__main__":
    app = IntegrityChecker()
    app.report()