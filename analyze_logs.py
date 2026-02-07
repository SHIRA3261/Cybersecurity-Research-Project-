import json
import statistics
import glob
import os

def analyze_attack_logs(file_pattern):
    # חיפוש כל הקבצים שמתאימים לתבנית (למשל brute_force_*.jsonl)
    log_files = glob.glob(file_pattern)
    
    if not log_files:
        print(f"לא נמצאו קבצים התואמים לתבנית: {file_pattern}")
        return

    for file_path in sorted(log_files):
        latencies = []
        cpu_usages = []
        rss_memory = []
        total_attempts = 0
        success_count = 0
        prev_runtime = 0.0

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    event = entry.get("event_type", "")
                    
                    # נתמקד רק בשורות של ניסיונות (spray או brute)
                    if "attempt" not in event:
                        continue
                    
                    data = entry.get("data", {})
                    total_attempts += 1
                    if data.get("success"):
                        success_count += 1

                    # 1. חישוב Latency (הפרש בזמני הריצה בין ניסיונות)
                    current_runtime = entry.get("runtime_seconds", 0)
                    latency = (current_runtime - prev_runtime) * 1000  # המרה למילי-שניות
                    if latency >= 0:
                        latencies.append(latency)
                    prev_runtime = current_runtime

                    # 2. חילוץ CPU Usage
                    cpu = data.get("cpu_percent")
                    if cpu is not None:
                        cpu_usages.append(cpu)

                    # 3. חילוץ Memory RSS (המרה ל-MB)
                    rss = data.get("rss_bytes")
                    if rss is not None:
                        rss_memory.append(rss / (1024 * 1024))

                except (json.JSONDecodeError, KeyError):
                    continue

        if total_attempts > 0:
            print(f"\n" + "="*50)
            print(f"דוח עבור קובץ: {os.path.basename(file_path)}")
            print(f"סה\"כ ניסיונות: {total_attempts} | הצלחות: {success_count}")
            
            # פונקציית עזר לחישוב והדפסת סטטיסטיקה
            def report_metric(name, values, unit):
                if values:
                    avg = statistics.mean(values)
                    median = statistics.median(values)
                    # חישוב אחוזון 90
                    sorted_vals = sorted(values)
                    p90 = sorted_vals[int(len(sorted_vals) * 0.9) - 1]
                    print(f"{name:<15} | ממוצע: {avg:>8.2f} {unit} | חציון: {median:>8.2f} {unit} | אחוזון 90: {p90:>8.2f} {unit}")

            report_metric("Latency", latencies, "ms")
            report_metric("CPU Usage", cpu_usages, "%")
            report_metric("Memory (RSS)", rss_memory, "MB")
        else:
            print(f"הקובץ {os.path.basename(file_path)} ריק מנתוני ניסיונות.")

if __name__ == "__main__":
    print("מתחיל ניתוח לוגים...")
    # מנתח את כל קבצי ה-Brute Force וה-Password Spray שנוצרו
    analyze_attack_logs("*.jsonl")
