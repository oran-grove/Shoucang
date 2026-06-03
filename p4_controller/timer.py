import time
import threading


def start_timer_thread(interval_sec, callback_func):
    """
    后台守护线程，每隔 interval_sec 秒，调用一次控制器传进来的回调函数
    """

    def loop():
        while True:
            time.sleep(interval_sec)
            callback_func()  # 触发控制器的拉取动作

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    print(f"⏱️ [定时器] 已启动，心跳周期 {interval_sec} 秒。")