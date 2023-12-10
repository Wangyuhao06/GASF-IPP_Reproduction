"""
Overlap Sliding Window Implementation
"""
MAXLEN = 5


class SlidingWindow(object):
    def __init__(self, maxsize=MAXLEN):
        self.time_queue = []
        self.maxlen = maxsize

    def cal_win(self, loc):
        sum = 0
        if len(self.time_queue) == 0:
            return 0
        for tp in self.time_queue:
            sum += tp[loc]  # 要计算的数据的位置
        return sum / len(self.time_queue)

    def update_win(self, loc, *args):
        if len(self.time_queue) >= self.maxlen:
            self.time_queue.pop(0)
        self.time_queue.append(args)
        mn = self.cal_win(loc)
        return mn


'''test'''
if __name__ == '__main__':
    tw = SlidingWindow(5)
    for i in range(20):
        mn = tw.update_win(0, i ** 2)
        print(mn)
