"""
计算聚合流GASF矩阵三阶矩的XGBoost评分
"""
import torch
import math


class GASF(object):
    def __init__(self):
        self.max = 1
        self.min = -1

    def cal_gramian(self, traffic):
        Gramian = [[]]
        X_S = []
        Theta = []
        Xmax = max(traffic)
        Xmin = min(traffic)
        for x in traffic:
            # 将 x 缩放到(-1, 1)之间
            xi_s = ((x - Xmin) * (self.max - self.min) + self.min) / (Xmax - Xmin)
            X_S.append(xi_s)
        for xi_s in X_S:
            xi_s = round(xi_s, 5)  # 防止溢出
            theta = math.acos(xi_s)
            Theta.append(theta)
        for i in Theta:
            G_temp = []
            for j in Theta:
                G_temp.append(math.cos(i+j))
            Gramian.append(G_temp)
        return Gramian  # 返回Gramian矩阵

    def cal_three_moments(self, matrix):
        rows = len(matrix)     # 获取Gramian矩阵的行数
        cols = len(matrix[0])  # 获取Gramian矩阵的列数
        E, sigma, S = 0, 0, 0
        first_sum, second_sum, third_sum = 0, 0, 0
        # Calculate first moment
        for i in range(rows):
            for j in range(cols):
                first_sum += matrix[i][j]
        E = first_sum / rows * cols
        # Calculate second moment
        for i in range(rows):
            for j in range(cols):
                second_sum += (matrix[i][j] - E) ** 2
        sigma = math.sqrt(second_sum / rows * cols)
        # Calculate third moment
        for i in range(rows):
            for j in range(cols):
                third_sum += (matrix[i][j] - E) ** 3
        S = math.pow(third_sum / rows * cols, 1 / 3)
        return E, sigma, S  # 返回三阶矩

    # TODO 计算三阶矩的XGBoost评分


'''test'''
if __name__ == '__main__':
    GASF = GASF()
    with open("overlapped_agg_window.csv", "r") as file:
        content = file.read()



