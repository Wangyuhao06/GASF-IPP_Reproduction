import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
import pandas as pd
import numpy as np

# 加载样本数据集
x = np.array([[1,2,3],[4,5,6]])  # 输入特征
y = np.array([0,1])   # 目标变量
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=123) # 数据集分割

# 训练模型
model = xgb.XGBClassifier(max_depth=5, learning_rate=0.1, n_estimators=160, silent=True, objective='binary:logistic')
model.fit(X_train, y_train)

feature_importance = model.feature_importances_
weights = feature_importance/sum(feature_importance)
score = np.dot(x,weights)

clf = KNeighborsClassifier(n_neighbors=5, weights='uniform', algorithm='auto', leaf_size=30, p=2, metric='minkowski', metric_params=None, n_jobs=None)
clf.fit(score, y)


