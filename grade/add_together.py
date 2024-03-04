import pandas as pd

# 设置表名
sheet_name_now = input("请输入表名：")
# 读取四个表格
week1 = pd.read_excel("HGAME 2024 WEEK 1-比赛排名.xlsx", sheet_name=sheet_name_now)
week2 = pd.read_excel("HGAME 2024 WEEK 2-比赛排名.xlsx", sheet_name=sheet_name_now)
week3 = pd.read_excel("HGAME 2024 WEEK 3-比赛排名.xlsx", sheet_name=sheet_name_now)
week4 = pd.read_excel("HGAME 2024 WEEK 4-比赛排名.xlsx", sheet_name=sheet_name_now)

# 将四个表格合并为一个，使用 '名称' 列作为键
df = pd.concat([week1, week2, week3, week4])

# 按 '名称' 列对数据进行分组，然后计算 '分数' 列的总和
df = df.groupby("名称")["分数"].sum().reset_index()

# 按 '分数' 列进行降序排序
df = df.sort_values(by="分数", ascending=False)

# 将结果导出为 Excel 文件
df.to_excel(sheet_name_now + "总分排名.xlsx", index=False)
