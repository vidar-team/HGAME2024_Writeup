import pandas as pd

# week1=pd.read_excel("C:\\Users\\4nsw3r\\Downloads\\Week1.xlsx",sheet_name=1)

# week2=pd.read_excel("C:\\Users\\4nsw3r\\Downloads\\Week2.xlsx",sheet_name=1)

# week3=pd.read_excel("C:\\Users\\4nsw3r\\Downloads\\Week3.xlsx",sheet_name=1)
# week4=pd.read_excel("C:\\Users\\4nsw3r\\Downloads\\Week4.xlsx",sheet_name=1)
# data1=week1[['名称','分数']]
# print(data1)
# data1.rename(columns={"分数":"week1","名称":"ID"},inplace=True)
# data2=week2[['名称','分数']]
# data2.rename(columns={"分数":"week2","名称":"ID"},inplace=True)
# data3=week3[['名称','分数']]
# data3.rename(columns={"分数":"week3","名称":"ID"},inplace=True)
# data4=week4[['名称','分数']]
# data4.rename(columns={"分数":"week4","名称":"ID"},inplace=True)
# # print(data3)
# data_merge=pd.merge(data1,data2,how='outer',left_on='ID',right_on="ID")
# data_merge=pd.merge(data_merge,data3,how='outer',left_on='ID',right_on="ID")
# data_merge=pd.merge(data_merge,data4,how='outer',left_on='ID',right_on="ID")
# data_merge=data_merge.fillna(0)
# data_merge['sum']=data_merge['week1']+data_merge['week2']+data_merge['week3']+data_merge['week4']
# data_merge.sort_values('sum',ascending=False,inplace=True)
# # df.rename(columns={'old_name': 'new_name'})
# data_merge.index = range(1,len(data_merge) + 1) 
# print(data_merge)
# data_merge.to_excel("merge2.xlsx")

final=pd.read_excel("final.xlsx")
week14=pd.read_excel("校内总榜 带学号.xlsx")
data_merge=pd.merge(week14,final,how='outer',left_on='ID',right_on="ID")
data_merge=data_merge.fillna(0)
data_merge['sum']=data_merge['week1']+data_merge['week2']+data_merge['week3']+data_merge['week4']+data_merge['分数']
data_merge.sort_values('sum',ascending=False,inplace=True)
data_merge=data_merge.rename(columns={'分数': 'final'})
data_merge.to_csv("week+final.csv")