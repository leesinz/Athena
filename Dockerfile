FROM python:3.8.10-slim-buster
ENV TZ="Asia/Shanghai"
# 修改更新源, 设置时区
RUN echo "deb https://mirrors.aliyun.com/debian/ buster main non-free contrib" > /etc/apt/sources.list \
    && echo "deb-src https://mirrors.aliyun.com/debian/ buster main non-free contrib" >> /etc/apt/sources.list \
    && echo "deb https://mirrors.aliyun.com/debian-security buster/updates main" >> /etc/apt/sources.list \
    && echo "deb-src https://mirrors.aliyun.com/debian-security buster/updates main" >> /etc/apt/sources.list \
    && echo "deb https://mirrors.aliyun.com/debian/ buster-updates main non-free contrib" >> /etc/apt/sources.list \
    && echo "deb-src https://mirrors.aliyun.com/debian/ buster-updates main non-free contrib" >> /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends tzdata gcc libmariadb-dev \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime  \
    && echo $TZ > /etc/timezone
# 设置工作目录, 安装依赖
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
# 拷贝代码
COPY . .
# 启动
ENTRYPOINT ["python", "main.py"]