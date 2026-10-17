# Step 1
FROM outsrkem/alpine:3.19.1-go1.25.14-upx5.0.0
WORKDIR /opt/spki
ARG GO_VERSION="go1.25.14"
ARG SPKI_VERSION
ARG SPKI_REVISION

COPY . /opt/spki
# 如有必要可以下载时区数据库，并在目标镜像中安装
# RUN apk update && apk fetch tzdata
# RUN apk add tzdata-2024a-r0.apk

# -trimpath 移除源代码中的文件路径信息
# -ldflags -s：不生成符号表 -w：不生成DWARF调试信息
ARG LD_PATH="spki/src/config"
ARG LD_FLAGS="-X $LD_PATH.GoVersion=${GO_VERSION} -X $LD_PATH.Version=${SPKI_VERSION} -X $LD_PATH.GitCommit=${SPKI_REVISION}"
RUN go build -trimpath  -ldflags "-s -w $LD_FLAGS" -o output/spki src/main/main.go
# RUN upx -9 output/spki
RUN output/spki -version
RUN cp spki.yaml output
RUN cp docker-entrypoint.sh output/entrypoint.sh

# Step 2
FROM alpine:3.19.1
ARG SPKI_VERSION
ARG SPKI_REVISION

COPY --from=0 /opt/spki/output/ /usr/local/bin
RUN mkdir "/etc/spki" && mv /usr/local/bin/spki.yaml /etc/spki/spki.yaml

ENV SPKI_VERSION=$SPKI_VERSION SPKI_REVISION=$SPKI_REVISION
ENTRYPOINT ["entrypoint.sh"]
