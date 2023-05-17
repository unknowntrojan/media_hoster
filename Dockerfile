FROM docker.io/rustlang/rust:nightly-alpine as prepare

WORKDIR /app
COPY . .

RUN apk add --no-cache libc-dev musl-dev openssl-dev git sqlite-dev
RUN cargo install sqlx-cli
RUN sqlx migrate run

FROM docker.io/rustlang/rust:nightly-alpine as build

WORKDIR /app
COPY . .
COPY --from=prepare /app/db.sqlite .

RUN apk add --no-cache libc-dev musl-dev openssl-dev sqlite-dev

RUN cargo build --release

FROM docker.io/fedora

RUN dnf install -y https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm
RUN dnf install -y https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
RUN yum -y install libwebp-tools ffmpeg akmod-nvidia xorg-x11-drv-nvidia-cuda

COPY --from=build /app/target/release/media_hoster ./

EXPOSE 80

ENTRYPOINT ["./media_hoster"]